// Package traefik_threath_plugin implements a Traefik middleware plugin for threat detection
package traefik_threath_plugin

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config holds the plugin configuration
type Config struct {
	Enabled        bool     `json:"enabled,omitempty"`
	MaxAttempts    int      `json:"maxAttempts,omitempty"`
	BanDuration    int      `json:"banDuration,omitempty"`
	ThreatPatterns []string `json:"threatPatterns,omitempty"`
}

// CreateConfig creates a new Config with default values
func CreateConfig() *Config {
	return &Config{
		Enabled:     true,
		MaxAttempts: 5,
		BanDuration: 3600, // 1 hour in seconds
		ThreatPatterns: []string{
			"/wp-admin",
			"/wp-login.php",
			"/wp-login",
			"/admin",
			"/administrator",
			"/phpmyadmin",
			"/pma",
			"/mysql",
			"/db",
			"/adminer",
			"/.env",
			"/config",
			"/backup",
			"/sftp-config.json",
			"/.git",
			"/console",
		},
	}
}

// ThreatDetector holds the plugin state
type ThreatDetector struct {
	next           http.Handler
	name           string
	config         *Config
	ipAttempts     map[string]*ipInfo
	mutex          sync.RWMutex
	bannedIPs      prometheus.Gauge
	threatAttempts prometheus.Counter
}

type ipInfo struct {
	attempts  int
	bannedAt  time.Time
	firstSeen time.Time
}

var (
	bannedIPsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "traefik_threat_plugin_banned_ips_total",
		Help: "Total number of currently banned IP addresses",
	})

	threatAttemptsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "traefik_threat_plugin_threat_attempts_total",
		Help: "Total number of threat attempts detected",
	})
)

func init() {
	prometheus.MustRegister(bannedIPsGauge)
	prometheus.MustRegister(threatAttemptsCounter)
}

// New creates a new ThreatDetector plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 5
	}
	if config.BanDuration <= 0 {
		config.BanDuration = 3600
	}
	if len(config.ThreatPatterns) == 0 {
		config.ThreatPatterns = CreateConfig().ThreatPatterns
	}

	detector := &ThreatDetector{
		next:           next,
		name:           name,
		config:         config,
		ipAttempts:     make(map[string]*ipInfo),
		bannedIPs:      bannedIPsGauge,
		threatAttempts: threatAttemptsCounter,
	}

	// Start cleanup goroutine
	go detector.cleanupExpiredBans()

	return detector, nil
}

// ServeHTTP implements the http.Handler interface
func (td *ThreatDetector) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !td.config.Enabled {
		td.next.ServeHTTP(rw, req)
		return
	}

	// Expose Prometheus metrics at /metrics endpoint
	if req.URL.Path == "/metrics" {
		promhttp.Handler().ServeHTTP(rw, req)
		return
	}

	ip := td.getClientIP(req)
	if ip == "" {
		td.next.ServeHTTP(rw, req)
		return
	}

	// Check if IP is banned
	if td.isIPBanned(ip) {
		http.Error(rw, "Forbidden: Your IP has been blocked due to suspicious activity", http.StatusForbidden)
		return
	}

	// Check if request matches threat patterns
	if td.isThreatPattern(req.URL.Path) {
		td.recordThreat(ip)
		td.threatAttempts.Inc()

		// Check if IP should be banned
		if td.shouldBanIP(ip) {
			td.banIP(ip)
			http.Error(rw, "Forbidden: Your IP has been blocked due to suspicious activity", http.StatusForbidden)
			return
		}

		// Still allow the request but log the attempt
		http.Error(rw, "Not Found", http.StatusNotFound)
		return
	}

	td.next.ServeHTTP(rw, req)
}

// getClientIP extracts the client IP from the request
func (td *ThreatDetector) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := req.Header.Get("X-Real-IP")
	if xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// isThreatPattern checks if the URL path matches any threat pattern
func (td *ThreatDetector) isThreatPattern(path string) bool {
	lowerPath := strings.ToLower(path)
	for _, pattern := range td.config.ThreatPatterns {
		lowerPattern := strings.ToLower(pattern)
		if strings.Contains(lowerPath, lowerPattern) {
			return true
		}
	}
	return false
}

// recordThreat records a threat attempt from an IP
func (td *ThreatDetector) recordThreat(ip string) {
	td.mutex.Lock()
	defer td.mutex.Unlock()

	info, exists := td.ipAttempts[ip]
	if !exists {
		info = &ipInfo{
			attempts:  0,
			firstSeen: time.Now(),
		}
		td.ipAttempts[ip] = info
	}
	info.attempts++
}

// shouldBanIP checks if an IP should be banned based on attempts
func (td *ThreatDetector) shouldBanIP(ip string) bool {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	info, exists := td.ipAttempts[ip]
	if !exists {
		return false
	}
	return info.attempts >= td.config.MaxAttempts
}

// isIPBanned checks if an IP is currently banned
func (td *ThreatDetector) isIPBanned(ip string) bool {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	info, exists := td.ipAttempts[ip]
	if !exists {
		return false
	}

	if info.bannedAt.IsZero() {
		return false
	}

	// Check if ban has expired
	banExpiry := info.bannedAt.Add(time.Duration(td.config.BanDuration) * time.Second)
	if time.Now().After(banExpiry) {
		return false
	}

	return true
}

// banIP bans an IP address
func (td *ThreatDetector) banIP(ip string) {
	td.mutex.Lock()
	defer td.mutex.Unlock()

	info, exists := td.ipAttempts[ip]
	if !exists {
		return
	}

	if info.bannedAt.IsZero() {
		info.bannedAt = time.Now()
		td.bannedIPs.Inc()
	}
}

// cleanupExpiredBans periodically cleans up expired bans
func (td *ThreatDetector) cleanupExpiredBans() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		td.mutex.Lock()
		now := time.Now()
		bannedCount := 0

		for ip, info := range td.ipAttempts {
			if !info.bannedAt.IsZero() {
				banExpiry := info.bannedAt.Add(time.Duration(td.config.BanDuration) * time.Second)
				if now.After(banExpiry) {
					// Ban expired, remove from tracking
					delete(td.ipAttempts, ip)
				} else {
					bannedCount++
				}
			} else {
				// Clean up old non-banned entries after 24 hours
				if now.Sub(info.firstSeen) > 24*time.Hour {
					delete(td.ipAttempts, ip)
				}
			}
		}

		td.bannedIPs.Set(float64(bannedCount))
		td.mutex.Unlock()
	}
}

// GetBannedIPsCount returns the current count of banned IPs (for testing)
func (td *ThreatDetector) GetBannedIPsCount() int {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	count := 0
	now := time.Now()
	for _, info := range td.ipAttempts {
		if !info.bannedAt.IsZero() {
			banExpiry := info.bannedAt.Add(time.Duration(td.config.BanDuration) * time.Second)
			if now.Before(banExpiry) {
				count++
			}
		}
	}
	return count
}
