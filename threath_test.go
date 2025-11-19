package traefik_threath_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()
	if cfg == nil {
		t.Fatal("CreateConfig returned nil")
	}
	if !cfg.Enabled {
		t.Error("Expected Enabled to be true by default")
	}
	if cfg.MaxAttempts != 5 {
		t.Errorf("Expected MaxAttempts to be 5, got %d", cfg.MaxAttempts)
	}
	if cfg.BanDuration != 3600 {
		t.Errorf("Expected BanDuration to be 3600, got %d", cfg.BanDuration)
	}
	if len(cfg.ThreatPatterns) == 0 {
		t.Error("Expected default threat patterns to be set")
	}
}

func TestNew(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if handler == nil {
		t.Fatal("New() returned nil handler")
	}
}

func TestThreatDetection(t *testing.T) {
	cfg := CreateConfig()
	cfg.MaxAttempts = 3
	cfg.BanDuration = 10

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectNext     bool
		ip             string
	}{
		{
			name:           "Normal request",
			path:           "/api/users",
			expectedStatus: http.StatusOK,
			expectNext:     true,
			ip:             "192.168.1.100",
		},
		{
			name:           "Threat wp-admin",
			path:           "/wp-admin/index.php",
			expectedStatus: http.StatusNotFound,
			expectNext:     false,
			ip:             "192.168.1.101",
		},
		{
			name:           "Threat wp-login",
			path:           "/wp-login.php",
			expectedStatus: http.StatusNotFound,
			expectNext:     false,
			ip:             "192.168.1.102",
		},
		{
			name:           "Threat phpmyadmin",
			path:           "/phpmyadmin/",
			expectedStatus: http.StatusNotFound,
			expectNext:     false,
			ip:             "192.168.1.103",
		},
		{
			name:           "Threat .env",
			path:           "/.env",
			expectedStatus: http.StatusNotFound,
			expectNext:     false,
			ip:             "192.168.1.104",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled = false
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = tt.ip + ":12345"
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
			if nextCalled != tt.expectNext {
				t.Errorf("Expected nextCalled to be %v, got %v", tt.expectNext, nextCalled)
			}
		})
	}
}

func TestIPBanning(t *testing.T) {
	cfg := CreateConfig()
	cfg.MaxAttempts = 3
	cfg.BanDuration = 5

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	td := handler.(*ThreatDetector)

	// Make 3 threat requests from the same IP
	testIP := "10.0.0.1"
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
		req.RemoteAddr = testIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Check if IP is banned
	if !td.isIPBanned(testIP) {
		t.Error("Expected IP to be banned after 3 attempts")
	}

	// Next request should be forbidden
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.RemoteAddr = testIP + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for banned IP, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestIPExtraction(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	td := handler.(*ThreatDetector)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expectedIP string
	}{
		{
			name:       "From RemoteAddr",
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "From X-Forwarded-For",
			remoteAddr: "127.0.0.1:12345",
			xff:        "10.0.0.1, 172.16.0.1",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "From X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xri:        "10.0.0.2",
			expectedIP: "10.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := td.getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestBanExpiry(t *testing.T) {
	cfg := CreateConfig()
	cfg.MaxAttempts = 2
	cfg.BanDuration = 2 // 2 seconds

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	td := handler.(*ThreatDetector)

	// Make 2 threat requests to ban the IP
	testIP := "10.0.0.2"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
		req.RemoteAddr = testIP + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Verify IP is banned
	if !td.isIPBanned(testIP) {
		t.Error("Expected IP to be banned")
	}

	// Wait for ban to expire
	time.Sleep(3 * time.Second)

	// Verify IP is no longer banned
	if td.isIPBanned(testIP) {
		t.Error("Expected IP ban to have expired")
	}
}

func TestDisabledPlugin(t *testing.T) {
	cfg := CreateConfig()
	cfg.Enabled = false

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Try a threat pattern - should pass through when disabled
	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	req.RemoteAddr = "10.0.0.3:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("Expected next handler to be called when plugin is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d for /metrics, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !contains(body, "traefik_threat_plugin") {
		t.Error("Expected metrics output to contain plugin metrics")
	}
}

func TestGetBannedIPsCount(t *testing.T) {
	cfg := CreateConfig()
	cfg.MaxAttempts = 2
	cfg.BanDuration = 10

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	td := handler.(*ThreatDetector)

	// Initially should be 0
	if count := td.GetBannedIPsCount(); count != 0 {
		t.Errorf("Expected 0 banned IPs, got %d", count)
	}

	// Ban 2 IPs
	ips := []string{"10.0.0.10", "10.0.0.11"}
	for _, ip := range ips {
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
			req.RemoteAddr = ip + ":12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	}

	// Should have 2 banned IPs
	if count := td.GetBannedIPsCount(); count != 2 {
		t.Errorf("Expected 2 banned IPs, got %d", count)
	}
}

func TestCaseInsensitivePatternMatching(t *testing.T) {
	cfg := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		path          string
		shouldDetect  bool
		ip            string
	}{
		{"/wp-admin", true, "10.0.0.200"},
		{"/WP-ADMIN", true, "10.0.0.201"},
		{"/Wp-Admin", true, "10.0.0.202"},
		{"/WP-admin/index.php", true, "10.0.0.203"},
		{"/phpmyadmin", true, "10.0.0.204"},
		{"/phpMyAdmin", true, "10.0.0.205"},
		{"/PHPMYADMIN", true, "10.0.0.206"},
		{"/normal-path", false, "10.0.0.207"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = tt.ip + ":12345"
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			isDetected := rec.Code == http.StatusNotFound
			if isDetected != tt.shouldDetect {
				t.Errorf("Path %s: expected shouldDetect=%v, got isDetected=%v (status=%d)",
					tt.path, tt.shouldDetect, isDetected, rec.Code)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
