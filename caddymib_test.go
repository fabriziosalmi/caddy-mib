package caddymib

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestMiddleware_Provision(t *testing.T) {
	m := Middleware{}
	ctx := caddy.Context{}

	err := m.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if m.MaxErrorCount != 5 {
		t.Errorf("Expected MaxErrorCount to be 5, got %d", m.MaxErrorCount)
	}

	if m.BanDuration != caddy.Duration(10*time.Minute) {
		t.Errorf("Expected BanDuration to be 10m, got %v", m.BanDuration)
	}

	if m.BanDurationMultiplier != 1 {
		t.Errorf("Expected BanDurationMultiplier to be 1, got %v", m.BanDurationMultiplier)
	}

	if m.BanStatusCode != http.StatusForbidden {
		t.Errorf("Expected BanStatusCode to be 403, got %d", m.BanStatusCode)
	}
}

func TestMiddleware_ServeHTTP_Whitelist(t *testing.T) {
	m := Middleware{
		Whitelist: []string{"127.0.0.1"},
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", rec.Code)
	}
}

func TestMiddleware_ServeHTTP_Ban(t *testing.T) {
	m := Middleware{
		ErrorCodes:    []int{500},
		MaxErrorCount: 1,
		BanDuration:   caddy.Duration(1 * time.Minute),
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	})

	// First request should trigger a ban
	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code 500, got %d", rec.Code)
	}

	// Second request should be banned
	rec = httptest.NewRecorder()
	err = m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status code 403, got %d", rec.Code)
	}
}

func TestMiddleware_ServeHTTP_CIDRBans(t *testing.T) {
	m := Middleware{
		CIDRBans: []string{"192.168.1.0/24"},
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status code 403, got %d", rec.Code)
	}
}

func TestMiddleware_ServeHTTP_CustomResponseHeader(t *testing.T) {
	m := Middleware{
		CustomResponseHeader: "TestHeaderValue",
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Header().Get("X-Custom-MIB-Info") != "TestHeaderValue" {
		t.Errorf("Expected custom header 'X-Custom-MIB-Info' to be 'TestHeaderValue', got '%s'", rec.Header().Get("X-Custom-MIB-Info"))
	}
}

func TestMiddleware_CleanupExpiredBans(t *testing.T) {
	m := Middleware{}
	ctx := caddy.Context{}
	m.Provision(ctx)

	m.bannedIPs.Store("192.168.1.1", time.Now().Add(-1*time.Minute))

	go m.cleanupExpiredBans()
	time.Sleep(2 * time.Second) // Wait for cleanup to run

	if _, banned := m.bannedIPs.Load("192.168.1.1"); banned {
		t.Error("Expected ban to be cleaned up, but it still exists")
	}
}

func TestMiddleware_UnmarshalCaddyfile(t *testing.T) {
	m := Middleware{}
	d := caddyfile.NewTestDispenser(`
	caddy_mib {
		error_codes 500 404
		max_error_count 3
		ban_duration 5m
		ban_duration_multiplier 2
		whitelist 127.0.0.1
		custom_response_header "TestHeader"
		log_request_headers User-Agent
		log_level debug
		cidr_bans 192.168.1.0/24
		ban_response_body "Banned"
		ban_status_code 429
		per_path /test {
			error_codes 400
			max_error_count 2
			ban_duration 10m
			ban_duration_multiplier 3
		}
	}
	`)

	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if len(m.ErrorCodes) != 2 || m.ErrorCodes[0] != 500 || m.ErrorCodes[1] != 404 {
		t.Errorf("Expected error_codes to be [500, 404], got %v", m.ErrorCodes)
	}

	if m.MaxErrorCount != 3 {
		t.Errorf("Expected max_error_count to be 3, got %d", m.MaxErrorCount)
	}

	if m.BanDuration != caddy.Duration(5*time.Minute) {
		t.Errorf("Expected ban_duration to be 5m, got %v", m.BanDuration)
	}

	if m.BanDurationMultiplier != 2 {
		t.Errorf("Expected ban_duration_multiplier to be 2, got %v", m.BanDurationMultiplier)
	}

	if len(m.Whitelist) != 1 || m.Whitelist[0] != "127.0.0.1" {
		t.Errorf("Expected whitelist to be [127.0.0.1], got %v", m.Whitelist)
	}

	if m.CustomResponseHeader != "TestHeader" {
		t.Errorf("Expected custom_response_header to be 'TestHeader', got '%s'", m.CustomResponseHeader)
	}

	if len(m.LogRequestHeaders) != 1 || m.LogRequestHeaders[0] != "User-Agent" {
		t.Errorf("Expected log_request_headers to be [User-Agent], got %v", m.LogRequestHeaders)
	}

	if m.LogLevel != "debug" {
		t.Errorf("Expected log_level to be 'debug', got '%s'", m.LogLevel)
	}

	if len(m.CIDRBans) != 1 || m.CIDRBans[0] != "192.168.1.0/24" {
		t.Errorf("Expected cidr_bans to be [192.168.1.0/24], got %v", m.CIDRBans)
	}

	if m.BanResponseBody != "Banned" {
		t.Errorf("Expected ban_response_body to be 'Banned', got '%s'", m.BanResponseBody)
	}

	if m.BanStatusCode != 429 {
		t.Errorf("Expected ban_status_code to be 429, got %d", m.BanStatusCode)
	}

	if len(m.PerPathConfig) != 1 {
		t.Errorf("Expected per_path config to have 1 entry, got %d", len(m.PerPathConfig))
	}

	pathConfig, ok := m.PerPathConfig["/test"]
	if !ok {
		t.Fatal("Expected per_path config for /test, but not found")
	}

	if len(pathConfig.ErrorCodes) != 1 || pathConfig.ErrorCodes[0] != 400 {
		t.Errorf("Expected per_path error_codes to be [400], got %v", pathConfig.ErrorCodes)
	}

	if pathConfig.MaxErrorCount != 2 {
		t.Errorf("Expected per_path max_error_count to be 2, got %d", pathConfig.MaxErrorCount)
	}

	if pathConfig.BanDuration != caddy.Duration(10*time.Minute) {
		t.Errorf("Expected per_path ban_duration to be 10m, got %v", pathConfig.BanDuration)
	}

	if pathConfig.BanDurationMultiplier != 3 {
		t.Errorf("Expected per_path ban_duration_multiplier to be 3, got %v", pathConfig.BanDurationMultiplier)
	}
}

func TestMiddleware_ServeHTTP_EmptyCustomHeader(t *testing.T) {
	m := Middleware{
		CustomResponseHeader: "",
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	if rec.Header().Get("X-Custom-MIB-Info") != "" {
		t.Errorf("Expected no custom header, got '%s'", rec.Header().Get("X-Custom-MIB-Info"))
	}
}

//

func TestMiddleware_ServeHTTP_MultipleCustomHeaders(t *testing.T) {
	m := Middleware{
		CustomResponseHeader: "TestHeaderValue1,TestHeaderValue2",
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	headers := rec.Header().Values("X-Custom-MIB-Info")
	if len(headers) != 2 {
		t.Errorf("Expected 2 custom headers, got %d", len(headers))
	}
	if headers[0] != "TestHeaderValue1" || headers[1] != "TestHeaderValue2" {
		t.Errorf("Expected custom headers 'TestHeaderValue1' and 'TestHeaderValue2', got %v", headers)
	}
}

func TestMiddleware_ServeHTTP_LogRequestHeaders(t *testing.T) {
	m := Middleware{
		LogRequestHeaders: []string{"User-Agent", "X-Forwarded-For"},
	}
	ctx := caddy.Context{}
	m.Provision(ctx)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "TestAgent")
	req.Header.Set("X-Forwarded-For", "192.168.1.2")

	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	err := m.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

}
