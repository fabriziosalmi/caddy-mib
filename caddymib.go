package caddymib

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("caddy_mib", parseCaddyfile)
}

// Middleware implements the Caddy MIB middleware.
type Middleware struct {
	ErrorCodes            []int          `json:"error_codes,omitempty"`
	MaxErrorCount         int            `json:"max_error_count,omitempty"`
	BanDuration           caddy.Duration `json:"ban_duration,omitempty"`
	BanDurationMultiplier float64        `json:"ban_duration_multiplier,omitempty"`
	Whitelist             []string       `json:"whitelist,omitempty"`
	CustomResponseHeader  string         `json:"custom_response_header,omitempty"`
	LogRequestHeaders     []string       `json:"log_request_headers,omitempty"`
	LogLevel              string         `json:"log_level,omitempty"`         // New: Configurable log level
	CIDRBans              []string       `json:"cidr_bans,omitempty"`         // New: Support for CIDR range bans
	BanResponseBody       string         `json:"ban_response_body,omitempty"` // New: Custom ban response body

	logger          *zap.Logger
	errorCounts     map[string]int
	bannedIPs       map[string]time.Time
	bannedCIDRs     []*net.IPNet // New: Track banned CIDR ranges
	mu              sync.RWMutex
	whitelistedNets []*net.IPNet
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_mib",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the middleware.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.errorCounts = make(map[string]int)
	m.bannedIPs = make(map[string]time.Time)
	m.logger = ctx.Logger(m)

	// Set log level
	if m.LogLevel != "" {
		level, err := zapcore.ParseLevel(m.LogLevel)
		if err != nil {
			return fmt.Errorf("invalid log level: %s", m.LogLevel)
		}
		m.logger = m.logger.WithOptions(zap.IncreaseLevel(level))
	}

	m.logger.Info("starting caddy mib middleware")

	if m.MaxErrorCount == 0 {
		m.MaxErrorCount = 5
	}
	if m.BanDuration == 0 {
		m.BanDuration = caddy.Duration(10 * time.Minute)
	}
	if m.BanDurationMultiplier == 0 {
		m.BanDurationMultiplier = 1
	}

	// Parse whitelist
	for _, cidr := range m.Whitelist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid IP or CIDR in whitelist: %s", cidr)
			}
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			ipNet = &net.IPNet{IP: ip, Mask: mask}
		}
		m.whitelistedNets = append(m.whitelistedNets, ipNet)
	}

	// Parse CIDR bans
	for _, cidr := range m.CIDRBans {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR in CIDR bans: %s", cidr)
		}
		m.bannedCIDRs = append(m.bannedCIDRs, ipNet)
	}

	m.logger.Info("caddy mib middleware provisioned",
		zap.Ints("error_codes", m.ErrorCodes),
		zap.Int("max_error_count", m.MaxErrorCount),
		zap.Duration("ban_duration", time.Duration(m.BanDuration)),
		zap.Strings("whitelist", m.Whitelist),
		zap.String("custom_response_header", m.CustomResponseHeader),
		zap.Strings("log_request_headers", m.LogRequestHeaders),
		zap.String("log_level", m.LogLevel),
		zap.Strings("cidr_bans", m.CIDRBans),
	)

	go m.cleanupExpiredBans()
	return nil
}

// Validate ensures the configuration is valid.
func (m *Middleware) Validate() error {
	if m.MaxErrorCount <= 0 {
		return fmt.Errorf("max_error_count must be greater than 0")
	}
	if m.BanDuration <= 0 {
		return fmt.Errorf("ban_duration must be greater than 0")
	}
	return nil
}

// ServeHTTP handles the HTTP request.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Error("failed to parse client IP",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("request_path", r.URL.Path),
		)
		return next.ServeHTTP(w, r)
	}

	// Normalize IP (treat IPv4 and IPv6 loopback as the same)
	clientIP = normalizeIP(clientIP)
	parsedIP := net.ParseIP(clientIP)

	// Check if IP is in a banned CIDR range
	for _, ipNet := range m.bannedCIDRs {
		if ipNet.Contains(parsedIP) {
			m.logger.Info("IP is in a banned CIDR range",
				zap.String("client_ip", clientIP),
				zap.String("cidr", ipNet.String()),
			)
			w.WriteHeader(http.StatusForbidden)
			if m.BanResponseBody != "" {
				w.Write([]byte(m.BanResponseBody))
			}
			return nil
		}
	}

	// Check if IP is whitelisted
	for _, ipNet := range m.whitelistedNets {
		if ipNet.Contains(parsedIP) {
			m.logger.Debug("client IP is whitelisted",
				zap.String("client_ip", clientIP),
			)
			return next.ServeHTTP(w, r)
		}
	}

	// Check if IP is banned
	m.mu.RLock()
	banTime, banned := m.bannedIPs[clientIP]
	m.mu.RUnlock()

	if banned {
		if time.Now().Before(banTime) {
			m.mu.RLock()
			_, alreadyLogged := m.errorCounts[clientIP]
			m.mu.RUnlock()
			if !alreadyLogged {
				m.logger.Info("IP is currently banned",
					zap.String("client_ip", clientIP),
					zap.Time("ban_expires", banTime),
				)
				m.mu.Lock()
				m.errorCounts[clientIP] = -1 // Mark as logged
				m.mu.Unlock()
			}
			w.WriteHeader(http.StatusForbidden)
			if m.BanResponseBody != "" {
				w.Write([]byte(m.BanResponseBody))
			}
			return nil
		}
		m.logger.Info("unbanning IP; ban expired",
			zap.String("client_ip", clientIP),
		)
		m.mu.Lock()
		delete(m.bannedIPs, clientIP)
		delete(m.errorCounts, clientIP)
		m.mu.Unlock()
	}

	// Skip middleware if no error codes are specified
	if len(m.ErrorCodes) == 0 {
		m.logger.Debug("no error codes specified; skipping middleware",
			zap.String("client_ip", clientIP),
		)
		return next.ServeHTTP(w, r)
	}

	// Record the response from the next handler
	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		m.logger.Error("error in next handler",
			zap.Error(err),
			zap.String("client_ip", clientIP),
		)
		statusCode := extractStatusCodeFromError(err)
		if statusCode == 0 {
			return err
		}
		m.logger.Debug("extracted status code from error",
			zap.Int("status_code", statusCode),
			zap.String("client_ip", clientIP),
		)
		m.trackErrorStatus(clientIP, statusCode, r.URL.Path, r)
		return err
	}

	// Track the response status code
	statusCode := rec.Status()
	m.logger.Debug("response status code",
		zap.Int("status_code", statusCode),
		zap.String("client_ip", clientIP),
	)
	m.trackErrorStatus(clientIP, statusCode, r.URL.Path, r)

	// Add the custom header if configured
	if m.CustomResponseHeader != "" {
		w.Header().Set("X-Custom-MIB-Info", m.CustomResponseHeader)
	}

	return nil
}

// normalizeIP normalizes IPv4 and IPv6 loopback addresses.
func normalizeIP(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip
	}
	if parsedIP.IsLoopback() {
		if parsedIP.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return ip
}

func (m *Middleware) trackErrorStatus(clientIP string, code int, path string, r *http.Request) {
	commonFields := []zap.Field{
		zap.String("client_ip", clientIP),
		zap.Int("error_code", code),
		zap.String("request_path", path),
		zap.String("method", r.Method),
		zap.String("user_agent", r.Header.Get("User-Agent")),
	}

	for _, errCode := range m.ErrorCodes {
		if code == errCode {
			m.mu.Lock()
			countBefore := m.errorCounts[clientIP]
			m.logger.Debug("tracking error", append(commonFields,
				zap.Int("current_error_count", countBefore),
				zap.Int("max_error_count", m.MaxErrorCount),
			)...)
			m.errorCounts[clientIP] = countBefore + 1
			countNow := m.errorCounts[clientIP]
			m.logger.Debug("error count incremented", append(commonFields,
				zap.Int("new_error_count", countNow),
				zap.Int("max_error_count", m.MaxErrorCount),
			)...)
			if countNow >= m.MaxErrorCount {
				offenses := countNow - m.MaxErrorCount + 1
				banDuration := time.Duration(m.BanDuration) * time.Duration(math.Pow(m.BanDurationMultiplier, float64(offenses)))
				expiration := time.Now().Add(banDuration)
				m.bannedIPs[clientIP] = expiration
				logFields := append(commonFields,
					zap.Int("error_count", countNow),
					zap.Int("max_error_count", m.MaxErrorCount),
					zap.Duration("ban_duration", banDuration),
					zap.Time("ban_expires", expiration),
				)

				// Add configured request headers to the log
				for _, headerName := range m.LogRequestHeaders {
					if value := r.Header.Get(headerName); value != "" {
						logFields = append(logFields, zap.String(strings.ToLower(headerName), value))
					}
				}

				m.logger.Info("IP banned", logFields...)
			}
			m.mu.Unlock()
			break
		}
	}
}

// extractStatusCodeFromError extracts the HTTP status code from the error message.
func extractStatusCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	errMsg := err.Error()
	if len(errMsg) >= 6 && errMsg[len(errMsg)-3:] == "404" {
		return 404
	}
	return 0
}

// cleanupExpiredBans periodically cleans up expired bans.
func (m *Middleware) cleanupExpiredBans() {
	for {
		time.Sleep(time.Minute)
		m.mu.Lock()
		now := time.Now()
		for ip, banTime := range m.bannedIPs {
			if now.After(banTime) {
				m.logger.Info("cleaned up expired ban",
					zap.String("client_ip", ip),
				)
				delete(m.bannedIPs, ip)
				delete(m.errorCounts, ip)
			}
		}
		m.mu.Unlock()
	}
}

// UnmarshalCaddyfile parses the Caddyfile configuration.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "error_codes":
				var codes []int
				for d.NextArg() {
					code, err := strconv.Atoi(d.Val())
					if err != nil {
						return d.Errf("invalid error code: %s", d.Val())
					}
					codes = append(codes, code)
				}
				if len(codes) == 0 {
					return d.Err("error_codes needs at least one argument")
				}
				m.ErrorCodes = codes

			case "max_error_count":
				if !d.NextArg() {
					return d.ArgErr()
				}
				count, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid max_error_count: %s", d.Val())
				}
				m.MaxErrorCount = count

			case "ban_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ban_duration: %v", err)
				}
				m.BanDuration = caddy.Duration(dur)

			case "ban_duration_multiplier":
				if !d.NextArg() {
					return d.ArgErr()
				}
				multiplier, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("invalid ban_duration_multiplier: %s", d.Val())
				}
				m.BanDurationMultiplier = multiplier

			case "whitelist":
				var whitelist []string
				for d.NextArg() {
					whitelist = append(whitelist, d.Val())
				}
				m.Whitelist = whitelist

			case "custom_response_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.CustomResponseHeader = d.Val()

			case "log_request_headers":
				var headers []string
				for d.NextArg() {
					headers = append(headers, d.Val())
				}
				m.LogRequestHeaders = headers

			case "log_level":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LogLevel = d.Val()

			case "cidr_bans":
				var cidrBans []string
				for d.NextArg() {
					cidrBans = append(cidrBans, d.Val())
				}
				m.CIDRBans = cidrBans

			case "ban_response_body":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BanResponseBody = d.Val()

			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := Middleware{}
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
