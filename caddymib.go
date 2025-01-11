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
	LogRequestHeaders     []string       `json:"log_request_headers,omitempty"` // New field to specify headers to log

	logger          *zap.Logger
	errorCounts     map[string]int
	bannedIPs       map[string]time.Time
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

	m.logger.Info("caddy mib middleware provisioned",
		zap.Ints("error_codes", m.ErrorCodes),
		zap.Int("max_error_count", m.MaxErrorCount),
		zap.Duration("ban_duration", time.Duration(m.BanDuration)),
		zap.Strings("whitelist", m.Whitelist),
		zap.String("custom_response_header", m.CustomResponseHeader),
		zap.Strings("log_request_headers", m.LogRequestHeaders), // Log configured request headers
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

	parsedIP := net.ParseIP(clientIP)
	for _, ipNet := range m.whitelistedNets {
		if ipNet.Contains(parsedIP) {
			m.logger.Debug("client IP is whitelisted",
				zap.String("client_ip", clientIP),
				zap.String("request_path", r.URL.Path),
				zap.String("method", r.Method),
				zap.String("user_agent", r.Header.Get("User-Agent")),
			)
			return next.ServeHTTP(w, r)
		}
	}

	m.mu.RLock()
	banTime, banned := m.bannedIPs[clientIP]
	m.mu.RUnlock()

	if banned {
		if time.Now().Before(banTime) {
			m.logger.Info("IP is currently banned",
				zap.String("client_ip", clientIP),
				zap.String("request_path", r.URL.Path),
				zap.Time("ban_expires", banTime),
				zap.String("method", r.Method),
				zap.String("user_agent", r.Header.Get("User-Agent")),
			)
			w.WriteHeader(http.StatusForbidden)
			return nil
		}
		m.logger.Info("unbanning IP; ban expired",
			zap.String("client_ip", clientIP),
			zap.String("request_path", r.URL.Path),
			zap.Time("previous_ban_expiration", banTime),
			zap.String("method", r.Method),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)
		m.mu.Lock()
		delete(m.bannedIPs, clientIP)
		delete(m.errorCounts, clientIP)
		m.mu.Unlock()
	}

	if len(m.ErrorCodes) == 0 {
		m.logger.Debug("no error codes specified; skipping middleware",
			zap.String("client_ip", clientIP),
			zap.String("request_path", r.URL.Path),
			zap.String("method", r.Method),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)
		return next.ServeHTTP(w, r)
	}

	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		m.logger.Error("error in next handler",
			zap.Error(err),
			zap.String("client_ip", clientIP),
			zap.String("request_path", r.URL.Path),
			zap.String("method", r.Method),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)
		statusCode := extractStatusCodeFromError(err)
		if statusCode == 0 {
			return err
		}
		m.logger.Debug("extracted status code from error",
			zap.Int("status_code", statusCode),
			zap.String("client_ip", clientIP),
			zap.String("request_path", r.URL.Path),
			zap.String("method", r.Method),
			zap.String("user_agent", r.Header.Get("User-Agent")),
		)
		m.trackErrorStatus(clientIP, statusCode, r.URL.Path, r)
		return err
	}

	statusCode := rec.Status()
	m.logger.Debug("response status code",
		zap.Int("status_code", statusCode),
		zap.String("client_ip", clientIP),
		zap.String("request_path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("user_agent", r.Header.Get("User-Agent")),
	)
	m.trackErrorStatus(clientIP, statusCode, r.URL.Path, r)

	// Add the custom header if configured
	if m.CustomResponseHeader != "" {
		w.Header().Set("X-Custom-MIB-Info", m.CustomResponseHeader)
	}

	return nil
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
				// No need to write header here, it's done in ServeHTTP
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

			case "log_request_headers": // New Caddyfile option
				var headers []string
				for d.NextArg() {
					headers = append(headers, d.Val())
				}
				m.LogRequestHeaders = headers

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
