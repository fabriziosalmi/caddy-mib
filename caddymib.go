package caddymib

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
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
	Output                string         `json:"output,omitempty"`
	Whitelist             []string       `json:"whitelist,omitempty"`

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

	m.logger.Info("Starting Caddy MIB middleware...")

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

	m.logger.Info("Caddy MIB middleware provisioned",
		zap.Ints("error_codes", m.ErrorCodes),
		zap.Int("max_error_count", m.MaxErrorCount),
		zap.Duration("ban_duration", time.Duration(m.BanDuration)),
		zap.Any("whitelist", m.Whitelist),
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
		m.logger.Error("failed to parse client IP", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
		return next.ServeHTTP(w, r)
	}

	parsedIP := net.ParseIP(clientIP)
	for _, ipNet := range m.whitelistedNets {
		if ipNet.Contains(parsedIP) {
			m.logger.Debug("client IP is whitelisted", zap.String("ip", clientIP), zap.String("path", r.URL.Path))
			return next.ServeHTTP(w, r)
		}
	}

	m.mu.RLock()
	banTime, banned := m.bannedIPs[clientIP]
	m.mu.RUnlock()

	if banned {
		if time.Now().Before(banTime) {
			m.logger.Info("IP is currently banned", zap.String("ip", clientIP), zap.String("path", r.URL.Path), zap.Time("ban_expires_at", banTime))
			w.WriteHeader(http.StatusForbidden)
			return nil
		}
		m.logger.Info("unbanning IP because ban expired", zap.String("ip", clientIP), zap.String("path", r.URL.Path), zap.Time("was_banned_until", banTime))
		m.mu.Lock()
		delete(m.bannedIPs, clientIP)
		delete(m.errorCounts, clientIP)
		m.mu.Unlock()
	}

	if len(m.ErrorCodes) == 0 {
		m.logger.Debug("skipping middleware because no error codes are specified", zap.String("ip", clientIP), zap.String("path", r.URL.Path))
		return next.ServeHTTP(w, r)
	}

	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		m.logger.Error("error in next handler", zap.Error(err), zap.String("ip", clientIP), zap.String("path", r.URL.Path))
		statusCode := extractStatusCodeFromError(err)
		if statusCode == 0 {
			return err
		}
		m.logger.Debug("extracted status code from error", zap.Int("status_code", statusCode), zap.String("ip", clientIP), zap.String("path", r.URL.Path))
		m.trackErrorStatus(clientIP, statusCode, r.URL.Path, w)
		return err
	}

	statusCode := rec.Status()
	m.logger.Debug("response status code", zap.Int("status_code", statusCode), zap.String("ip", clientIP), zap.String("path", r.URL.Path))
	m.trackErrorStatus(clientIP, statusCode, r.URL.Path, w)
	return nil
}

func (m *Middleware) trackErrorStatus(clientIP string, code int, path string, w http.ResponseWriter) {
	for _, errCode := range m.ErrorCodes {
		if code == errCode {
			m.mu.Lock()
			m.logger.Debug("tracking error",
				zap.String("ip", clientIP),
				zap.Int("error_code", code),
				zap.Int("current_error_count", m.errorCounts[clientIP]),
				zap.Int("max_error_count", m.MaxErrorCount),
			)
			m.errorCounts[clientIP]++
			m.logger.Debug("error count incremented",
				zap.String("ip", clientIP),
				zap.Int("error_code", code),
				zap.Int("new_error_count", m.errorCounts[clientIP]),
				zap.Int("max_error_count", m.MaxErrorCount),
			)
			if m.errorCounts[clientIP] >= m.MaxErrorCount {
				offenses := m.errorCounts[clientIP] - m.MaxErrorCount + 1
				banDuration := time.Duration(m.BanDuration) * time.Duration(math.Pow(m.BanDurationMultiplier, float64(offenses)))
				m.bannedIPs[clientIP] = time.Now().Add(banDuration)
				m.logger.Info("IP banned",
					zap.String("ip", clientIP),
					zap.Int("error_code", code),
					zap.Int("error_count", m.errorCounts[clientIP]),
					zap.Int("max_error_count", m.MaxErrorCount),
					zap.Duration("ban_duration", banDuration),
					zap.Time("ban_expires_at", m.bannedIPs[clientIP]),
					zap.String("path", path),
				)
				w.WriteHeader(http.StatusForbidden)
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
	// Simple 404 detection. Can be extended as needed.
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
				delete(m.bannedIPs, ip)
				delete(m.errorCounts, ip)
				m.logger.Info("cleaned up expired ban", zap.String("ip", ip))
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

			case "output":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Output = d.Val()

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
