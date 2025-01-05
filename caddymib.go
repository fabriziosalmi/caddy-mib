package caddymib

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

// Middleware tracks and bans IPs based on repetitive errors.
type Middleware struct {
	ErrorCodes    []int                `json:"error_codes,omitempty"`
	MaxErrorCount int                  `json:"max_error_count,omitempty"`
	BanDuration   caddy.Duration       `json:"ban_duration,omitempty"`
	ErrorCounts   map[string]int       `json:"-"`
	BannedIPs     map[string]time.Time `json:"-"`
	mu            sync.Mutex
	logger        *zap.Logger
	w             io.Writer
	Output        string `json:"output,omitempty"`
}

// CaddyModule registers the module.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_mib",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision configures the middleware during initialization.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.ErrorCounts = make(map[string]int)
	m.BannedIPs = make(map[string]time.Time)

	switch m.Output {
	case "stdout":
		m.w = os.Stdout
	case "stderr":
		m.w = os.Stderr
	default:
		return fmt.Errorf("output stream must be stdout or stderr")
	}
	m.logger.Info("Middleware provisioned", zap.Any("config", m))
	return nil
}

// Validate ensures the configuration is valid.
func (m *Middleware) Validate() error {
	if len(m.ErrorCodes) == 0 {
		return fmt.Errorf("at least one error code must be specified")
	}
	if m.MaxErrorCount <= 0 {
		return fmt.Errorf("max_error_count must be greater than 0")
	}
	if m.BanDuration <= 0 {
		return fmt.Errorf("ban_duration must be greater than 0")
	}
	if m.w == nil {
		return fmt.Errorf("no output stream specified")
	}
	return nil
}

// ServeHTTP handles incoming HTTP requests, tracks errors, and enforces IP bans.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Error("Failed to parse client IP", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("internal server error"))
	}
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		clientIP = strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
	}

	m.logger.Debug("Request received",
		zap.String("ip", clientIP),
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if IP is banned
	if banTime, banned := m.BannedIPs[clientIP]; banned {
		if time.Since(banTime) < time.Duration(m.BanDuration) {
			m.logger.Info("IP is currently banned",
				zap.String("ip", clientIP),
				zap.Time("ban_expires", banTime.Add(time.Duration(m.BanDuration))),
			)
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("IP banned"))
		}
		delete(m.BannedIPs, clientIP)
		m.logger.Info("Ban expired", zap.String("ip", clientIP))
	}

	// Wrap response to track status codes
	buf := new(bytes.Buffer)
	recorder := caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		return true
	})

	// Call the next handler
	err = next.ServeHTTP(recorder, r)
	statusCode := recorder.Status()

	// If no status is set, assume 404
	if statusCode == 0 {
		m.logger.Warn("Status code was zero; defaulting to 404 Not Found")
		statusCode = http.StatusNotFound
	}

	m.logger.Debug("Handler returned status", zap.Int("status_code", statusCode))

	// Handle 404 specifically
	if statusCode == http.StatusNotFound {
		m.logger.Warn("Resource not found",
			zap.String("path", r.URL.Path),
			zap.String("ip", clientIP),
		)
		m.ErrorCounts[clientIP]++

		// Ban after threshold exceeded
		if m.ErrorCounts[clientIP] >= m.MaxErrorCount {
			m.BannedIPs[clientIP] = time.Now()
			m.logger.Info("IP banned due to excessive 404 errors",
				zap.String("ip", clientIP),
				zap.Int("error_count", m.ErrorCounts[clientIP]),
			)
			delete(m.ErrorCounts, clientIP)
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("IP banned"))
		}

		// Write 404 response without triggering 500
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
		return nil
	}

	// Handle other errors
	if err != nil {
		m.logger.Error("Handler encountered an error", zap.String("ip", clientIP), zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// Write headers and response
	for k, v := range recorder.Header() {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())

	m.logger.Debug("Response status", zap.Int("status_code", statusCode))
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration for this module.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() && d.Val() != "caddy_mib" {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "output":
				if !d.Args(&m.Output) {
					return d.ArgErr()
				}
			case "error_codes":
				m.ErrorCodes = []int{}
				args := d.RemainingArgs()
				for _, arg := range args {
					code, err := parseInt(arg)
					if err != nil {
						return d.Errf("invalid error code: %v", err)
					}
					m.ErrorCodes = append(m.ErrorCodes, code)
				}
			case "max_error_count":
				if !d.NextArg() {
					return d.ArgErr()
				}
				count, err := parseInt(d.Val())
				if err != nil {
					return d.Errf("invalid max_error_count: %v", err)
				}
				m.MaxErrorCount = count + 1
			case "ban_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				duration, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ban_duration: %v", err)
				}
				m.BanDuration = caddy.Duration(duration)
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func parseInt(s string) (int, error) {
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m *Middleware = new(Middleware)
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}
