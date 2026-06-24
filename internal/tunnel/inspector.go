package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
)

//go:embed ui/dashboard ui/login
var staticFiles embed.FS

const maxCapturedRequests = 500
const maxAPIBodySize = 64 * 1024 // 64 KB limit on dashboard API request bodies

// loginRateLimit controls brute-force protection on the dashboard login.
const (
	loginRateLimit  = 5
	loginRateWindow = 60 * time.Second
	loginFailDelay  = 500 * time.Millisecond
)

// CapturedRequest holds metadata about a single proxied HTTP request.
type CapturedRequest struct {
	ID          int         `json:"id"`
	Timestamp   time.Time   `json:"ts"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Host        string      `json:"host"`
	Endpoint    string      `json:"endpoint"`
	StatusCode  int         `json:"status"`
	DurationMs  int64       `json:"duration_ms"`
	ClientIP    string      `json:"client_ip"`
	ReqHeaders  http.Header `json:"req_headers,omitempty"`
	RespHeaders http.Header `json:"resp_headers,omitempty"`
	ReqSize     int64       `json:"req_size"`
	RespSize    int64       `json:"resp_size"`
	ReqBody     []byte      `json:"req_body,omitempty"`
}

type TunnelEntry struct {
	Type             string `json:"type"`
	Endpoint         string `json:"endpoint"`
	Connections      int    `json:"connections"`
	HasAPIKey        bool   `json:"hasApiKey"`
	APIKeyEnabled    bool   `json:"apikey_enabled"`
	BasicAuthEnabled bool   `json:"basicauth_enabled"`
	AIModeEnabled    bool   `json:"aimode_enabled"`
	ProxyURL         string `json:"proxy_url"`
	ClientIP         string `json:"client_ip"`
}

// Inspector provides a secured web dashboard for live inspection of tunnel traffic.
type Inspector struct {
	mu       sync.RWMutex
	requests []CapturedRequest
	nextID   int

	subsMu sync.Mutex
	subs   []chan CapturedRequest

	ServerAddr  string
	TunAddr     string
	InspectAddr string
	Token       string
	StartTime   time.Time
	ActiveConns *atomic.Int64

	// Auth
	Username      string
	Password      string
	sessionsMu    sync.RWMutex           // FIX: RWMutex so concurrent reads don't block each other
	sessions      map[string]sessionData // token → session info (expiry + CSRF)
	loginLimiters sync.Map               // IP → *loginBucket

	// Reference to server for tunnels API and replay.
	srv  *Server
	done chan struct{} // closed by Stop() to terminate background goroutines
}

// sessionData stores per-session info including the CSRF token.
type sessionData struct {
	expiry    time.Time
	csrfToken string
}

// loginBucket tracks per-IP login attempt counts.
type loginBucket struct {
	mu       sync.Mutex
	attempts []time.Time
}

func (b *loginBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-loginRateWindow)
	valid := b.attempts[:0]
	for _, t := range b.attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.attempts = valid
	if len(b.attempts) >= loginRateLimit {
		return false
	}
	b.attempts = append(b.attempts, now)
	return true
}

// hasActiveAttempts returns true if this bucket has attempts within the rate window.
func (b *loginBucket) hasActiveAttempts() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := time.Now().Add(-loginRateWindow)
	for _, t := range b.attempts {
		if t.After(cutoff) {
			return true
		}
	}
	return false
}

// NewInspector creates a new request inspector.
func NewInspector(serverAddr, tunAddr, inspectAddr, token, username, password string, activeConns *atomic.Int64, srv *Server) *Inspector {
	ins := &Inspector{
		requests:    make([]CapturedRequest, 0, maxCapturedRequests),
		ServerAddr:  serverAddr,
		TunAddr:     tunAddr,
		InspectAddr: inspectAddr,
		Token:       token,
		StartTime:   time.Now(),
		ActiveConns: activeConns,
		Username:    username,
		Password:    password,
		sessions:    make(map[string]sessionData),
		srv:         srv,
		done:        make(chan struct{}),
	}
	go ins.cleanSessions()
	go ins.cleanLoginLimiters()
	return ins
}

// Stop terminates background goroutines started by NewInspector.
func (ins *Inspector) Stop() {
	select {
	case <-ins.done:
		// already stopped
	default:
		close(ins.done)
	}
}

// cleanSessions periodically purges expired session tokens.
func (ins *Inspector) cleanSessions() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			ins.sessionsMu.Lock()
			for tok, sd := range ins.sessions {
				if now.After(sd.expiry) {
					delete(ins.sessions, tok)
				}
			}
			ins.sessionsMu.Unlock()
		case <-ins.done:
			return
		}
	}
}

// cleanLoginLimiters periodically evicts loginBucket entries with no recent
// attempts, preventing unbounded growth of the loginLimiters sync.Map.
func (ins *Inspector) cleanLoginLimiters() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ins.loginLimiters.Range(func(k, v any) bool {
				if !v.(*loginBucket).hasActiveAttempts() {
					ins.loginLimiters.Delete(k)
				}
				return true
			})
		case <-ins.done:
			return
		}
	}
}

// isAuthenticated returns true if the request carries a valid session cookie.
// If no password is configured, authentication always fails — the dashboard
// will remain inaccessible until a password is set.
func (ins *Inspector) isAuthenticated(r *http.Request) bool {
	if ins.Password == "" {
		return false
	}
	cookie, err := r.Cookie("gotunnel_session")
	if err != nil {
		return false
	}
	// FIX: use RLock for read-only map access — avoids exclusive lock contention
	// on every authenticated request.
	ins.sessionsMu.RLock()
	sd, ok := ins.sessions[cookie.Value]
	ins.sessionsMu.RUnlock()
	return ok && time.Now().Before(sd.expiry)
}

// getCSRFToken returns the CSRF token for the current session, or "" if not found.
func (ins *Inspector) getCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("gotunnel_session")
	if err != nil {
		return ""
	}
	// FIX: use RLock for read-only map access.
	ins.sessionsMu.RLock()
	sd, ok := ins.sessions[cookie.Value]
	ins.sessionsMu.RUnlock()
	if !ok {
		return ""
	}
	return sd.csrfToken
}

// validateCSRF checks that the X-CSRF-Token header matches the session's CSRF token.
func (ins *Inspector) validateCSRF(w http.ResponseWriter, r *http.Request) bool {
	expected := ins.getCSRFToken(r)
	got := r.Header.Get("X-CSRF-Token")
	if expected == "" || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		http.Error(w, "CSRF token mismatch", http.StatusForbidden)
		return false
	}
	return true
}

// Record stores a completed request and fans it out to SSE subscribers.
func (ins *Inspector) Record(endpoint, clientIP, method, path, host string, statusCode int, dur time.Duration, reqHeaders, respHeaders http.Header, reqSize, respSize int64, reqBody []byte) {
	ins.mu.Lock()
	ins.nextID++
	cr := CapturedRequest{
		ID:          ins.nextID,
		Timestamp:   time.Now(),
		Method:      method,
		Path:        path,
		Host:        host,
		Endpoint:    endpoint,
		StatusCode:  statusCode,
		DurationMs:  dur.Milliseconds(),
		ClientIP:    clientIP,
		ReqHeaders:  cloneHeaders(reqHeaders),
		RespHeaders: cloneHeaders(respHeaders),
		ReqSize:     reqSize,
		RespSize:    respSize,
		ReqBody:     reqBody,
	}
	if len(ins.requests) >= maxCapturedRequests {
		ins.requests = ins.requests[1:]
	}
	ins.requests = append(ins.requests, cr)
	ins.mu.Unlock()

	ins.subsMu.Lock()
	for _, ch := range ins.subs {
		select {
		case ch <- cr:
		default:
		}
	}
	ins.subsMu.Unlock()
}

func cloneHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	// Strip sensitive auth headers from the inspector view.
	clone := h.Clone()
	clone.Del("Authorization")
	clone.Del("X-API-Key")
	return clone
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func (ins *Inspector) subscribe() (chan CapturedRequest, func()) {
	ch := make(chan CapturedRequest, 64)
	ins.subsMu.Lock()
	ins.subs = append(ins.subs, ch)
	ins.subsMu.Unlock()
	return ch, func() {
		ins.subsMu.Lock()
		for i, s := range ins.subs {
			if s == ch {
				ins.subs = append(ins.subs[:i], ins.subs[i+1:]...)
				break
			}
		}
		ins.subsMu.Unlock()
	}
}

// serveStaticFile reads a file from the embedded FS and writes it with the given
// content type. Cache-Control is set to allow short-term caching of static assets.
func serveStaticFile(w http.ResponseWriter, path, contentType string) {
	data, err := staticFiles.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Write(data)
}

// ServeHTTP routes all dashboard requests.
func (ins *Inspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Public routes — no auth required. Must be listed before the auth gate.
	switch r.URL.Path {
	case "/login":
		ins.handleLogin(w, r)
		return
	case "/logout":
		ins.handleLogout(w, r)
		return
	// Static assets, nested to mirror the ui/login and ui/dashboard folders.
	// Served without auth so the login page can load its own CSS/JS.
	case "/login/styles.css":
		serveStaticFile(w, "ui/login/styles.css", "text/css; charset=utf-8")
		return
	case "/login/script.js":
		serveStaticFile(w, "ui/login/script.js", "application/javascript; charset=utf-8")
		return
	case "/dashboard/styles.css":
		serveStaticFile(w, "ui/dashboard/styles.css", "text/css; charset=utf-8")
		return
	case "/dashboard/script.js":
		serveStaticFile(w, "ui/dashboard/script.js", "application/javascript; charset=utf-8")
		return
	}

	// Every other route requires a valid session.
	if !ins.isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Security headers on every authenticated response.
	// CSP: connect only to same origin — blocks exfiltration even if injected
	// JS manages to call /api/token with the victim's live session.
	// NOTE: script-src/style-src must keep 'unsafe-inline' — the dashboard
	// markup uses inline style="" attributes and onclick=/onchange= handlers
	// extensively (not just the old <style>/<script> blocks), and CSP's
	// unsafe-inline keyword governs those too. Dropping it silently breaks
	// all dashboard styling and interactivity in a real browser.
	// style-src/font-src also allowlist Google Fonts: the dashboard's <head>
	// Security headers.
	// NOTE: script-src no longer needs 'unsafe-inline' because all event
	// handlers have been moved to external JS files (addEventListener calls).
	// style-src keeps 'unsafe-inline' for inline style="" attributes used
	// for conditional visibility; the Google Fonts origins are needed for
	// the Geist typeface loaded via the preconnect link in HTML.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// X-XSS-Protection: belt-and-braces for older browsers that ignore CSP.
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()")
	// HSTS: only sent over TLS; tells browsers to always use HTTPS.
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	// Set CSRF cookie so JS can read it and include in POST headers.
	csrf := ins.getCSRFToken(r)
	if csrf != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "gotunnel_csrf",
			Value:    csrf,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
			// HttpOnly intentionally omitted: JS must read this cookie to implement
			// the Double Submit Cookie CSRF pattern (send it as X-CSRF-Token header).
		})
	}

	switch r.URL.Path {
	case "/":
		data, err := staticFiles.ReadFile("ui/dashboard/index.html")
		if err != nil {
			http.Error(w, "dashboard unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	case "/api/requests":
		ins.mu.RLock()
		data := make([]CapturedRequest, len(ins.requests))
		copy(data, ins.requests)
		ins.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	case "/api/status":
		ins.mu.RLock()
		total := ins.nextID
		ins.mu.RUnlock()
		var active int64
		if ins.ActiveConns != nil {
			active = ins.ActiveConns.Load()
		}
		var logs []ipc.LogEntry
		if ins.srv != nil {
			ins.srv.logsMu.Lock()
			logs = make([]ipc.LogEntry, len(ins.srv.logs))
			copy(logs, ins.srv.logs)
			ins.srv.logsMu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"server":       ins.ServerAddr,
			"https_addr":   ins.srv.httpsAddr,
			"tun_addr":     ins.TunAddr,
			"inspect_addr": ins.InspectAddr,
			"dash_user":    ins.Username,
			"dash_pass":    "[redacted]",
			"uptime_sec":   int(time.Since(ins.StartTime).Seconds()),
			"total":        total,
			"active_conns": active,
			"logs":         logs,
		})
	case "/api/token":
		ins.handleToken(w, r)
	case "/api/token/regen":
		ins.handleTokenRegen(w, r)
	case "/api/tunnels/apikey":
		ins.handleTunnelAPIKey(w, r)
	case "/api/tunnels/auth":
		ins.handleTunnelAuth(w, r)
	case "/api/tunnels/basicauth":
		ins.handleTunnelBasicAuth(w, r)
	case "/api/tunnels/basicauth-creds":
		ins.handleTunnelBasicAuthCreds(w, r)
	case "/api/tunnels/aimode":
		ins.handleTunnelAIMode(w, r)
	case "/api/tunnels":
		ins.handleTunnels(w, r)
	case "/api/requests/stream":
		ins.handleSSE(w, r)
	case "/api/status/stream":
		ins.handleStatusSSE(w, r)
	case "/api/replay":
		ins.handleReplay(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleLogin serves the login form (GET) and validates credentials (POST).
func (ins *Inspector) handleLogin(w http.ResponseWriter, r *http.Request) {
	if ins.Password == "" {
		http.Error(w, "Dashboard is not available: no password configured.", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet && ins.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		// Per-IP rate limiting on login attempts.
		peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if peerIP == "" {
			peerIP = r.RemoteAddr
		}
		bucketVal, _ := ins.loginLimiters.LoadOrStore(peerIP, &loginBucket{})
		bucket := bucketVal.(*loginBucket)
		if !bucket.allow() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		user := r.FormValue("username")
		pass := r.FormValue("password")
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(ins.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(ins.Password)) == 1
		if userOK && passOK {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			tok := hex.EncodeToString(b)

			// Generate CSRF token for this session.
			csrfBytes := make([]byte, 32)
			if _, err := rand.Read(csrfBytes); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			csrfToken := hex.EncodeToString(csrfBytes)

			ins.sessionsMu.Lock()
			ins.sessions[tok] = sessionData{
				expiry:    time.Now().Add(24 * time.Hour),
				csrfToken: csrfToken,
			}
			ins.sessionsMu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name:     "gotunnel_session",
				Value:    tok,
				Path:     "/",
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// Brief delay on failed login to slow brute-force.
		time.Sleep(loginFailDelay)
		http.Redirect(w, r, "/login?error=1", http.StatusFound)
		return
	}
	data, err := staticFiles.ReadFile("ui/login/index.html")
	if err != nil {
		http.Error(w, "login page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleLogout clears the session cookie and redirects to the login page.
// POST requests are validated with CSRF to prevent cross-site forced-logout
// attacks. The JS dashboard always uses POST; GET is kept only as a graceful
// fallback for direct browser navigation (e.g. bookmarked /logout link).
func (ins *Inspector) handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if !ins.validateCSRF(w, r) {
			return
		}
	case http.MethodGet:
		// Accepted without CSRF — an attacker can only force a logout (not
		// gain access), and the UX cost of blocking direct navigation would
		// be higher than the residual risk.
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Invalidate the server-side session.
	if cookie, err := r.Cookie("gotunnel_session"); err == nil {
		ins.sessionsMu.Lock()
		delete(ins.sessions, cookie.Value)
		ins.sessionsMu.Unlock()
	}
	// MaxAge=-1 ensures the cookie is deleted on both old and new browsers
	// (Expires alone is ignored by some older HTTP/1.0 proxies).
	http.SetCookie(w, &http.Cookie{
		Name:     "gotunnel_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "gotunnel_csrf",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	})

	// POST comes from a JS fetch — return 200 and let JS redirect.
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// buildTunnelList returns a snapshot of all active tunnels (without API keys).
// Callers must NOT hold srv.mu or srv.tunnelMetaMu.
func (ins *Inspector) buildTunnelList() []TunnelEntry {
	tunnels := []TunnelEntry{}
	if ins.srv == nil {
		return tunnels
	}
	ins.srv.tunnelMetaMu.RLock()
	defer ins.srv.tunnelMetaMu.RUnlock()

	for ep, meta := range ins.srv.tunnelMeta {
		conns := 0
		if meta.Session != nil {
			conns = int(meta.Session.NumStreams())
		}
		tunnels = append(tunnels, TunnelEntry{
			Type:             meta.Type,
			Endpoint:         ep,
			Connections:      conns,
			HasAPIKey:        meta.APIKey != "",
			APIKeyEnabled:    meta.APIKeyEnabled,
			BasicAuthEnabled: meta.BasicAuthEnabled,
			AIModeEnabled:    meta.AIMode,
			ProxyURL:         meta.ProxyURL,
			ClientIP:         meta.ClientIP,
		})
	}
	return tunnels
}

// handleTunnelAIMode enables or disables AI/Ollama optimisations for a tunnel.
// POST /api/tunnels/aimode  {"endpoint":"X","enabled":true}
func (ins *Inspector) handleTunnelAIMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	if ins.srv == nil {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var req struct {
		Endpoint string `json:"endpoint"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}
	if err := ins.srv.SetTunnelAIMode(req.Endpoint, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}

// handleTunnelAPIKey reveals the current API key for a tunnel.
// POST /api/tunnels/apikey  body: {"endpoint":"X"}
// Changed from GET so CSRF validation applies — prevents a cross-site page
// from silently reading the API key even when a session cookie is present.
func (ins *Inspector) handleTunnelAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	if ins.srv == nil {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}
	ins.srv.tunnelMetaMu.RLock()
	meta, ok := ins.srv.tunnelMeta[req.Endpoint]
	ins.srv.tunnelMetaMu.RUnlock()
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	json.NewEncoder(w).Encode(map[string]string{"apikey": meta.APIKey})
}

// handleTunnelBasicAuthCreds returns the plaintext credentials for a tunnel's
// Basic Auth config. Only accessible to authenticated dashboard users.
// POST /api/tunnels/basicauth-creds  body: {"endpoint":"X"}
// Uses POST + CSRF — credentials must never travel in a GET query string
// (logged by proxies, stored in browser history, leaked via Referer).
func (ins *Inspector) handleTunnelBasicAuthCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	endpoint := body.Endpoint
	if endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}
	if ins.srv == nil {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
		return
	}
	ins.srv.tunnelMetaMu.RLock()
	meta, ok := ins.srv.tunnelMeta[endpoint]
	ins.srv.tunnelMetaMu.RUnlock()
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	username, password := "", ""
	if meta.BasicAuth != "" {
		decoded, err := base64.StdEncoding.DecodeString(meta.BasicAuth)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				username, password = parts[0], parts[1]
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"username": username,
		"password": password,
	})
}

// handleTunnelAuth enables/disables API key auth and optionally regenerates the key.
// POST /api/tunnels/auth
//
//	{"endpoint":"X","enabled":true,"regenerate":false,"apikey":"optional-custom-key"}
func (ins *Inspector) handleTunnelAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	if ins.srv == nil {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var req struct {
		Endpoint   string `json:"endpoint"`
		Enabled    bool   `json:"enabled"`
		Regenerate bool   `json:"regenerate"`
		APIKey     string `json:"apikey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}

	newKey := req.APIKey
	if req.Regenerate || (req.Enabled && newKey == "") {
		// Generate a fresh key if asked, or if enabling with no key at all.
		ins.srv.tunnelMetaMu.RLock()
		meta, ok := ins.srv.tunnelMeta[req.Endpoint]
		ins.srv.tunnelMetaMu.RUnlock()
		if !ok {
			http.Error(w, "tunnel not found", http.StatusNotFound)
			return
		}
		if req.Regenerate || meta.APIKey == "" {
			b := make([]byte, 20)
			if _, err := rand.Read(b); err != nil {
				http.Error(w, "failed to generate key", http.StatusInternalServerError)
				return
			}
			newKey = hex.EncodeToString(b)
		}
	}

	if err := ins.srv.SetTunnelAuth(req.Endpoint, req.Enabled, newKey); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	ins.srv.tunnelMetaMu.RLock()
	meta := ins.srv.tunnelMeta[req.Endpoint]
	ins.srv.tunnelMetaMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"enabled": meta.APIKeyEnabled,
		"apikey":  meta.APIKey,
	})
}

// handleTunnelBasicAuth enables/disables per-tunnel Basic Auth from the dashboard.
// POST /api/tunnels/basicauth
//
//	{"endpoint":"X","enabled":true,"username":"user","password":"pass"}
func (ins *Inspector) handleTunnelBasicAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	if ins.srv == nil {
		http.Error(w, "server unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var req struct {
		Endpoint string `json:"endpoint"`
		Enabled  bool   `json:"enabled"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}

	var credsB64 string
	if req.Enabled {
		if req.Username == "" || req.Password == "" {
			http.Error(w, "username and password required when enabling basic auth", http.StatusBadRequest)
			return
		}
		// RFC 7617 §2: the username must not contain a colon because the
		// Basic credentials are encoded as "username:password".
		if strings.Contains(req.Username, ":") {
			http.Error(w, "username must not contain a colon character", http.StatusBadRequest)
			return
		}
		// Enforce reasonable length limits to prevent abuse.
		const maxCredLen = 128
		if len(req.Username) > maxCredLen {
			http.Error(w, "username exceeds maximum length", http.StatusBadRequest)
			return
		}
		if len(req.Password) > maxCredLen {
			http.Error(w, "password exceeds maximum length", http.StatusBadRequest)
			return
		}
		credsB64 = base64Encode(req.Username + ":" + req.Password)
	}

	if err := ins.srv.SetTunnelBasicAuth(req.Endpoint, req.Enabled, credsB64); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}

// handleToken returns the server token on an explicit authenticated POST request.
// Uses POST (not GET) so browser prefetch/cache/history cannot leak the token.
// CSRF is validated to ensure the request was deliberately initiated by the user.
func (ins *Inspector) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"token": ins.Token})
}

// handleTokenRegen generates a new token, updates config.yaml and the in-memory token.
func (ins *Inspector) handleTokenRegen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}

	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	newToken := hex.EncodeToString(b)

	if err := UpdateTokenInConfig(newToken); err != nil {
		http.Error(w, "failed to update config file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ins.mu.Lock()
	ins.Token = newToken
	ins.mu.Unlock()

	if ins.srv != nil {
		ins.srv.UpdateToken(newToken)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func (ins *Inspector) handleTunnels(w http.ResponseWriter, r *http.Request) {
	tunnels := ins.buildTunnelList()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tunnels)
}

func (ins *Inspector) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// FIX: tell nginx/caddy not to buffer SSE responses, or streaming breaks.
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ch, unsub := ins.subscribe()
	defer unsub()

	// FIX: heartbeat ticker keeps the connection alive through idle periods so
	// intermediary proxies don't silently drop it. SSE comment lines (:) are
	// ignored by EventSource and do not trigger onmessage.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case cr := <-ch:
			data, _ := json.Marshal(cr)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleStatusSSE streams combined status + tunnel list every second.
// The dashboard subscribes to this instead of polling /api/status and /api/tunnels.
func (ins *Inspector) handleStatusSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// FIX: tell nginx/caddy not to buffer SSE responses.
	w.Header().Set("X-Accel-Buffering", "no")
	flusher.Flush()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ins.mu.RLock()
			total := ins.nextID
			ins.mu.RUnlock()

			var active int64
			if ins.ActiveConns != nil {
				active = ins.ActiveConns.Load()
			}

			tunnels := ins.buildTunnelList()

			var logs []ipc.LogEntry
			if ins.srv != nil {
				ins.srv.logsMu.Lock()
				logs = make([]ipc.LogEntry, len(ins.srv.logs))
				copy(logs, ins.srv.logs)
				ins.srv.logsMu.Unlock()
			}

			payload := map[string]any{
				"server":       ins.ServerAddr,
				"https_addr":   ins.srv.httpsAddr,
				"tun_addr":     ins.TunAddr,
				"inspect_addr": ins.InspectAddr,
				"dash_user":    ins.Username,
				"dash_pass":    "[redacted]",
				"uptime_sec":   int(time.Since(ins.StartTime).Seconds()),
				"total":        total,
				"active_conns": active,
				"tunnels":      tunnels,
				"logs":         logs,
			}
			data, _ := json.Marshal(payload)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

func (ins *Inspector) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !ins.validateCSRF(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ins.mu.RLock()
	var targetReq *CapturedRequest
	for i := range ins.requests {
		if ins.requests[i].ID == req.ID {
			cr := ins.requests[i] // copy to avoid holding lock during replay
			targetReq = &cr
			break
		}
	}
	ins.mu.RUnlock()

	if targetReq == nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	// Always replay to localhost using only the port from ServerAddr,
	// regardless of the bind address (0.0.0.0, specific IP, etc.).
	_, port, err := net.SplitHostPort(ins.ServerAddr)
	if err != nil {
		// ServerAddr may be just ":port"
		port = strings.TrimPrefix(ins.ServerAddr, ":")
	}
	replayTarget := "localhost:" + port
	if port == "" {
		replayTarget = "localhost:8080"
	}

	newReq, err := http.NewRequest(targetReq.Method, "http://"+replayTarget+targetReq.Path, bytes.NewReader(targetReq.ReqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newReq.Host = targetReq.Host

	// Copy original request headers (auth headers were already stripped when recording).
	for k, vv := range targetReq.ReqHeaders {
		for _, v := range vv {
			newReq.Header.Add(k, v)
		}
	}

	// Re-apply gateway auth so the replayed request passes the server's auth check.
	if ins.srv != nil {
		ins.srv.tunnelMetaMu.RLock()
		endpointKey := ins.srv.getEndpointKeyLocked(targetReq.Host)
		tMeta, ok := ins.srv.tunnelMeta[endpointKey]
		ins.srv.tunnelMetaMu.RUnlock()

		if ok && tMeta.APIKeyEnabled && tMeta.APIKey != "" {
			newReq.Header.Set("X-API-Key", tMeta.APIKey)
		}
		if ok && tMeta.BasicAuthEnabled && tMeta.BasicAuth != "" {
			newReq.Header.Set("Authorization", "Basic "+tMeta.BasicAuth)
		}
	}

	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(newReq)
		if err != nil {
			log.Printf("replay error: %v", err)
			return
		}
		// FIX: defer Close so body is always released even if io.Copy fails.
		defer resp.Body.Close()
		// Drain body to return the connection to the pool.
		io.Copy(io.Discard, resp.Body)
	}()

	w.WriteHeader(http.StatusAccepted)
}
