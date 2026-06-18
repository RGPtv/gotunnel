package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
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
)

//go:embed ui/dashboard.html
var inspectorHTML string

//go:embed ui/login.html
var loginHTML string

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
	Token       string
	StartTime   time.Time
	ActiveConns *atomic.Int64

	// Auth
	Username      string
	Password      string
	sessionsMu    sync.Mutex
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

// NewInspector creates a new request inspector.
func NewInspector(serverAddr, tunAddr, token, username, password string, activeConns *atomic.Int64, srv *Server) *Inspector {
	ins := &Inspector{
		requests:    make([]CapturedRequest, 0, maxCapturedRequests),
		ServerAddr:  serverAddr,
		TunAddr:     tunAddr,
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
	ins.sessionsMu.Lock()
	sd, ok := ins.sessions[cookie.Value]
	ins.sessionsMu.Unlock()
	return ok && time.Now().Before(sd.expiry)
}

// getCSRFToken returns the CSRF token for the current session, or "" if not found.
func (ins *Inspector) getCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("gotunnel_session")
	if err != nil {
		return ""
	}
	ins.sessionsMu.Lock()
	sd, ok := ins.sessions[cookie.Value]
	ins.sessionsMu.Unlock()
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

// ServeHTTP routes all dashboard requests.
func (ins *Inspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Login / logout bypass auth check.
	switch r.URL.Path {
	case "/login":
		ins.handleLogin(w, r)
		return
	case "/logout":
		ins.handleLogout(w, r)
		return
	}

	// Every other route requires a valid session.
	if !ins.isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Security headers on every authenticated response.
	// CSP: script/style/connect only from same origin — blocks exfiltration even
	// if injected JS manages to call /api/token with the victim's live session.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

	// Set CSRF cookie so JS can read it and include in POST headers.
	csrf := ins.getCSRFToken(r)
	if csrf != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "gotunnel_csrf",
			Value:    csrf,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		})
	}

	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, inspectorHTML)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"server":       ins.ServerAddr,
			"tun_addr":     ins.TunAddr,
			"uptime_sec":   int(time.Since(ins.StartTime).Seconds()),
			"total":        total,
			"active_conns": active,
		})
	case "/api/token":
		ins.handleToken(w, r)
	case "/api/tunnels/apikey":
		ins.handleTunnelAPIKey(w, r)
	case "/api/tunnels/auth":
		ins.handleTunnelAuth(w, r)
	case "/api/tunnels/basicauth":
		ins.handleTunnelBasicAuth(w, r)
	case "/api/tunnels/basicauth/creds":
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginHTML)
}

// handleLogout clears the session and redirects to the login page.
func (ins *Inspector) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("gotunnel_session"); err == nil {
		ins.sessionsMu.Lock()
		delete(ins.sessions, cookie.Value)
		ins.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "gotunnel_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// Also clear the CSRF cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "gotunnel_csrf",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// buildTunnelList returns a snapshot of all active tunnels (without API keys).
// Callers must NOT hold srv.mu or srv.tunnelMetaMu.
func (ins *Inspector) buildTunnelList() []TunnelEntry {
	tunnels := []TunnelEntry{}
	if ins.srv == nil {
		return tunnels
	}
	ins.srv.mu.RLock()
	ins.srv.tunnelMetaMu.RLock()
	defer ins.srv.tunnelMetaMu.RUnlock()
	defer ins.srv.mu.RUnlock()

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
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}

// handleTunnelAuth handles GET (reveal) and POST (enable/disable/regenerate) for API keys.
//
//	GET  /api/tunnels/apikey?endpoint=X          → returns {"apikey":"..."}
//	POST /api/tunnels/auth  body: {"endpoint":"X","enabled":true,"regenerate":false,"apikey":"custom"}
func (ins *Inspector) handleTunnelAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	endpoint := r.URL.Query().Get("endpoint")
	if endpoint == "" {
		http.Error(w, "missing endpoint parameter", http.StatusBadRequest)
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"apikey": meta.APIKey})
}

// handleTunnelBasicAuthCreds returns the plaintext credentials for a tunnel's
// Basic Auth config. Only accessible to authenticated dashboard users.
// GET /api/tunnels/basicauth/creds?endpoint=X
func (ins *Inspector) handleTunnelBasicAuthCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	endpoint := r.URL.Query().Get("endpoint")
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
		credsB64 = base64Encode(req.Username + ":" + req.Password)
	}

	if err := ins.srv.SetTunnelBasicAuth(req.Endpoint, req.Enabled, credsB64); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}



// handleToken returns the server token on an explicit authenticated GET request.
// The token is never pushed automatically (not in SSE or status) so a passive
// XSS beacon cannot exfiltrate it without simulating a deliberate user action.
func (ins *Inspector) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"token": ins.Token})
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
	flusher.Flush()

	ch, unsub := ins.subscribe()
	defer unsub()

	for {
		select {
		case cr := <-ch:
			data, _ := json.Marshal(cr)
			fmt.Fprintf(w, "data: %s\n\n", data)
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

			payload := map[string]any{
				"server":       ins.ServerAddr,
				"tun_addr":     ins.TunAddr,
				"uptime_sec":   int(time.Since(ins.StartTime).Seconds()),
				"total":        total,
				"active_conns": active,
				"tunnels":      tunnels,
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
			cr := ins.requests[i] // copy to avoid holding lock
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
		// Acquire locks in consistent order (mu before tunnelMetaMu) to match
		// the janitor and avoid lock-order inversion.
		ins.srv.mu.RLock()
		ins.srv.tunnelMetaMu.RLock()
		endpointKey := ins.srv.getEndpointKeyLocked(targetReq.Host)
		tMeta, ok := ins.srv.tunnelMeta[endpointKey]
		ins.srv.tunnelMetaMu.RUnlock()
		ins.srv.mu.RUnlock()

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
		// Drain and close body to return the connection to the pool.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	w.WriteHeader(http.StatusAccepted)
}
