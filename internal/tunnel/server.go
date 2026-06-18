package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
	"github.com/hashicorp/yamux"
)

// ── Per-IP rate limiter for tunnel authentication ─────────────────────────────

const (
	authRateLimit    = 5               // max auth attempts per window
	authRateWindow   = 30 * time.Second // sliding window duration
	authFailDelay    = 500 * time.Millisecond // delay after failed auth to slow scanners
	authLimiterExpiry = 5 * time.Minute // expire limiter entries after inactivity
)

// authBucket tracks per-IP authentication attempt counts.
type authBucket struct {
	mu       sync.Mutex
	attempts []time.Time
	lastSeen time.Time
}

// allow returns true if the IP is within the rate limit.
func (b *authBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.lastSeen = now
	cutoff := now.Add(-authRateWindow)
	// Prune old attempts.
	valid := b.attempts[:0]
	for _, t := range b.attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.attempts = valid
	if len(b.attempts) >= authRateLimit {
		return false
	}
	b.attempts = append(b.attempts, now)
	return true
}

// expired reports whether this bucket has been idle long enough to evict.
func (b *authBucket) expired() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Since(b.lastSeen) > authLimiterExpiry
}

// TunnelMeta stores per-tunnel metadata surfaced in the dashboard.
type TunnelMeta struct {
	APIKey           string
	APIKeyEnabled    bool   // dashboard toggle — false means no API key check even if APIKey is set
	BasicAuth        string // base64(user:pass), dashboard-managed per-tunnel basic auth
	BasicAuthEnabled bool   // dashboard toggle
	AIMode           bool   // optimise for AI/Ollama: no body cap, small flush buffer, CORS, long timeouts
	Type             string
	Endpoint         string
	ProxyURL         string
	ConnectedAt      time.Time
	ClientIP         string
	Session          *yamux.Session
}

// SetTunnelAIMode enables or disables AI/Ollama optimisations for a tunnel.
func (s *Server) SetTunnelAIMode(endpoint string, enabled bool) error {
	s.tunnelMetaMu.Lock()
	defer s.tunnelMetaMu.Unlock()
	meta, ok := s.tunnelMeta[endpoint]
	if !ok {
		return fmt.Errorf("tunnel %q not found", endpoint)
	}
	meta.AIMode = enabled
	s.tunnelMeta[endpoint] = meta
	return nil
}

// SetTunnelAuth updates (or removes) the API key for a tunnel from the dashboard.
// endpoint must match the key used in tunnelMeta ("(default)", subdomain, or TCP addr).
func (s *Server) SetTunnelAuth(endpoint string, enabled bool, apiKey string) error {
	s.tunnelMetaMu.Lock()
	defer s.tunnelMetaMu.Unlock()
	meta, ok := s.tunnelMeta[endpoint]
	if !ok {
		return fmt.Errorf("tunnel %q not found", endpoint)
	}
	meta.APIKeyEnabled = enabled
	if apiKey != "" {
		meta.APIKey = apiKey
	}
	if !enabled {
		// Keep the key value so it can be re-enabled, but stop enforcing it.
	}
	s.tunnelMeta[endpoint] = meta
	return nil
}

// SetTunnelBasicAuth updates the per-tunnel basic-auth config from the dashboard.
func (s *Server) SetTunnelBasicAuth(endpoint string, enabled bool, creds string) error {
	s.tunnelMetaMu.Lock()
	defer s.tunnelMetaMu.Unlock()
	meta, ok := s.tunnelMeta[endpoint]
	if !ok {
		return fmt.Errorf("tunnel %q not found", endpoint)
	}
	meta.BasicAuthEnabled = enabled
	if creds != "" {
		meta.BasicAuth = creds
	}
	s.tunnelMeta[endpoint] = meta
	return nil
}

// Server accepts tunnel client connections and proxies incoming HTTP requests
// through them to the target service on the other end.

const (
	LevelInfo = iota
	LevelWarn
	LevelError
	LevelSuccess
)

type Server struct {
	token           string
	domain          string
	httpAddr        string
	httpsAddr       string
	
	tcpListeners    map[string]net.Listener
	mu              sync.RWMutex
	count           atomic.Int64 // active tunnel connections
	inspector       *Inspector
	tunnelMeta      map[string]TunnelMeta
	tunnelMetaMu    sync.RWMutex
	logs            []ipc.LogEntry
	logsMu          sync.Mutex
	startTime       time.Time
	authLimiters    sync.Map       // IP → *authBucket for rate-limiting tunnel auth
	allowedTCPPorts []string       // if non-empty, only these remote addrs are allowed for TCP tunnels

	// poolEmptySince tracks when each named pool (http subdomain or TCP addr)
	// was first observed empty by the janitor.  A pool is only removed once it
	// has been continuously empty for poolEmptyGrace — transient emptiness
	// (workers mid-reconnect or all busy serving requests) does not trigger deletion.
	// Protected by s.mu (always held by the janitor when it reads/writes this map).
	
}

// hopByHopHeaders are headers that must not be forwarded through a proxy.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailers", "Transfer-Encoding", "Upgrade",
}

// hopByHopSet is a case-folded set of hop-by-hop header names for O(1) lookup.
var hopByHopSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(hopByHopHeaders))
	for _, h := range hopByHopHeaders {
		m[strings.ToLower(h)] = struct{}{}
	}
	return m
}()

// srvLog sends a message to the TUI log if available, otherwise falls back to
// the standard logger. This lets all server log lines flow through the TUI
// without hard-coupling every call site to it.
func (s *Server) srvLog(level int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	if s == nil {
		return
	}
	s.logsMu.Lock()
	s.logs = append(s.logs, ipc.LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
	})
	if len(s.logs) > 200 {
		s.logs = s.logs[len(s.logs)-200:]
	}
	s.logsMu.Unlock()
}

func RunServer(cfg *ServerConfig) {
	httpAddr := cfg.HTTPAddr
	if httpAddr == "" { httpAddr = ":8080" }
	tunAddr := cfg.TunAddr
	if tunAddr == "" { tunAddr = ":2222" }
	token := cfg.Token
	inspectUser := cfg.InspectUser
	if inspectUser == "" { inspectUser = "admin" }
	inspectPass := cfg.InspectPass
	inspect := cfg.Inspect
	if inspect == "" { inspect = ":4040" }
	
	if token == "auto" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate token: %v", err)
		}
		token = hex.EncodeToString(b)
	}

	if inspect != "" && inspectPass == "" {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate inspect password: %v", err)
		}
		inspectPass = hex.EncodeToString(b)

		// Persist credentials to .gotunnel-admin so the operator can retrieve
		// the auto-generated password without needing the TUI or dashboard.
		adminFile := ".gotunnel-admin"
		inspectURL := inspect
		if strings.HasPrefix(inspectURL, ":") {
			inspectURL = "http://localhost" + inspectURL
		} else {
			inspectURL = "http://" + inspectURL
		}
		contents := fmt.Sprintf(
			"# GoTunnel dashboard credentials (auto-generated)\n"+
				"# Delete this file and restart to rotate the password.\n"+
				"url:      %s\n"+
				"username: %s\n"+
				"password: %s\n",
			inspectURL, inspectUser, inspectPass,
		)
		if err := os.WriteFile(adminFile, []byte(contents), 0600); err != nil {
			log.Printf("warning: could not write %s: %v", adminFile, err)
		} else {
			log.Printf("dashboard credentials saved to %s", adminFile)
		}
	}
	
	srv := &Server{
		token:           token,
		domain:          cfg.Domain,
		httpAddr:        httpAddr,
		httpsAddr:       cfg.HTTPSAddr,
		
		tcpListeners:    make(map[string]net.Listener),
		tunnelMeta:      make(map[string]TunnelMeta),
		
		startTime:       time.Now(),
		allowedTCPPorts: cfg.AllowedTCPPorts,
	}


	if _, err := ipc.StartIPCServer(41400, func() interface{} {
		// Snapshot pool/meta state under the two read locks, then release
		// before acquiring logsMu to preserve consistent lock ordering and
		// avoid starvation of writers on the RWMutexes.
		srv.mu.RLock()
		srv.tunnelMetaMu.RLock()
		var tunnels []ipc.TunnelInfo
		for _, tm := range srv.tunnelMeta {
			conns := 0
			streams := 0
			if tm.Session != nil {
				conns = 1
				streams = int(tm.Session.NumStreams())
			}
			tunnels = append(tunnels, ipc.TunnelInfo{
				Endpoint:    tm.Endpoint,
				Type:        tm.Type,
				Connections: conns,
				Streams:     streams,
				ClientIP:    tm.ClientIP,
				ProxyURL:    tm.ProxyURL,
			})
		}
		srv.tunnelMetaMu.RUnlock()
		srv.mu.RUnlock()

		// Acquire logsMu only after releasing the other two locks.
		srv.logsMu.Lock()
		logs := make([]ipc.LogEntry, len(srv.logs))
		copy(logs, srv.logs)
		srv.logsMu.Unlock()

		return ipc.ServerState{
			Token:       "[redacted]",
			HTTPAddr:    httpAddr,
			HTTPSAddr:   cfg.HTTPSAddr,
			TunAddr:     tunAddr,
			InspectAddr: inspect,
			DashUser:    inspectUser,
			DashPass:    "[redacted]",
			ActiveConns: srv.count.Load(),
			TotalReqs:   0,
			Uptime:      int64(time.Since(srv.startTime).Seconds()),
			Tunnels:     tunnels,
			Logs:        logs,
		}
	}); err != nil {
		srv.srvLog(LevelError, "IPC server failed to start: %v", err)
	}

	var tunLn net.Listener
	var err error

	if cfg.NoTLS {
		tunLn, err = net.Listen("tcp", tunAddr)
		if err != nil {
			srv.srvLog(LevelError, "tunnel listen %s: %v", tunAddr, err)
			os.Exit(1)
		}
		srv.srvLog(LevelInfo, "tunnel listener %s (plain TCP)", tunAddr)
	} else {
		tlsCfg, err := makeTLSConfig(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			srv.srvLog(LevelError, "TLS setup: %v", err)
			os.Exit(1)
		}
		tunLn, err = tls.Listen("tcp", tunAddr, tlsCfg)
		if err != nil {
			srv.srvLog(LevelError, "tunnel listen %s: %v", tunAddr, err)
			os.Exit(1)
		}
		srv.srvLog(LevelSuccess, "tunnel listener %s (TLS)", tunAddr)
		if cfg.CertFile == "" {
			srv.srvLog(LevelWarn, "self-signed cert — run client with skipTLSVerify: true")
		}
	}

	srv.srvLog(LevelSuccess, "HTTP proxy listening on %s", httpAddr)
	if cfg.HTTPSAddr != "" {
		srv.srvLog(LevelSuccess, "HTTPS proxy listening on %s", cfg.HTTPSAddr)
	}

	// Start inspector web UI.
	var inspSrv *http.Server
	if inspect != "" {
		srv.inspector = NewInspector(httpAddr, tunAddr, token, inspectUser, inspectPass, &srv.count, srv)
		inspSrv = &http.Server{Addr: inspect, Handler: srv.inspector}
		go func() {
			srv.srvLog(LevelSuccess, "dashboard at http://%s", inspect)
			if err := inspSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				srv.srvLog(LevelError, "inspector: %v", err)
			}
		}()
	}

	go srv.acceptTunnelConns(tunLn)
	go srv.startJanitor()

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start native HTTPS listener if configured.
	// We use a manual tls.NewListener with LoadTLSConfigForHTTPS instead of
	// ListenAndServeTLS so that GetCertificate (SNI-aware) is used.  This is
	// required for wildcard certs (e.g. *.gotunnel.rgptv.site): without it the
	// TLS stack only matches the cert's exact SAN entries and hangs/rejects
	// connections to subdomains that are not explicitly listed in the cert.
	var httpsSrv *http.Server
	if cfg.HTTPSAddr != "" {
		httpsTLSCfg, err := LoadTLSConfigForHTTPS(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			srv.srvLog(LevelError, "HTTPS TLS setup: %v", err)
			os.Exit(1)
		}
		httpsLn, err := tls.Listen("tcp", cfg.HTTPSAddr, httpsTLSCfg)
		if err != nil {
			srv.srvLog(LevelError, "HTTPS listen %s: %v", cfg.HTTPSAddr, err)
			os.Exit(1)
		}
		httpsSrv = &http.Server{
			Handler:           srv,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := httpsSrv.Serve(httpsLn); err != nil && err != http.ErrServerClosed {
				srv.srvLog(LevelError, "HTTPS server: %v", err)
				os.Exit(1)
			}
		}()
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		srv.srvLog(LevelWarn, "received %v — shutting down", sig)
		tunLn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			srv.srvLog(LevelWarn, "HTTP shutdown: %v", err)
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(ctx); err != nil {
				srv.srvLog(LevelWarn, "HTTPS shutdown: %v", err)
			}
		}
		if inspSrv != nil {
			inspSrv.Shutdown(ctx)
		}
		// Close all TCP port listeners registered by tunnel clients.
		srv.mu.Lock()
		for addr, ln := range srv.tcpListeners {
			ln.Close()
			delete(srv.tcpListeners, addr)
		}
		srv.mu.Unlock()
		srv.closeAllSessions()
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		srv.srvLog(LevelError, "HTTP server: %v", err)
		os.Exit(1)
	}
	srv.srvLog(LevelInfo, "server stopped")
}

// acceptTunnelConns loops, accepting connections from tunnel clients.
func (s *Server) acceptTunnelConns(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed during shutdown
			}
			s.srvLog(LevelError, "tunnel accept: %v", err)
			time.Sleep(time.Second)
			continue
		}
		// Enable TCP keepalive so the OS detects dead peers.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		} else if tlsConn, ok := conn.(*tls.Conn); ok {
			if tc, ok := tlsConn.NetConn().(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(30 * time.Second)
			}
		}
		go s.handleTunnelConn(conn)
	}
}

// handleTunnelConn authenticates the new tunnel connection and adds it to the pool.
func (s *Server) handleTunnelConn(conn net.Conn) {
	// ── Per-IP rate limiting ─────────────────────────────────────────────────
	peerIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if peerIP == "" {
		peerIP = conn.RemoteAddr().String()
	}
	bucketVal, _ := s.authLimiters.LoadOrStore(peerIP, &authBucket{lastSeen: time.Now()})
	bucket := bucketVal.(*authBucket)
	if !bucket.allow() {
		s.srvLog(LevelWarn, "auth rate limited: %s", conn.RemoteAddr())
		fmt.Fprintf(conn, "ERROR rate limited\n")
		conn.Close()
		return
	}

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	r := bufio.NewReaderSize(conn, 64*1024)

	// ── Detect WebSocket Upgrade vs direct AUTH ───────────────────────────────
	peek, err := r.Peek(4)
	if err != nil {
		s.srvLog(LevelWarn, "auth peek: %v", err)
		conn.Close()
		return
	}
	if string(peek) == "GET " {
		req, err := http.ReadRequest(r)
		if err != nil || strings.ToLower(req.Header.Get("Upgrade")) != "websocket" {
			fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			conn.Close()
			return
		}
		wsKey := req.Header.Get("Sec-WebSocket-Key")
		if wsKey == "" {
			fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			conn.Close()
			return
		}
		const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		h := sha1.Sum([]byte(wsKey + wsMagic))
		acceptKey := base64.StdEncoding.EncodeToString(h[:])
		fmt.Fprintf(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: %s\r\n"+
				"\r\n",
			acceptKey,
		)
	}

	// ── CHALLENGE ──────────────────────────────────────────────────────────────
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		s.srvLog(LevelError, "nonce generation failed: %v", err)
		conn.Close()
		return
	}
	nonceHex := hex.EncodeToString(nonce)
	fmt.Fprintf(conn, "CHALLENGE %s\n", nonceHex)

	// ── AUTH ──────────────────────────────────────────────────────────────────
	line, err := r.ReadString('\n')
	if err != nil {
		s.srvLog(LevelError, "auth read: %v", err)
		conn.Close()
		return
	}

	line = strings.TrimSpace(line)
	parts := strings.Fields(line) // correctly handle spaces
	if len(parts) < 2 || parts[0] != "AUTH" {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		conn.Close()
		s.srvLog(LevelWarn, "auth format fail from %s", conn.RemoteAddr())
		return
	}

	clientHmac := parts[1]
	tunnelType := "http"
	if len(parts) > 2 {
		tunnelType = parts[2]
	}
	remoteAddr := ""
	if len(parts) > 3 && parts[3] != "-" {
		remoteAddr = parts[3]
	}

	mac := hmac.New(sha256.New, []byte(s.token))
	mac.Write([]byte(nonceHex))
	expectedHmac := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(clientHmac), []byte(expectedHmac)) != 1 {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		// Brief delay to slow down brute-force scanners.
		time.Sleep(authFailDelay)
		conn.Close()
		s.srvLog(LevelWarn, "auth failed (bad token) from %s", conn.RemoteAddr())
		return
	}

	// Auth succeeded — clear the deadline so the data path is unbounded.
	conn.SetDeadline(time.Time{})

	if tunnelType == "tcp" {
		if remoteAddr == "" {
			fmt.Fprintf(conn, "ERROR remote address required for tcp\n")
			conn.Close()
			return
		}

		// Validate against allowed TCP ports if configured.
		if !s.isTCPPortAllowed(remoteAddr) {
			fmt.Fprintf(conn, "ERROR tcp port %s is not allowed\n", remoteAddr)
			conn.Close()
			s.srvLog(LevelWarn, "TCP port denied: %s from %s", remoteAddr, conn.RemoteAddr())
			return
		}

		s.mu.Lock()
		_, exists := s.tcpListeners[remoteAddr]
		if !exists {
			ln, err := net.Listen("tcp", remoteAddr)
			if err != nil {
				s.mu.Unlock()
				fmt.Fprintf(conn, "ERROR %v\n", err)
				conn.Close()
				return
			}
			s.tcpListeners[remoteAddr] = ln
			go s.acceptTCPConns(ln, remoteAddr)
			s.srvLog(LevelSuccess, "TCP listener opened on %s", remoteAddr)
		}
		s.mu.Unlock()

		fmt.Fprintf(conn, "OK\n")
		
		session, err := yamux.Client(&bufferedConn{Conn: conn, r: r}, yamux.DefaultConfig())
		if err != nil {
			s.srvLog(LevelError, "yamux client err: %v", err)
			conn.Close()
			return
		}
		
		n := s.count.Add(1)
		s.srvLog(LevelSuccess, "tunnel connected %s → tcp:%s (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		s.tunnelMetaMu.Lock()
		prev := s.tunnelMeta[remoteAddr]
		s.tunnelMeta[remoteAddr] = TunnelMeta{
			APIKey:           prev.APIKey,
			APIKeyEnabled:    prev.APIKeyEnabled,
			BasicAuth:        prev.BasicAuth,
			BasicAuthEnabled: prev.BasicAuthEnabled,
			AIMode:           prev.AIMode,
			Type:             "tcp",
			Endpoint:         remoteAddr,
			ProxyURL:         "tcp://" + remoteAddr,
			ConnectedAt:      time.Now(),
			ClientIP:         conn.RemoteAddr().String(),
			Session:          session,
		}
		s.tunnelMetaMu.Unlock()
		return
	}

	if tunnelType == "http" && remoteAddr != "" {
		fmt.Fprintf(conn, "OK\n")
		
		session, err := yamux.Client(&bufferedConn{Conn: conn, r: r}, yamux.DefaultConfig())
		if err != nil {
			s.srvLog(LevelError, "yamux client err: %v", err)
			conn.Close()
			return
		}

		n := s.count.Add(1)
		s.srvLog(LevelSuccess, "tunnel connected %s → http:%s (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		s.tunnelMetaMu.Lock()
		prev := s.tunnelMeta[remoteAddr]
		s.tunnelMeta[remoteAddr] = TunnelMeta{
			APIKey:           prev.APIKey,
			APIKeyEnabled:    prev.APIKeyEnabled,
			BasicAuth:        prev.BasicAuth,
			BasicAuthEnabled: prev.BasicAuthEnabled,
			AIMode:           prev.AIMode,
			Type:             "http",
			Endpoint:         remoteAddr,
			ProxyURL:         s.buildProxyURL("http", remoteAddr),
			ConnectedAt:      time.Now(),
			ClientIP:         conn.RemoteAddr().String(),
			Session:          session,
		}
		s.tunnelMetaMu.Unlock()
		return
	}

	// Default HTTP pool.
	fmt.Fprintf(conn, "OK\n")
	
	session, err := yamux.Client(&bufferedConn{Conn: conn, r: r}, yamux.DefaultConfig())
	if err != nil {
		s.srvLog(LevelError, "yamux client err: %v", err)
		conn.Close()
		return
	}

	n := s.count.Add(1)
	s.srvLog(LevelSuccess, "tunnel connected %s → http:(default) (active: %d)", conn.RemoteAddr(), n)

	s.tunnelMetaMu.Lock()
	prev := s.tunnelMeta["(default)"]
	s.tunnelMeta["(default)"] = TunnelMeta{
		APIKey:           prev.APIKey,
		APIKeyEnabled:    prev.APIKeyEnabled,
		BasicAuth:        prev.BasicAuth,
		BasicAuthEnabled: prev.BasicAuthEnabled,
		AIMode:           prev.AIMode,
		Type:             "http",
		Endpoint:         "(default)",
		ProxyURL:         s.buildProxyURL("http", "(default)"),
		ConnectedAt:      time.Now(),
		ClientIP:         conn.RemoteAddr().String(),
		Session:          session,
	}
	s.tunnelMetaMu.Unlock()
}

// acceptTCPConns loops, accepting connections from external TCP clients.
func (s *Server) acceptTCPConns(l net.Listener, remoteAddr string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.srvLog(LevelError, "tcp accept %s: %v", remoteAddr, err)
			time.Sleep(time.Second)
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		}
		go s.handleExternalTCPConn(conn, remoteAddr)
	}
}

// handleExternalTCPConn proxies a raw TCP connection through a tcp pool worker.
func (s *Server) handleExternalTCPConn(conn net.Conn, remoteAddr string) {
	defer conn.Close()

	s.tunnelMetaMu.RLock()
	tMeta, ok := s.tunnelMeta[remoteAddr]
	s.tunnelMetaMu.RUnlock()

	if !ok || tMeta.Session == nil || tMeta.Session.IsClosed() {
		return
	}

	stream, err := tMeta.Session.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()

	if _, err := fmt.Fprintf(stream, "START\n"); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(stream, conn)
	go cp(conn, stream)
	<-done
	stream.Close()
	conn.Close()
	<-done
}

// ServeHTTP handles incoming HTTP requests from end users.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ── Per-tunnel API key check ─────────────────────────────────────────────
	endpointKey := s.getEndpointKey(r.Host)
	s.tunnelMetaMu.RLock()
	tMeta, hasTMeta := s.tunnelMeta[endpointKey]
	s.tunnelMetaMu.RUnlock()
	if hasTMeta && tMeta.APIKeyEnabled && tMeta.APIKey != "" {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
				key = strings.TrimPrefix(authHdr, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(tMeta.APIKey)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gotunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r.Header.Del("X-API-Key")
		if !tMeta.BasicAuthEnabled {
			r.Header.Del("Authorization")
		}
	}

	// ── Per-tunnel Basic Auth check ──────────────────────────────────────────
	if hasTMeta && tMeta.BasicAuthEnabled && tMeta.BasicAuth != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Basic ")), []byte(tMeta.BasicAuth)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="gotunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// ── Health endpoint (minimal info — detailed stats require the dashboard) ─
	if r.URL.Path == "/_tunnel/health" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	// ── WebSocket upgrade — needs special handling ────────────────────────────
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		s.proxyWebSocket(w, r)
		return
	}

	// ── Regular HTTP request ──────────────────────────────────────────────────
	var reqBody *cappedBuffer
	if s.inspector != nil && r.Body != nil {
		reqBody = &cappedBuffer{max: 1024 * 1024}
		r.Body = io.NopCloser(io.TeeReader(r.Body, reqBody))
	}

	s.proxyHTTP(w, r, reqBody)
}

// proxyHTTP forwards a regular HTTP request through a pooled tunnel connection.
func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request, reqBody *cappedBuffer) {
	start := time.Now()
	epKey := s.getEndpointKey(r.Host)

	s.tunnelMetaMu.RLock()
	tMeta, hasMeta := s.tunnelMeta[epKey]
	s.tunnelMetaMu.RUnlock()
	
	if !hasMeta || tMeta.Session == nil || tMeta.Session.IsClosed() {
		http.Error(w, "no tunnel clients connected — is the client running?", http.StatusServiceUnavailable)
		return
	}
	
	sub := ""
	if epKey != "(default)" {
		sub = epKey
	}
	aiMode := tMeta.AIMode

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	if r.Host == "" {
		out.URL.Host = "localhost"
	} else {
		out.URL.Host = r.Host
	}

	// Strip gateway-level auth headers only when the gateway enforced them.
	// If no gateway auth is active, forward the client's Authorization header
	// to the backend so downstream services can authenticate the request.
	s.tunnelMetaMu.RLock()
	epMeta := s.tunnelMeta[epKey]
	s.tunnelMetaMu.RUnlock()
	out.Header.Del("X-API-Key") // never forward our internal key header
	if epMeta.APIKeyEnabled || epMeta.BasicAuthEnabled {
		out.Header.Del("Authorization")
	}
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	// HSTS — tell browsers to always use HTTPS for this domain.
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	// Remove hop-by-hop headers before forwarding.
	removeHopByHop(out.Header)

	// Buffer the request body upfront so that the retry attempt can replay it.
	// In AI mode the cap is lifted to 100 MB to support base64 image payloads
	// and large context windows sent to Ollama.
	maxBodyBuf := int64(10 * 1024 * 1024) // 10 MB default
	if aiMode {
		maxBodyBuf = 100 * 1024 * 1024 // 100 MB for AI payloads
	}
	var bodyBuf []byte
	if out.Body != nil {
		var rerr error
		bodyBuf, rerr = io.ReadAll(io.LimitReader(out.Body, maxBodyBuf+1))
		out.Body.Close()
		if rerr != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if int64(len(bodyBuf)) > maxBodyBuf {
			limit := "10 MB"
			if aiMode {
				limit = "100 MB"
			}
			http.Error(w, "request body too large (max "+limit+")", http.StatusRequestEntityTooLarge)
			return
		}
		out.ContentLength = int64(len(bodyBuf))
	}

	// In AI mode, tell upstream proxies (nginx, CDN) not to buffer the response
	// so streaming tokens reach the browser immediately.
	if aiMode {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		// CORS — Open WebUI and similar browser clients call the API directly.
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		// Handle CORS preflight so the browser doesn't block the actual request.
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	if bodyBuf != nil {
		out.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}

	stream, err := tMeta.Session.OpenStream()
	if err != nil {
		http.Error(w, "failed to open stream to client", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	if err := out.Write(stream); err != nil {
		s.srvLog(LevelWarn, "tunnel write failed: %v", err)
		http.Error(w, "tunnel write error", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream), out)
	if err != nil {
		s.srvLog(LevelWarn, "tunnel read failed: %v", err)
		http.Error(w, "tunnel read error", http.StatusBadGateway)
		return
	}

	// Success — stream the response.
	s.streamResponse(w, resp, stream, aiMode)
	elapsed := time.Since(start)
	s.srvLog(LevelInfo, "%s %s → %d (%s)", r.Method, r.URL.Path, resp.StatusCode, elapsed.Round(time.Millisecond))
	if s.inspector != nil {
		var capturedBody []byte
		if reqBody != nil {
			reqBody.mu.Lock()
			capturedBody = make([]byte, len(reqBody.buf))
			copy(capturedBody, reqBody.buf)
			reqBody.mu.Unlock()
		}
		ep := sub
		if ep == "" {
			ep = "(default)"
		}
		s.inspector.Record(ep, clientIP(r), r.Method, r.URL.RequestURI(), r.Host, resp.StatusCode, elapsed, r.Header, resp.Header, r.ContentLength, resp.ContentLength, capturedBody)
	}
}

// streamResponse writes the upstream response to the HTTP client and returns
// the tunnel connection to the pool when possible.
// streamResponse writes the upstream response to the HTTP client and returns
// the tunnel connection to the pool when possible.
// aiMode enables per-chunk flushing with a small read buffer so LLM streaming
// tokens reach the browser immediately instead of waiting for a 32 KB fill.
func (s *Server) streamResponse(w http.ResponseWriter, resp *http.Response, stream net.Conn, aiMode bool) {
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if !isHopByHop(k) {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, canFlush := w.(http.Flusher)

	// AI mode: 512-byte buffer so each small chunk (a few tokens) is flushed
	// immediately instead of waiting for a 32 KB fill. Regular mode keeps the
	// larger 32 KB buffer for throughput efficiency.
	bufSize := 32 * 1024
	if aiMode {
		bufSize = 512
	}
	buf := make([]byte, bufSize)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				
				break
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
}

// proxyWebSocket tunnels a browser WebSocket connection bidirectionally.
func (s *Server) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	epKey := s.getEndpointKey(r.Host)
	s.tunnelMetaMu.RLock()
	tMeta, ok := s.tunnelMeta[epKey]
	s.tunnelMetaMu.RUnlock()

	if !ok || tMeta.Session == nil || tMeta.Session.IsClosed() {
		http.Error(w, "no tunnel clients connected", http.StatusServiceUnavailable)
		return
	}

	stream, err := tMeta.Session.OpenStream()
	if err != nil {
		http.Error(w, "failed to open stream to client", http.StatusBadGateway)
		return
	}
	defer stream.Close()

	// Hijack the browser-side connection so we can speak raw TCP.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return
	}
	browserConn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer browserConn.Close()

	// Forward the original upgrade request to the tunnel client.
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	if r.Host == "" {
		out.URL.Host = "localhost"
	} else {
		out.URL.Host = r.Host
	}
	// Strip gateway-level auth headers only when the gateway enforced them.
	pwsEpKey := s.getEndpointKey(r.Host)
	s.tunnelMetaMu.RLock()
	pwsMeta := s.tunnelMeta[pwsEpKey]
	s.tunnelMetaMu.RUnlock()
	out.Header.Del("X-API-Key") // never forward our internal key header
	if pwsMeta.APIKeyEnabled || pwsMeta.BasicAuthEnabled {
		out.Header.Del("Authorization")
	}
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	if err := out.Write(stream); err != nil {
		fmt.Fprintf(browserConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	// Read the 101 back from the client and relay it to the browser.
	resp, err := http.ReadResponse(bufio.NewReader(stream), out)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		if err == nil {
			resp.Body.Close()
		}
		fmt.Fprintf(browserConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	// Write the 101 response (and any buffered bytes) to the browser, then flush.
	resp.Write(brw)
	brw.Flush()

	s.srvLog(LevelInfo, "ws tunnel open: %s %s", r.Method, r.URL.Path)

	// Pipe both directions concurrently until either side closes.
	// FIX: write to browserConn directly (not brw.Writer) so WebSocket frames
	// are not stuck in a bufio buffer waiting for a flush that never comes.
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(stream, brw.Reader) 
	go cp(browserConn, stream)
	<-done
	browserConn.Close()
	stream.Close()
	<-done

	s.srvLog(LevelInfo, "ws tunnel closed: %s", r.URL.Path)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

type cappedBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) >= c.max {
		return len(p), nil
	}
	rem := c.max - len(c.buf)
	if len(p) > rem {
		c.buf = append(c.buf, p[:rem]...)
	} else {
		c.buf = append(c.buf, p...)
	}
	return len(p), nil
}



// getEndpointKey returns the tunnel endpoint key for a given host (subdomain or "(default)").
func (s *Server) getEndpointKey(host string) string {
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.tunnelMetaMu.RLock()
	defer s.tunnelMetaMu.RUnlock()
	// Primary: strict domain match.
	if s.domain != "" && strings.HasSuffix(hostOnly, "."+s.domain) {
		sub := strings.TrimSuffix(hostOnly, "."+s.domain)
		if _, ok := s.tunnelMeta[sub]; ok {
			return sub
		}
	}
	// Fallback: prefix match against known pool keys.
	for sub := range s.tunnelMeta {
		if strings.HasPrefix(hostOnly, sub+".") {
			return sub
		}
	}
	return "(default)"
}

// getEndpointKeyLocked is like getEndpointKey but assumes the caller already
// holds s.mu.RLock (and optionally s.tunnelMetaMu.RLock). It does not acquire
// any locks itself, avoiding lock-order inversions in callers that hold mu.
func (s *Server) getEndpointKeyLocked(host string) string {
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}
	s.tunnelMetaMu.RLock()
	defer s.tunnelMetaMu.RUnlock()
	// Primary: strict domain match.
	if s.domain != "" && strings.HasSuffix(hostOnly, "."+s.domain) {
		sub := strings.TrimSuffix(hostOnly, "."+s.domain)
		if _, ok := s.tunnelMeta[sub]; ok {
			return sub
		}
	}
	// Fallback: prefix match against known pool keys.
	for sub := range s.tunnelMeta {
		if strings.HasPrefix(hostOnly, sub+".") {
			return sub
		}
	}
	return "(default)"
}

// buildProxyURL constructs the public-facing proxy URL for a given tunnel.
func (s *Server) buildProxyURL(tunnelType, endpoint string) string {
	if tunnelType == "tcp" {
		return "tcp://" + endpoint
	}
	if endpoint == "(default)" {
		if s.httpsAddr != "" {
			if s.domain != "" {
				return "https://" + s.domain
			}
			return "https://" + s.httpsAddr
		}
		if s.domain != "" {
			return "http://" + s.domain
		}
		return "http://" + s.httpAddr
	}
	// subdomain
	if s.domain != "" {
		if s.httpsAddr != "" {
			return "https://" + endpoint + "." + s.domain
		}
		return "http://" + endpoint + "." + s.domain
	}
	return "http://" + endpoint + s.httpAddr
}









// startJanitor periodically scans all pools and removes dead connections.
// Named pools (subdomain / TCP) are only deleted after they have been
// continuously empty for poolEmptyGrace — a transient empty pool (all
// workers busy serving a request, or mid-reconnect) does not trigger deletion.
//
// Both s.mu and s.tunnelMetaMu are held simultaneously during map cleanup so
// that handleTunnelConn cannot insert new metadata for an endpoint between
// the moment we decide to delete its pool and the moment we delete its meta
// (TOCTOU fix). Blocking I/O (listener close) and logging are deferred until
// after the locks are released to avoid holding the write mutex during syscalls.
const poolEmptyGrace = 30 * time.Second

func (s *Server) startJanitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.authLimiters.Range(func(key, value any) bool {
			if b, ok := value.(*authBucket); ok && b.expired() {
				s.authLimiters.Delete(key)
			}
			return true
		})

		s.tunnelMetaMu.Lock()
		for ep, meta := range s.tunnelMeta {
			if meta.Session != nil && meta.Session.IsClosed() {
				delete(s.tunnelMeta, ep)
				s.mu.Lock()
				if ln, ok := s.tcpListeners[ep]; ok {
					ln.Close()
					delete(s.tcpListeners, ep)
				}
				s.mu.Unlock()
				s.srvLog(LevelInfo, "tunnel session closed and removed: %s", ep)
				s.count.Add(-1)
			}
		}
		s.tunnelMetaMu.Unlock()
	}
}

func (s *Server) closeAllSessions() {
	s.tunnelMetaMu.Lock()
	for _, meta := range s.tunnelMeta {
		if meta.Session != nil {
			meta.Session.Close()
		}
	}
	s.tunnelMetaMu.Unlock()
}



// keepAlive reports whether the tunnel connection should be returned to the
// pool after this response (i.e. the server did not request close).
func keepAlive(resp *http.Response) bool {
	if strings.ToLower(resp.Header.Get("Connection")) == "close" {
		return false
	}
	if resp.Proto == "HTTP/1.0" {
		return false
	}
	return true
}

// removeHopByHop strips hop-by-hop headers from h, including any headers
// listed in the Connection header itself.
func removeHopByHop(h http.Header) {
	// Headers named in Connection: are also hop-by-hop.
	for _, v := range h["Connection"] {
		for _, tok := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(tok))
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func isHopByHop(k string) bool {
	_, ok := hopByHopSet[strings.ToLower(k)]
	return ok
}

// clientIP returns the direct peer IP. It intentionally does NOT forward a
// client-supplied X-Forwarded-For because the server sits at the edge —
// any XFF already present came from an untrusted client and would allow IP
// spoofing. Only the real remote address from the TCP connection is trustworthy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// scheme returns "https" if the request arrived over TLS, otherwise "http".
// X-Forwarded-Proto is intentionally NOT trusted from clients — this server
// is the TLS termination point, so the scheme is determined solely from the
// connection itself.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// isTCPPortAllowed checks if a remote address is permitted by the server's
// AllowedTCPPorts configuration. An empty allow-list means all ports are allowed.
func (s *Server) isTCPPortAllowed(remoteAddr string) bool {
	if len(s.allowedTCPPorts) == 0 {
		return true // default allow — backward compatible
	}
	for _, allowed := range s.allowedTCPPorts {
		if allowed == remoteAddr {
			return true
		}
		// Support wildcard port patterns like ":20000-:30000" — simple exact match for now.
		// Operators can list specific ports like ":22222", ":33333".
	}
	return false
}


type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
