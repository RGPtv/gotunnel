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
)

// poolConn pairs a raw net.Conn with its persistent buffered reader so we
// never lose bytes that were pre-read during authentication.
// pool holds the channel this connection belongs to so enqueue can return it
// to the correct pool (default, subdomain, or TCP).
type poolConn struct {
	conn   net.Conn
	r      *bufio.Reader
	pool   chan *poolConn // owning pool — never nil after construction
	closed int32          // atomic flag for idempotent close
}

// TunnelMeta stores per-tunnel metadata surfaced in the dashboard.
type TunnelMeta struct {
	APIKey      string
	Type        string
	Endpoint    string
	ProxyURL    string
	ConnectedAt time.Time
	ClientIP    string
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
	token        string
	basicAuth    string
	domain       string
	httpAddr     string
	httpsAddr    string
	poolSize     int
	pool         chan *poolConn
	httpPools    map[string]chan *poolConn
	tcpPools     map[string]chan *poolConn
	tcpListeners map[string]net.Listener
	mu           sync.RWMutex
	count        atomic.Int64 // active tunnel connections
	inspector    *Inspector
	tunnelMeta   map[string]TunnelMeta
	tunnelMetaMu sync.RWMutex
	logs         []ipc.LogEntry
	logsMu       sync.Mutex
	startTime    time.Time
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
	log.Printf(msg)
	if s != nil {
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
	poolSize := cfg.PoolSize
	if poolSize <= 0 { poolSize = 512 }

	if token == "auto" {
		b := make([]byte, 32)
		rand.Read(b)
		token = hex.EncodeToString(b)
	}

	if inspect != "" && inspectPass == "" {
		b := make([]byte, 10)
		rand.Read(b)
		inspectPass = hex.EncodeToString(b)
	}
	
	basicAuthEnc := ""
	if cfg.Auth != "" {
		basicAuthEnc = base64.StdEncoding.EncodeToString([]byte(cfg.Auth))
	}
srv := &Server{
		token:        token,
		basicAuth:    basicAuthEnc,
		domain:       cfg.Domain,
		httpAddr:     httpAddr,
		httpsAddr:    cfg.HTTPSAddr,
		poolSize:     poolSize,
		pool:         make(chan *poolConn, poolSize),
		httpPools:    make(map[string]chan *poolConn),
		tcpPools:     make(map[string]chan *poolConn),
		tcpListeners: make(map[string]net.Listener),
		tunnelMeta:   make(map[string]TunnelMeta),
		startTime: time.Now(),
	}

	
	ipc.StartIPCServer(41400, func() interface{} {
		srv.mu.RLock()
		srv.tunnelMetaMu.RLock()
		
		var tunnels []ipc.TunnelInfo
		for ep, tm := range srv.tunnelMeta {
			conns := 0
			if tm.Type == "tcp" {
				if p, ok := srv.tcpPools[ep]; ok {
					conns = len(p)
				}
			} else {
				if ep == "(default)" {
					conns = len(srv.pool)
				} else if p, ok := srv.httpPools[ep]; ok {
					conns = len(p)
				}
			}
			tunnels = append(tunnels, ipc.TunnelInfo{
				Endpoint:    tm.Endpoint,
				Type:        tm.Type,
				Connections: conns,
				ClientIP:    tm.ClientIP,
				ProxyURL:    tm.ProxyURL,
			})
		}
		srv.tunnelMetaMu.RUnlock()
		srv.mu.RUnlock()

		srv.logsMu.Lock()
		logs := make([]ipc.LogEntry, len(srv.logs))
		copy(logs, srv.logs)
		srv.logsMu.Unlock()

		return ipc.ServerState{
			Token:       token,
			HTTPAddr:    httpAddr,
			HTTPSAddr:   cfg.HTTPSAddr,
			TunAddr:     tunAddr,
			InspectAddr: inspect,
			DashUser:    inspectUser,
			DashPass:    inspectPass,
			ActiveConns: srv.count.Load(),
			TotalReqs:   0, // Simplified
			Uptime:      int64(time.Since(srv.startTime).Seconds()),
			Tunnels:     tunnels,
			Logs:        logs,
		}
	})

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
	if inspect != "" {
		srv.inspector = NewInspector(httpAddr, tunAddr, token, inspectUser, inspectPass, &srv.count, srv)
		go func() {
			isrv := &http.Server{Addr: inspect, Handler: srv.inspector}
			srv.srvLog(LevelSuccess, "dashboard at http://%s", inspect)
			if err := isrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				srv.srvLog(LevelError, "inspector: %v", err)
			}
		}()
	}

	go srv.acceptTunnelConns(tunLn)
	go srv.startJanitor()

	// Live stats ticker — pushes counts + tunnel list to TUI every second.
	

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start native HTTPS listener if configured.
	var httpsSrv *http.Server
	if cfg.HTTPSAddr != "" {
		httpsSrv = &http.Server{
			Addr:              cfg.HTTPSAddr,
			Handler:           srv,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := httpsSrv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil && err != http.ErrServerClosed {
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
		httpSrv.Shutdown(ctx)
		if httpsSrv != nil {
			httpsSrv.Shutdown(ctx)
		}
		srv.drainPool()
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
	conn.SetDeadline(time.Time{})

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
	apiKey := ""
	if len(parts) > 4 && parts[4] != "-" {
		// Join all remaining fields: apikey is always the last field and
		// must never contain spaces, but joining is defensive.
		apiKey = strings.Join(parts[4:], " ")
		if apiKey == "-" {
			apiKey = ""
		}
	}

	mac := hmac.New(sha256.New, []byte(s.token))
	mac.Write([]byte(nonceHex))
	expectedHmac := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(clientHmac), []byte(expectedHmac)) != 1 {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		conn.Close()
		s.srvLog(LevelWarn, "auth failed (bad token) from %s", conn.RemoteAddr())
		return
	}

	if tunnelType == "tcp" {
		if remoteAddr == "" {
			fmt.Fprintf(conn, "ERROR remote address required for tcp\n")
			conn.Close()
			return
		}

		// Probe the map without holding the lock across a blocking syscall.
		s.mu.Lock()
		pool, exists := s.tcpPools[remoteAddr]
		s.mu.Unlock()

		if !exists {
			ln, err := net.Listen("tcp", remoteAddr)
			if err != nil {
				fmt.Fprintf(conn, "ERROR %v\n", err)
				conn.Close()
				return
			}
			// Re-lock and double-check; another goroutine may have won the race.
			s.mu.Lock()
			if pool, exists = s.tcpPools[remoteAddr]; !exists {
				pool = make(chan *poolConn, s.poolSize)
				s.tcpPools[remoteAddr] = pool
				s.tcpListeners[remoteAddr] = ln
				go s.acceptTCPConns(ln, remoteAddr)
				s.srvLog(LevelSuccess, "TCP listener opened on %s", remoteAddr)
			} else {
				ln.Close() // lost race — discard the listener we just bound
			}
			s.mu.Unlock()
		}

		fmt.Fprintf(conn, "OK\n")
		n := s.count.Add(1)
		s.srvLog(LevelSuccess, "tunnel connected %s → tcp:%s (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		s.tunnelMetaMu.Lock()
		s.tunnelMeta[remoteAddr] = TunnelMeta{
			APIKey:      apiKey,
			Type:        "tcp",
			Endpoint:    remoteAddr,
			ProxyURL:    "tcp://" + remoteAddr,
			ConnectedAt: time.Now(),
			ClientIP:    conn.RemoteAddr().String(),
		}
		s.tunnelMetaMu.Unlock()

		pc := &poolConn{conn: conn, r: r, pool: pool}
		select {
		case pool <- pc:
		default:
			conn.Close()
			s.count.Add(-1)
			s.srvLog(LevelWarn, "pool full, rejected %s", conn.RemoteAddr())
		}
		return
	}

	if tunnelType == "http" && remoteAddr != "" {
		s.mu.Lock()
		pool, exists := s.httpPools[remoteAddr]
		if !exists {
			pool = make(chan *poolConn, s.poolSize)
			s.httpPools[remoteAddr] = pool
			s.srvLog(LevelSuccess, "HTTP subdomain tunnel: %s", remoteAddr)
		}
		s.mu.Unlock()

		fmt.Fprintf(conn, "OK\n")
		n := s.count.Add(1)
		s.srvLog(LevelSuccess, "tunnel connected %s → http:%s (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		s.tunnelMetaMu.Lock()
		s.tunnelMeta[remoteAddr] = TunnelMeta{
			APIKey:      apiKey,
			Type:        "http",
			Endpoint:    remoteAddr,
			ProxyURL:    s.buildProxyURL("http", remoteAddr),
			ConnectedAt: time.Now(),
			ClientIP:    conn.RemoteAddr().String(),
		}
		s.tunnelMetaMu.Unlock()

		pc := &poolConn{conn: conn, r: r, pool: pool}
		select {
		case pool <- pc:
		default:
			conn.Close()
			s.count.Add(-1)
			s.srvLog(LevelWarn, "pool full, rejected %s", conn.RemoteAddr())
		}
		return
	}

	// Default HTTP pool.
	fmt.Fprintf(conn, "OK\n")
	n := s.count.Add(1)
	s.srvLog(LevelSuccess, "tunnel connected %s → http:(default) (active: %d)", conn.RemoteAddr(), n)

	s.tunnelMetaMu.Lock()
	s.tunnelMeta["(default)"] = TunnelMeta{
		APIKey:      apiKey,
		Type:        "http",
		Endpoint:    "(default)",
		ProxyURL:    s.buildProxyURL("http", "(default)"),
		ConnectedAt: time.Now(),
		ClientIP:    conn.RemoteAddr().String(),
	}
	s.tunnelMetaMu.Unlock()

	pc := &poolConn{conn: conn, r: r, pool: s.pool}
	select {
	case s.pool <- pc:
	default:
		conn.Close()
		s.count.Add(-1)
		s.srvLog(LevelWarn, "pool full, rejected %s", conn.RemoteAddr())
	}
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

	s.mu.Lock()
	pool := s.tcpPools[remoteAddr]
	s.mu.Unlock()

	if pool == nil {
		return
	}

	pc, ok := s.dequeueFrom(pool)
	if !ok {
		return // No available tunnel connections
	}

	if _, err := fmt.Fprintf(pc.conn, "START\n"); err != nil {
		s.closeConn(pc, "tcp start write failed")
		return
	}

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(pc.conn, conn)
	go cp(conn, pc.r) // Use buffered reader from poolConn!
	<-done
	<-done

	s.closeConn(pc, "tcp session closed")
}

// ServeHTTP handles incoming HTTP requests from end users.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ── Per-tunnel API key check ─────────────────────────────────────────────
	endpointKey := s.getEndpointKey(r.Host)
	s.tunnelMetaMu.RLock()
	tMeta, hasTMeta := s.tunnelMeta[endpointKey]
	s.tunnelMetaMu.RUnlock()
	if hasTMeta && tMeta.APIKey != "" {
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
		// Strip gateway auth headers before forwarding to backend.
		// NOTE: delete X-API-Key always, but only delete Authorization if
		// basicAuth is NOT also configured — otherwise the basicAuth check
		// below needs to read it. The clone in proxyHTTP/proxyWebSocket
		// will strip it again via the s.basicAuth guard there.
		r.Header.Del("X-API-Key")
		if s.basicAuth == "" {
			r.Header.Del("Authorization")
		}
	}

	// ── Basic Auth check ──────────────────────────────────────────────────────
	if s.basicAuth != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Basic ")), []byte(s.basicAuth)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="gotunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// ── Health endpoint ──────────────────────────────────────────────────────
	if r.URL.Path == "/_tunnel/health" {
		s.mu.RLock()
		totalCapacity := len(s.pool)
		for _, p := range s.httpPools {
			totalCapacity += len(p)
		}
		for _, p := range s.tcpPools {
			totalCapacity += len(p)
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","tunnel_clients":%d,"pool_ready":%d}`,
			s.count.Load(), totalCapacity)
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
	pool, sub := s.getHTTPPool(r.Host)

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	if r.Host == "" {
		out.URL.Host = "localhost"
	} else {
		out.URL.Host = r.Host
	}

	// Strip gateway-level auth headers — they are not meant for the backend.
	out.Header.Del("X-API-Key")
	out.Header.Del("Authorization")
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	// Remove hop-by-hop headers before forwarding.
	removeHopByHop(out.Header)

	// Buffer the request body upfront so that the retry attempt can replay it.
	// Without this, out.Body is drained on the first write and the retry sends
	// an empty body for POST/PUT/PATCH requests.
	// We read up to maxBodyBuf+1 bytes: if we get more than maxBodyBuf, the
	// body exceeds the limit and we return 413 instead of silently truncating.
	var bodyBuf []byte
	if out.Body != nil {
		const maxBodyBuf = 10 * 1024 * 1024 // 10 MB
		var rerr error
		bodyBuf, rerr = io.ReadAll(io.LimitReader(out.Body, maxBodyBuf+1))
		out.Body.Close()
		if rerr != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if int64(len(bodyBuf)) > maxBodyBuf {
			http.Error(w, "request body too large (max 10 MB)", http.StatusRequestEntityTooLarge)
			return
		}
		out.ContentLength = int64(len(bodyBuf))
	}

	// Try up to 2 tunnel connections — the first may be stale.
	const maxAttempts = 2
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Reset body reader for each attempt.
		if bodyBuf != nil {
			out.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		}

		pc, ok := s.dequeueFrom(pool)
		if !ok {
			http.Error(w, "no tunnel clients connected — is the client running?", http.StatusServiceUnavailable)
			return
		}

		if err := out.Write(pc.conn); err != nil {
			s.closeConn(pc, "write request")
			if attempt < maxAttempts {
				s.srvLog(LevelWarn, "tunnel write failed (attempt %d/%d), retrying", attempt, maxAttempts)
				continue
			}
			http.Error(w, "tunnel write error", http.StatusBadGateway)
			return
		}

		resp, err := http.ReadResponse(pc.r, out)
		if err != nil {
			s.closeConn(pc, "read response")
			if attempt < maxAttempts {
				s.srvLog(LevelWarn, "tunnel read failed (attempt %d/%d), retrying", attempt, maxAttempts)
				continue
			}
			http.Error(w, "tunnel read error", http.StatusBadGateway)
			return
		}

		// Success — stream the response.
		s.streamResponse(w, resp, pc)
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
		return
	}
}

// streamResponse writes the upstream response to the HTTP client and returns
// the tunnel connection to the pool when possible.
func (s *Server) streamResponse(w http.ResponseWriter, resp *http.Response, pc *poolConn) {
	defer resp.Body.Close()

	reuse := keepAlive(resp)

	for k, vv := range resp.Header {
		if !isHopByHop(k) {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
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

	if reuse {
		s.enqueue(pc)
	} else {
		s.closeConn(pc, "connection: close")
	}
}

// proxyWebSocket tunnels a browser WebSocket connection bidirectionally.
func (s *Server) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	pool, _ := s.getHTTPPool(r.Host)
	pc, ok := s.dequeueFrom(pool)
	if !ok {
		http.Error(w, "no tunnel clients connected", http.StatusServiceUnavailable)
		return
	}

	// Hijack the browser-side connection so we can speak raw TCP.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		s.enqueue(pc)
		return
	}
	browserConn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		s.closeConn(pc, "hijack failed")
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
	// Strip gateway-level auth headers — they must not reach the backend.
	out.Header.Del("X-API-Key")
	out.Header.Del("Authorization")
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	if err := out.Write(pc.conn); err != nil {
		s.closeConn(pc, "ws write request")
		fmt.Fprintf(browserConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	// Read the 101 back from the client and relay it to the browser.
	resp, err := http.ReadResponse(pc.r, out)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		s.closeConn(pc, "ws upgrade response")
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
	go cp(pc.conn, brw.Reader) // browser → tunnel  (use buffered reader for pre-read bytes)
	go cp(browserConn, pc.r)   // tunnel  → browser  (write directly, no intermediate buffer)
	<-done
	browserConn.Close()
	pc.conn.Close()
	<-done

	// WebSocket connections are never returned to the pool.
	s.closeConn(pc, "ws closed")
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

func (s *Server) getHTTPPool(host string) (chan *poolConn, string) {
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.domain != "" && strings.HasSuffix(hostOnly, "."+s.domain) {
		sub := strings.TrimSuffix(hostOnly, "."+s.domain)
		if pool, ok := s.httpPools[sub]; ok {
			return pool, sub
		}
	}
	return s.pool, ""
}

// getEndpointKey returns the tunnel endpoint key for a given host (subdomain or "(default)").
func (s *Server) getEndpointKey(host string) string {
	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.domain != "" && strings.HasSuffix(hostOnly, "."+s.domain) {
		sub := strings.TrimSuffix(hostOnly, "."+s.domain)
		if _, ok := s.httpPools[sub]; ok {
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

func (s *Server) dequeueFrom(pool chan *poolConn) (*poolConn, bool) {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		// Fast-fail: if the pool is clearly empty, don't hold the goroutine for 10s.
		// We still fall through to the select so a connection arriving just after
		// the len check is not missed.
		select {
		case pc := <-pool:
			// Quick liveness probe: a non-blocking read on a healthy idle
			// connection returns a timeout error; a dead one returns EOF/reset.
			pc.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
			_, err := pc.r.Peek(1)
			pc.conn.SetReadDeadline(time.Time{})
			if err != nil && !isTimeout(err) {
				s.closeConn(pc, "dead on dequeue")
				continue // try next connection
			}
			return pc, true
		case <-deadline.C:
			return nil, false
		}
	}
}

// isTimeout reports whether err is a net timeout (i.e. the connection is alive
// but had nothing to read within the deadline).
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// enqueue returns pc to its own pool (the one it was dequeued from).
// FIX: previously this always returned to s.pool, which broke subdomain and
// TCP tunnels — connections from subdomain pools were returned to the wrong pool.
func (s *Server) enqueue(pc *poolConn) {
	select {
	case pc.pool <- pc:
	default:
		s.closeConn(pc, "pool full on return")
	}
}

func (s *Server) closeConn(pc *poolConn, reason string) {
	if atomic.CompareAndSwapInt32(&pc.closed, 0, 1) {
		pc.conn.Close()
		n := s.count.Add(-1)
		s.srvLog(LevelInfo, "tunnel- (%s)  (active: %d)", reason, n)
	}
}

// drainPool closes all idle connections in all pools.
func (s *Server) drainPool() {
	s.mu.Lock()
	defer s.mu.Unlock()

	drain := func(pool chan *poolConn) {
		for {
			select {
			case pc := <-pool:
				s.closeConn(pc, "draining")
			default:
				return
			}
		}
	}
	drain(s.pool)
	for _, p := range s.httpPools {
		drain(p)
	}
	for _, p := range s.tcpPools {
		drain(p)
	}
}

// startJanitor periodically scans all pools and removes dead connections.
// When a named pool (subdomain or TCP) becomes empty after cleaning, it is
// removed from the map so future requests immediately get a 503 instead of
// waiting 10 s for a connection that will never come.
func (s *Server) startJanitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanPool(s.pool)

		var deletedSubs, deletedTCPs []string
		deletedDefault := len(s.pool) == 0

		s.mu.Lock()
		for sub, p := range s.httpPools {
			s.cleanPool(p)
			if len(p) == 0 {
				delete(s.httpPools, sub)
				deletedSubs = append(deletedSubs, sub)
				s.srvLog(LevelInfo, "subdomain pool removed: %s (no active clients)", sub)
			}
		}
		for addr, p := range s.tcpPools {
			s.cleanPool(p)
			if len(p) == 0 {
				delete(s.tcpPools, addr)
				deletedTCPs = append(deletedTCPs, addr)
				if ln, ok := s.tcpListeners[addr]; ok {
					ln.Close()
					delete(s.tcpListeners, addr)
					s.srvLog(LevelInfo, "TCP listener closed: %s (no active clients)", addr)
				}
			}
		}
		s.mu.Unlock()

		if len(deletedSubs) > 0 || len(deletedTCPs) > 0 || deletedDefault {
			s.tunnelMetaMu.Lock()
			if deletedDefault {
				delete(s.tunnelMeta, "(default)")
			}
			for _, sub := range deletedSubs {
				delete(s.tunnelMeta, sub)
			}
			for _, addr := range deletedTCPs {
				delete(s.tunnelMeta, addr)
			}
			s.tunnelMetaMu.Unlock()
		}
	}
}

// cleanPool pops all items, checks their liveness, and pushes back the healthy ones.
func (s *Server) cleanPool(pool chan *poolConn) {
	n := len(pool)
	for i := 0; i < n; i++ {
		select {
		case pc := <-pool:
			// A 1ms future deadline: healthy idle conn → timeout error; dead conn → EOF/reset.
			pc.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
			_, err := pc.r.Peek(1)
			pc.conn.SetReadDeadline(time.Time{})
			if err != nil && !isTimeout(err) {
				s.closeConn(pc, "client disconnected")
			} else {
				select {
				case pool <- pc:
				default:
					s.closeConn(pc, "pool full in janitor")
				}
			}
		default:
			return
		}
	}
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

