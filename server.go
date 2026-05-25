package main

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
	"flag"
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
	"time"
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

// Server accepts tunnel client connections and proxies incoming HTTP requests
// through them to the target service on the other end.
type Server struct {
	token        string
	apiKey       string
	basicAuth    string
	domain       string
	poolSize     int
	pool         chan *poolConn
	httpPools    map[string]chan *poolConn
	tcpPools     map[string]chan *poolConn
	tcpListeners map[string]net.Listener
	mu           sync.RWMutex
	count        atomic.Int64 // active tunnel connections
	inspector    *Inspector
}

// hopByHopHeaders are headers that must not be forwarded through a proxy.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailers", "Transfer-Encoding", "Upgrade",
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	httpAddr := fs.String("http", ":8080", "HTTP listen address (for end users / apps)")
	tunAddr := fs.String("tun", ":2222", "Tunnel listen address (for tunnel client)")
	token := fs.String("token", "", "Shared auth token — must match client's -token (required)")
	certFile := fs.String("cert", "", "TLS cert PEM file (auto-generated if empty)")
	keyFile := fs.String("key", "", "TLS key PEM file (auto-generated if empty)")
	apiKey := fs.String("apikey", "", "Optional API key required on all HTTP requests")
	auth := fs.String("auth", "", "Optional HTTP Basic Auth (format: user:pass)")
	domain := fs.String("domain", "", "Base domain for subdomain routing (e.g., example.com)")
	noTLS := fs.Bool("notls", false, "Disable TLS on tunnel port (use when behind a TLS-terminating proxy)")
	httpsAddr := fs.String("https", "", "HTTPS listen address (e.g. :443) — requires -cert and -key")
	inspect := fs.String("inspect", ":4040", "Inspector web UI address (empty to disable)")
	inspectUser := fs.String("inspect-user", "admin", "Dashboard login username")
	inspectPass := fs.String("inspect-pass", "", "Dashboard login password (auto-generated if empty)")
	poolSize := fs.Int("poolsize", 512, "Maximum capacity per connection pool")
	fs.Parse(args)

	if *token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate token: %v", err)
		}
		*token = hex.EncodeToString(b)
		log.Printf("▶  Auto-generated token (give this to your clients)")
		log.Printf("   %s...", (*token)[:8])
	}

	if *inspect != "" && *inspectPass == "" {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate inspect password: %v", err)
		}
		*inspectPass = hex.EncodeToString(b)
		if err := os.WriteFile(".gotunnel-admin", []byte(fmt.Sprintf("username: %s\npassword: %s\n", *inspectUser, *inspectPass)), 0600); err != nil {
			log.Printf("▶  Dashboard login : user= %s  pass= %s", *inspectUser, *inspectPass)
		} else {
			log.Printf("▶  Dashboard credentials saved to .gotunnel-admin")
		}
	}

	basicAuthEnc := ""
	if *auth != "" {
		if strings.Count(*auth, ":") != 1 {
			log.Fatal("ERROR: -auth must be exactly in 'user:pass' format")
		}
		basicAuthEnc = base64.StdEncoding.EncodeToString([]byte(*auth))
	}

	srv := &Server{
		token:        *token,
		apiKey:       *apiKey,
		basicAuth:    basicAuthEnc,
		domain:       *domain,
		poolSize:     *poolSize,
		pool:         make(chan *poolConn, *poolSize),
		httpPools:    make(map[string]chan *poolConn),
		tcpPools:     make(map[string]chan *poolConn),
		tcpListeners: make(map[string]net.Listener),
	}

	var tunLn net.Listener
	var err error

	if *noTLS {
		tunLn, err = net.Listen("tcp", *tunAddr)
		if err != nil {
			log.Fatalf("Tunnel listen %s: %v", *tunAddr, err)
		}
		log.Printf("▶  Tunnel listener : %s (plain TCP — proxy handles TLS)", *tunAddr)
	} else {
		tlsCfg, err := makeTLSConfig(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("TLS setup: %v", err)
		}
		tunLn, err = tls.Listen("tcp", *tunAddr, tlsCfg)
		if err != nil {
			log.Fatalf("Tunnel listen %s: %v", *tunAddr, err)
		}
		log.Printf("▶  Tunnel listener : %s (TLS)", *tunAddr)
		if *certFile == "" {
			log.Printf("ℹ  Self-signed cert — run client with -k flag")
		}
	}

	log.Printf("▶  HTTP proxy      : %s", *httpAddr)
	if *httpsAddr != "" {
		log.Printf("▶  HTTPS proxy     : %s", *httpsAddr)
	}
	if *apiKey != "" {
		log.Printf("▶  API key auth    : enabled")
	}

	// Start inspector web UI.
	if *inspect != "" {
		srv.inspector = NewInspector(*httpAddr, *tunAddr, *token, *inspectUser, *inspectPass, &srv.count, srv)
		go func() {
			isrv := &http.Server{Addr: *inspect, Handler: srv.inspector}
			log.Printf("▶  Inspector       : http://%s", *inspect)
			if err := isrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("inspector: %v", err)
			}
		}()
	}

	go srv.acceptTunnelConns(tunLn)
	go srv.startJanitor()

	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start native HTTPS server if -https flag is provided.
	var httpsSrv *http.Server
	if *httpsAddr != "" {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("ERROR: -https requires -cert and -key flags")
		}
		httpsSrv = &http.Server{
			Addr:              *httpsAddr,
			Handler:           srv,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := httpsSrv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server: %v", err)
			}
		}()
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		sig := <-sigCh
		log.Printf("received %v — shutting down", sig)
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
		log.Fatalf("HTTP server: %v", err)
	}
	log.Printf("server stopped")
}

// acceptTunnelConns loops, accepting connections from tunnel clients.
func (s *Server) acceptTunnelConns(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // listener closed during shutdown
			}
			log.Printf("tunnel accept: %v", err)
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
		log.Printf("auth peek: %v", err)
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
	rand.Read(nonce)
	nonceHex := hex.EncodeToString(nonce)
	fmt.Fprintf(conn, "CHALLENGE %s\n", nonceHex)

	// ── AUTH ──────────────────────────────────────────────────────────────────
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("auth read: %v", err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})

	line = strings.TrimSpace(line)
	parts := strings.Fields(line) // correctly handle spaces
	if len(parts) < 2 || parts[0] != "AUTH" {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		conn.Close()
		log.Printf("auth format fail")
		return
	}

	clientHmac := parts[1]
	tunnelType := "http"
	if len(parts) > 2 {
		tunnelType = parts[2]
	}
	remoteAddr := ""
	if len(parts) > 3 {
		remoteAddr = parts[3]
	}

	mac := hmac.New(sha256.New, []byte(s.token))
	mac.Write([]byte(nonceHex))
	expectedHmac := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(clientHmac), []byte(expectedHmac)) != 1 {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		conn.Close()
		log.Printf("auth hmac mismatch")
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
				log.Printf("▶  TCP listener    : %s (requested by client)", remoteAddr)
			} else {
				ln.Close() // lost race — discard the listener we just bound
			}
			s.mu.Unlock()
		}

		fmt.Fprintf(conn, "OK\n")
		n := s.count.Add(1)
		log.Printf("tunnel+ %s  (tcp: %s) (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		pc := &poolConn{conn: conn, r: r, pool: pool}
		select {
		case pool <- pc:
		default:
			conn.Close()
			s.count.Add(-1)
			log.Printf("pool full, rejected %s", conn.RemoteAddr())
		}
		return
	}

	if tunnelType == "http" && remoteAddr != "" {
		s.mu.Lock()
		pool, exists := s.httpPools[remoteAddr]
		if !exists {
			pool = make(chan *poolConn, s.poolSize)
			s.httpPools[remoteAddr] = pool
			log.Printf("▶  HTTP subdomain  : %s (requested by client)", remoteAddr)
		}
		s.mu.Unlock()

		fmt.Fprintf(conn, "OK\n")
		n := s.count.Add(1)
		log.Printf("tunnel+ %s  (http: %s) (active: %d)", conn.RemoteAddr(), remoteAddr, n)

		pc := &poolConn{conn: conn, r: r, pool: pool}
		select {
		case pool <- pc:
		default:
			conn.Close()
			s.count.Add(-1)
			log.Printf("pool full, rejected %s", conn.RemoteAddr())
		}
		return
	}

	// Default HTTP pool.
	fmt.Fprintf(conn, "OK\n")
	n := s.count.Add(1)
	log.Printf("tunnel+ %s  (active: %d)", conn.RemoteAddr(), n)

	pc := &poolConn{conn: conn, r: r, pool: s.pool}
	select {
	case s.pool <- pc:
	default:
		conn.Close()
		s.count.Add(-1)
		log.Printf("pool full, rejected %s", conn.RemoteAddr())
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
			log.Printf("tcp accept %s: %v", remoteAddr, err)
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
	pc.conn.Close()
	<-done

	s.closeConn(pc, "tcp session closed")
}

// ServeHTTP handles incoming HTTP requests from end users.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ── API key check ────────────────────────────────────────────────────────
	if s.apiKey != "" {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.apiKey)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gotunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
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
	if s.apiKey != "" || s.basicAuth != "" {
		out.Header.Del("Authorization")
	}
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	// Remove hop-by-hop headers before forwarding.
	removeHopByHop(out.Header)

	// Buffer the request body upfront so that the retry attempt can replay it.
	// Without this, out.Body is drained on the first write and the retry sends
	// an empty body for POST/PUT/PATCH requests.
	var bodyBuf []byte
	if out.Body != nil {
		const maxBodyBuf = 10 * 1024 * 1024 // 10 MB
		var rerr error
		bodyBuf, rerr = io.ReadAll(io.LimitReader(out.Body, maxBodyBuf))
		out.Body.Close()
		if rerr != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
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
				log.Printf("tunnel write failed (attempt %d/%d), retrying", attempt, maxAttempts)
				continue
			}
			http.Error(w, "tunnel write error", http.StatusBadGateway)
			return
		}

		resp, err := http.ReadResponse(pc.r, out)
		if err != nil {
			s.closeConn(pc, "read response")
			if attempt < maxAttempts {
				log.Printf("tunnel read failed (attempt %d/%d), retrying", attempt, maxAttempts)
				continue
			}
			http.Error(w, "tunnel read error", http.StatusBadGateway)
			return
		}

		// Success — stream the response.
		s.streamResponse(w, resp, pc)
		elapsed := time.Since(start)
		log.Printf("%s %s → %d (%s)", r.Method, r.URL.Path, resp.StatusCode, elapsed.Round(time.Millisecond))
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
			s.inspector.Record(ep, r.Method, r.URL.RequestURI(), r.Host, resp.StatusCode, elapsed, r.Header, resp.Header, r.ContentLength, resp.ContentLength, capturedBody)
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

	log.Printf("ws tunnel open: %s %s", r.Method, r.URL.Path)

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
	log.Printf("ws tunnel closed: %s", r.URL.Path)
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

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.domain != "" && strings.HasSuffix(hostOnly, "."+s.domain) {
		sub := strings.TrimSuffix(hostOnly, "."+s.domain)
		if pool, ok := s.httpPools[sub]; ok {
			return pool, sub
		}
	}
	return s.pool, ""
}

func (s *Server) dequeueFrom(pool chan *poolConn) (*poolConn, bool) {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
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
		log.Printf("tunnel- (%s)  (active: %d)", reason, n)
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
	for range ticker.C {
		s.cleanPool(s.pool)

		s.mu.Lock()
		for sub, p := range s.httpPools {
			s.cleanPool(p)
			if len(p) == 0 {
				delete(s.httpPools, sub)
				log.Printf("subdomain pool removed: %s (no active clients)", sub)
			}
		}
		for addr, p := range s.tcpPools {
			s.cleanPool(p)
			if len(p) == 0 {
				delete(s.tcpPools, addr)
				if ln, ok := s.tcpListeners[addr]; ok {
					ln.Close()
					delete(s.tcpListeners, addr)
					log.Printf("TCP listener closed: %s (no active clients)", addr)
				}
			}
		}
		s.mu.Unlock()
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
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

// clientIP extracts the real client IP, respecting X-Forwarded-For from
// upstream proxies.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		return prior + ", " + host
	}
	return host
}

// scheme returns "https" if the request arrived over TLS (or was forwarded
// from a TLS proxy), otherwise "http".
func scheme(r *http.Request) string {
	if r.TLS != nil || strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
		return "https"
	}
	return "http"
}
