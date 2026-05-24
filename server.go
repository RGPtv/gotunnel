package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// poolConn pairs a raw net.Conn with its persistent buffered reader so we
// never lose bytes that were pre-read during authentication.
type poolConn struct {
	conn net.Conn
	r    *bufio.Reader
}

// Server accepts tunnel client connections and proxies incoming HTTP requests
// through them to the target service on the other end.
type Server struct {
	token  string
	apiKey string
	pool   chan *poolConn
	count  atomic.Int64 // active tunnel connections
}

// hopByHopHeaders are headers that must not be forwarded through a proxy.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailers", "Transfer-Encoding", "Upgrade",
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	httpAddr := fs.String("http", ":8080", "HTTP listen address (for end users / apps)")
	tunAddr  := fs.String("tun",  ":2222", "Tunnel listen address (for tunnel client)")
	token    := fs.String("token",  "", "Shared auth token — must match client's -token (required)")
	certFile := fs.String("cert",   "", "TLS cert PEM file (auto-generated if empty)")
	keyFile  := fs.String("key",    "", "TLS key PEM file (auto-generated if empty)")
	apiKey   := fs.String("apikey", "", "Optional API key required on all HTTP requests")
	noTLS   := fs.Bool("notls", false, "Disable TLS on tunnel port (use when behind a TLS-terminating proxy)")
	fs.Parse(args)

	if *token == "" {
		log.Fatal("ERROR: -token is required. Generate one with: gotunnel genkey")
	}

	srv := &Server{
		token:  *token,
		apiKey: *apiKey,
		pool:   make(chan *poolConn, 512),
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
	if *apiKey != "" {
		log.Printf("▶  API key auth    : enabled")
	}

	go srv.acceptTunnelConns(tunLn)

	httpSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: srv,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("HTTP server: %v", err)
	}
}

// acceptTunnelConns loops, accepting connections from tunnel clients.
func (s *Server) acceptTunnelConns(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("tunnel accept: %v", err)
			time.Sleep(time.Second)
			continue
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
		log.Printf("auth peek %s: %v", conn.RemoteAddr(), err)
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

	// ── AUTH ──────────────────────────────────────────────────────────────────
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("auth read %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "AUTH ") || strings.TrimPrefix(line, "AUTH ") != s.token {
		fmt.Fprintf(conn, "ERROR unauthorized\n")
		conn.Close()
		log.Printf("auth fail %s", conn.RemoteAddr())
		return
	}

	fmt.Fprintf(conn, "OK\n")
	n := s.count.Add(1)
	log.Printf("tunnel+ %s  (active: %d)", conn.RemoteAddr(), n)

	pc := &poolConn{conn: conn, r: r}
	select {
	case s.pool <- pc:
	default:
		conn.Close()
		s.count.Add(-1)
		log.Printf("pool full, rejected %s", conn.RemoteAddr())
	}
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
		if key != s.apiKey {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gotunnel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// ── Health endpoint ──────────────────────────────────────────────────────
	if r.URL.Path == "/_tunnel/health" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","tunnel_clients":%d,"pool_ready":%d}`,
			s.count.Load(), len(s.pool))
		return
	}

	// ── WebSocket upgrade — needs special handling ────────────────────────────
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		s.proxyWebSocket(w, r)
		return
	}

	// ── Regular HTTP request ──────────────────────────────────────────────────
	s.proxyHTTP(w, r)
}

// proxyHTTP forwards a regular HTTP request through a pooled tunnel connection.
func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	pc, ok := s.dequeue()
	if !ok {
		http.Error(w, "no tunnel clients connected — is the client running?", http.StatusServiceUnavailable)
		return
	}

	// Prepare the outbound request.
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = r.Host // preserve original Host

	// Set forwarding headers.
	out.Header.Del("X-API-Key")
	out.Header.Set("X-Forwarded-For", clientIP(r))
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", scheme(r))

	// Remove hop-by-hop headers before forwarding.
	removeHopByHop(out.Header)

	if err := out.Write(pc.conn); err != nil {
		s.closeConn(pc, "write request")
		http.Error(w, "tunnel write error", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(pc.r, out)
	if err != nil {
		s.closeConn(pc, "read response")
		http.Error(w, "tunnel read error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Determine whether the tunnel connection can be reused.
	reuse := keepAlive(resp)

	// Copy response headers (skip hop-by-hop).
	for k, vv := range resp.Header {
		if !isHopByHop(k) {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream body with flushing for SSE / chunked responses.
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
	pc, ok := s.dequeue()
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
	out.URL.Host = r.Host
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

	// Write 101 + any buffered bytes from the server to the browser.
	resp.Write(brw)
	brw.Flush()

	log.Printf("ws tunnel open: %s %s", r.Method, r.URL.Path)

	// Pipe both directions concurrently until either side closes.
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(pc.conn, brw)  // browser → tunnel
	go cp(brw, pc.r)     // tunnel → browser (uses buffered reader)
	<-done

	// WebSocket connections are never returned to the pool.
	s.closeConn(pc, "ws closed")
	log.Printf("ws tunnel closed: %s", r.URL.Path)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *Server) dequeue() (*poolConn, bool) {
	select {
	case pc := <-s.pool:
		return pc, true
	case <-time.After(10 * time.Second):
		return nil, false
	}
}

func (s *Server) enqueue(pc *poolConn) {
	select {
	case s.pool <- pc:
	default:
		s.closeConn(pc, "pool full on return")
	}
}

func (s *Server) closeConn(pc *poolConn, reason string) {
	pc.conn.Close()
	n := s.count.Add(-1)
	log.Printf("tunnel- (%s)  (active: %d)", reason, n)
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
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		return prior + ", " + r.RemoteAddr
	}
	return r.RemoteAddr
}

// scheme returns "https" if the request arrived over TLS (or was forwarded
// from a TLS proxy), otherwise "http".
func scheme(r *http.Request) string {
	if r.TLS != nil || strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
		return "https"
	}
	return "http"
}