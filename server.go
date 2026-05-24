package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
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

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	httpAddr := fs.String("http",   ":8080", "HTTP listen address (for end users / apps)")
	tunAddr  := fs.String("tun",    ":2222", "Tunnel listen address (for tunnel client)")
	token    := fs.String("token",  "",      "Shared auth token — must match client's -token (required)")
	certFile := fs.String("cert",   "",      "TLS cert PEM file (auto-generated if empty)")
	keyFile  := fs.String("key",    "",      "TLS key PEM file (auto-generated if empty)")
	apiKey   := fs.String("apikey", "",      "Optional API key required on all HTTP requests")
	noTLS    := fs.Bool("notls",   false,   "Disable TLS on tunnel port (use when behind a TLS-terminating proxy such as GitHub Codespaces, ngrok, Cloudflare Tunnel)")
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
// It supports two handshake styles:
//
//  1. Direct: client sends "AUTH <token>\n" immediately.
//  2. WebSocket Upgrade: client sends a GET /_tunnel/connect with
//     "Upgrade: websocket"; used when the tunnel port sits behind an HTTP
//     reverse proxy (GitHub Codespaces, ngrok, Cloudflare Tunnel, etc.).
func (s *Server) handleTunnelConn(conn net.Conn) {
	// Give the client 15 s to complete the handshake.
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
		// Client is speaking HTTP — perform a real WebSocket upgrade so that
		// any intermediate proxy (GitHub Codespaces, ngrok, Cloudflare, etc.)
		// is satisfied, then fall through to AUTH below.
		req, err := http.ReadRequest(r)
		if err != nil || strings.ToLower(req.Header.Get("Upgrade")) != "websocket" {
			fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			conn.Close()
			return
		}
		// Compute the standard WebSocket accept key so strict proxies don't reject us.
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

	// ── AUTH line (same for both paths) ──────────────────────────────────────
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("auth read %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after auth

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
		// available for HTTP handlers
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

	// ── Built-in health endpoint ─────────────────────────────────────────────
	if r.URL.Path == "/_tunnel/health" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","tunnel_clients":%d,"pool_ready":%d}`,
			s.count.Load(), len(s.pool))
		return
	}

	// ── Dequeue a tunnel connection ──────────────────────────────────────────
	var pc *poolConn
	select {
	case pc = <-s.pool:
	case <-time.After(10 * time.Second):
		http.Error(w, "no tunnel clients connected — is the client running?",
			http.StatusServiceUnavailable)
		return
	}

	// Strip internal headers, add forwarding info.
	r.Header.Del("X-API-Key")
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("X-Forwarded-Proto", "http")

	// ── Forward request through tunnel ───────────────────────────────────────
	if err := r.Write(pc.conn); err != nil {
		s.closeConn(pc, "write request")
		http.Error(w, "tunnel write error", http.StatusBadGateway)
		return
	}

	// ── Read response from tunnel ────────────────────────────────────────────
	resp, err := http.ReadResponse(pc.r, r)
	if err != nil {
		s.closeConn(pc, "read response")
		http.Error(w, "tunnel read error", http.StatusBadGateway)
		return
	}

	// Copy response headers to the client.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// ── Stream response body (supports SSE / chunked output) ─────────────────
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			_, werr := w.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
			if werr != nil {
				break // client disconnected
			}
		}
		if rerr != nil {
			break
		}
	}
	resp.Body.Close()

	// ── Return connection to pool ─────────────────────────────────────────────
	select {
	case s.pool <- pc:
		// reused
	default:
		s.closeConn(pc, "pool full on return")
	}
}

func (s *Server) closeConn(pc *poolConn, reason string) {
	pc.conn.Close()
	n := s.count.Add(-1)
	log.Printf("tunnel- (%s)  (active: %d)", reason, n)
}
