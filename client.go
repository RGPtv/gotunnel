package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client connects to the tunnel server and forwards HTTP requests to the
// target service running locally.
type Client struct {
	serverAddr string
	token      string
	targetAddr string
	tlsConfig  *tls.Config
	httpClient *http.Client // reused for all requests to the target service
}

// normalizeServerAddr accepts any of:
//
//	vps.example.com:2222
//	https://vps.example.com:2222
//	https://vps.example.com      → port 443
//	http://vps.example.com       → port 80
func normalizeServerAddr(raw string) string {
	raw = strings.TrimRight(raw, "/")

	if !strings.Contains(raw, "://") {
		if _, _, err := net.SplitHostPort(raw); err == nil {
			return raw
		}
		return raw + ":443"
	}

	u, err := url.Parse(raw)
	if err != nil {
		log.Fatalf("invalid -server address %q: %v", raw, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server   := fs.String("server",  "",               "Tunnel server — host:port or https://host[:port] (required)")
	token    := fs.String("token",   "",               "Auth token — must match server's -token (required)")
	target   := fs.String("target",  "localhost:8080", "Local service to tunnel, e.g. localhost:3000")
	workers  := fs.Int("workers",    10,               "Number of parallel tunnel connections")
	insecure := fs.Bool("k",         false,            "Skip TLS cert verification (for self-signed certs)")
	fs.Parse(args)

	if *server == "" {
		log.Fatal("ERROR: -server is required")
	}
	if *token == "" {
		log.Fatal("ERROR: -token is required")
	}

	serverAddr := normalizeServerAddr(*server)

	c := &Client{
		serverAddr: serverAddr,
		token:      *token,
		targetAddr: *target,
		tlsConfig:  &tls.Config{InsecureSkipVerify: *insecure},
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          200,
				MaxIdleConnsPerHost:   50,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 0, // no timeout — target may be slow
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // pass redirects through unchanged
			},
		},
	}

	log.Printf("▶  Server  : %s  (resolved: %s)", *server, serverAddr)
	log.Printf("▶  Target  : %s", *target)
	log.Printf("▶  Workers : %d", *workers)
	if *insecure {
		log.Printf("⚠  TLS cert verification disabled (-k)")
	}

	done := make(chan struct{})
	for i := 0; i < *workers; i++ {
		go c.runWorker(i + 1)
	}
	<-done
}

// runWorker dials the tunnel server and processes requests until an
// unrecoverable error occurs, then reconnects after a brief pause.
func (c *Client) runWorker(id int) {
	backoff := time.Second
	for {
		log.Printf("[w%d] connecting to %s …", id, c.serverAddr)
		err := c.connectAndServe(id)
		if err != nil {
			log.Printf("[w%d] disconnected: %v — retrying in %s", id, err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// connectAndServe opens one TLS connection to the server, authenticates, and
// then processes HTTP/WebSocket requests in a loop until the connection breaks.
func (c *Client) connectAndServe(id int) error {
	conn, err := tls.Dial("tcp", c.serverAddr, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReaderSize(conn, 64*1024)

	// ── WebSocket upgrade handshake ───────────────────────────────────────────
	// Most HTTP proxies (GitHub Codespaces, ngrok, etc.) only forward
	// connections that look like valid WebSocket upgrades.
	wsKey := base64.StdEncoding.EncodeToString([]byte("gotunnel-key"))
	fmt.Fprintf(conn,
		"GET /_tunnel/connect HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n",
		c.serverAddr, wsKey,
	)
	upgradeResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return fmt.Errorf("upgrade read: %w", err)
	}
	upgradeResp.Body.Close()
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("upgrade rejected: %s", upgradeResp.Status)
	}

	// ── Authenticate ──────────────────────────────────────────────────────────
	fmt.Fprintf(conn, "AUTH %s\n", c.token)

	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("auth read: %w", err)
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		return fmt.Errorf("auth rejected by server: %s", line)
	}

	log.Printf("[w%d] ready — waiting for requests", id)

	// ── Request loop ──────────────────────────────────────────────────────────
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return fmt.Errorf("read request: %w", err)
		}

		log.Printf("[w%d] ← %s %s", id, req.Method, req.URL.RequestURI())

		// WebSocket upgrade from a browser — handle as a raw TCP pipe.
		if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			if err := c.handleWebSocket(id, conn, reader, req); err != nil {
				return fmt.Errorf("websocket: %w", err)
			}
			// After a WebSocket session the tunnel connection is spent.
			return nil
		}

		// Regular HTTP request.
		resp, proxyErr := c.forwardToTarget(req)
		if proxyErr != nil {
			log.Printf("[w%d] target error: %v", id, proxyErr)
			if err := writeErrorResponse(conn, 502, proxyErr.Error()); err != nil {
				return fmt.Errorf("write error response: %w", err)
			}
			continue
		}

		if err := resp.Write(conn); err != nil {
			resp.Body.Close()
			return fmt.Errorf("write response: %w", err)
		}
		resp.Body.Close()
		log.Printf("[w%d] → %d %s", id, resp.StatusCode, req.URL.RequestURI())
	}
}

// handleWebSocket dials the local target, completes the WebSocket handshake,
// then pipes both directions until either side closes.
func (c *Client) handleWebSocket(id int, tunnelConn net.Conn, tunnelReader *bufio.Reader, req *http.Request) error {
	// Dial the local target directly (raw TCP so we can splice).
	targetConn, err := net.DialTimeout("tcp", c.targetAddr, 10*time.Second)
	if err != nil {
		writeErrorResponse(tunnelConn, 502, err.Error())
		return fmt.Errorf("dial target for ws: %w", err)
	}
	defer targetConn.Close()

	// Rewrite and forward the upgrade request to the local service.
	req.URL.Scheme = "http"
	req.URL.Host = c.targetAddr
	req.Host = c.targetAddr
	req.RequestURI = ""
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Proto")

	if err := req.Write(targetConn); err != nil {
		return fmt.Errorf("ws write to target: %w", err)
	}

	// Read the 101 from the local service and relay it back through the tunnel.
	targetReader := bufio.NewReaderSize(targetConn, 64*1024)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		return fmt.Errorf("ws read from target: %w", err)
	}
	if err := resp.Write(tunnelConn); err != nil {
		return fmt.Errorf("ws relay 101: %w", err)
	}

	log.Printf("[w%d] ws open: %s", id, req.URL.Path)

	// Splice: tunnel ↔ target, bidirectionally.
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(targetConn, tunnelReader) // server → local target
	go cp(tunnelConn, targetReader) // local target → server
	<-done

	log.Printf("[w%d] ws closed: %s", id, req.URL.Path)
	return nil
}

// forwardToTarget rewrites the request URL to point at the local target service.
func (c *Client) forwardToTarget(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = c.targetAddr
	// Preserve the original Host header — many apps depend on it for routing.
	if req.Host == "" {
		req.Host = c.targetAddr
	}
	req.RequestURI = "" // must be empty when using http.Client

	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Proto")

	return c.httpClient.Do(req)
}

// writeErrorResponse writes a minimal HTTP/1.1 error response to w.
func writeErrorResponse(w io.Writer, code int, msg string) error {
	resp := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d Error", code),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(msg + "\n")),
	}
	return resp.Write(w)
}