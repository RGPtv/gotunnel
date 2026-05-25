package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client connects to the tunnel server and forwards HTTP requests to the
// target service running locally.
type Client struct {
	serverAddr string
	token      string
	tunnelType string
	remoteAddr string
	targetAddr string
	noTLS      bool
	tlsConfig  *tls.Config
	httpClient *http.Client
	ctx        context.Context
	cancel     context.CancelFunc

	uiStatus  string
	uiWorkers atomic.Int32
}

type uiRequest struct {
	method string
	path   string
	status int
	dur    time.Duration
}

var (
	uiMu   sync.Mutex
	uiReqs []uiRequest
)

func (c *Client) setStatus(s string) {
	c.uiStatus = s
}

func addUIReq(method, path string, status int, dur time.Duration) {
	uiMu.Lock()
	defer uiMu.Unlock()
	uiReqs = append(uiReqs, uiRequest{method, path, status, dur})
	if len(uiReqs) > 10 {
		uiReqs = uiReqs[1:]
	}
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
	server := fs.String("server", "", "Tunnel server — host:port or https://host[:port] (required)")
	token := fs.String("token", "", "Auth token — must match server's -token (required)")
	target := fs.String("target", "localhost:8080", "Local service to tunnel, e.g. localhost:3000")
	typeFlag := fs.String("type", "http", "Tunnel type: 'http' (or websocket) or 'tcp'")
	subdomain := fs.String("subdomain", "", "Request a specific subdomain (requires server to use -domain)")
	remote := fs.String("remote", "", "Remote address/port to listen on for TCP tunnels, e.g. ':22222'")
	workers := fs.Int("workers", 10, "Number of parallel tunnel connections")
	insecure := fs.Bool("k", false, "Skip TLS cert verification (for self-signed certs)")
	noTLS := fs.Bool("notls", false, "Use plain TCP (when server runs -notls behind a TLS proxy)")
	fs.Parse(args)

	if *server == "" {
		fmt.Print("? Enter the tunnel server address (e.g. example.com:2222): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		*server = strings.TrimSpace(input)
	}
	if *token == "" {
		fmt.Print("? Enter your auth token: ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		*token = strings.TrimSpace(input)
	}

	if *server == "" || *token == "" {
		log.Fatal("ERROR: -server and -token are required")
	}
	if *typeFlag == "tcp" && *remote == "" {
		log.Fatal("ERROR: -remote is required for tcp tunnels (e.g. -remote :22222)")
	}
	if *subdomain != "" && *typeFlag != "http" {
		log.Fatal("ERROR: -subdomain can only be used with -type http")
	}

	remoteVal := *remote
	if *typeFlag == "http" && *subdomain != "" {
		remoteVal = *subdomain
	}

	serverAddr := normalizeServerAddr(*server)

	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		serverAddr: serverAddr,
		token:      *token,
		tunnelType: *typeFlag,
		remoteAddr: remoteVal,
		targetAddr: *target,
		noTLS:      *noTLS,
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
				return http.ErrUseLastResponse
			},
		},
		tlsConfig: &tls.Config{InsecureSkipVerify: *insecure},
		uiStatus:  "connecting...",
		ctx:       ctx,
		cancel:    cancel,
	}

	c.startUI()

	// ── Startup banner ───────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  \x1b[1;36mgotunnel\x1b[0m client\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Tunnel", serverAddr)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Type", *typeFlag)
	if *typeFlag == "tcp" {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Remote Port", *remote)
	}
	if *typeFlag == "http" && *subdomain != "" {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Subdomain", *subdomain)
	}
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Forwarding", *target)
	fmt.Fprintf(os.Stderr, "  %-14s %d\n", "Workers", *workers)
	if *insecure {
		fmt.Fprintf(os.Stderr, "  %-14s disabled (-k)\n", "TLS Verify")
	}
	fmt.Fprintln(os.Stderr)

	// Graceful shutdown on SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c.runWorker(id)
		}(i + 1)
	}
	wg.Wait()
}

// runWorker dials the tunnel server and processes requests until an
// unrecoverable error occurs, then reconnects after a brief pause.
func (c *Client) runWorker(id int) {
	backoff := time.Second
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.setStatus("reconnecting")
		err := c.connectAndServe(id)
		if err != nil && c.ctx.Err() == nil {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		return
	}
}

func (c *Client) connectAndServe(id int) error {
	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if c.noTLS {
		conn, err = dialer.DialContext(c.ctx, "tcp", c.serverAddr)
	} else {
		conn, err = tls.DialWithDialer(dialer, "tcp", c.serverAddr, c.tlsConfig)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	reader := bufio.NewReaderSize(conn, 64*1024)

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
		return err
	}
	upgradeResp.Body.Close()
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("upgrade rejected")
	}

	if c.tunnelType == "tcp" || (c.tunnelType == "http" && c.remoteAddr != "") {
		fmt.Fprintf(conn, "AUTH %s %s %s\n", c.token, c.tunnelType, c.remoteAddr)
	} else {
		fmt.Fprintf(conn, "AUTH %s\n", c.token)
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		return fmt.Errorf("auth rejected")
	}

	c.uiWorkers.Add(1)
	c.setStatus("online")
	defer c.uiWorkers.Add(-1)

	if c.tunnelType == "tcp" {
		return c.handleTCPWorker(id, conn, reader)
	}

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}

		if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			c.handleWebSocket(id, conn, reader, req)
			return nil
		}

		start := time.Now()
		resp, proxyErr := c.forwardToTarget(req)
		if proxyErr != nil {
			writeErrorResponse(conn, 502, proxyErr.Error())
			continue
		}

		if err := resp.Write(conn); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		addUIReq(req.Method, req.URL.RequestURI(), resp.StatusCode, time.Since(start))
	}
}

func (c *Client) handleTCPWorker(id int, tunnelConn net.Conn, tunnelReader *bufio.Reader) error {
	line, err := tunnelReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read tcp start: %w", err)
	}
	if strings.TrimSpace(line) != "START" {
		return fmt.Errorf("unexpected command: %s", line)
	}

	// Dial the local target directly (raw TCP).
	targetConn, err := net.DialTimeout("tcp", c.targetAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial target for tcp: %w", err)
	}
	defer targetConn.Close()

	log.Printf("[w%d] tcp session started: %s", id, c.targetAddr)

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	// Splice: tunnel ↔ target, bidirectionally.
	go cp(targetConn, tunnelReader) // server → local target
	go cp(tunnelConn, targetConn)   // local target → server
	<-done
	tunnelConn.Close()
	targetConn.Close()
	<-done

	log.Printf("[w%d] tcp session closed", id)
	return nil
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
	defer resp.Body.Close()
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
	targetConn.Close()
	tunnelConn.Close()
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

// ── TUI Dashboard ─────────────────────────────────────────────────────────────

func (c *Client) startUI() {
	f, err := os.OpenFile("gotunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(f)
	} else {
		log.SetOutput(io.Discard)
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	go func() {
		for range ticker.C {
			c.drawUI()
		}
	}()
}

func (c *Client) drawUI() {
	uiMu.Lock()
	defer uiMu.Unlock()

	// Clear screen and reset cursor (ANSI escapes)
	fmt.Print("\033[H\033[2J")

	fmt.Println("gotunnel by @RGPtv                                      (Ctrl+C to quit)")
	fmt.Println()
	statusColor := "\033[32m" // green
	if c.uiStatus != "online" {
		statusColor = "\033[33m" // yellow
	}
	fmt.Printf("Session Status                %s%s\033[0m\n", statusColor, c.uiStatus)
	
	if c.tunnelType == "tcp" {
		fmt.Printf("Forwarding                    tcp://%s -> %s\n", c.serverAddr+c.remoteAddr, c.targetAddr)
	} else {
		if c.remoteAddr != "" {
			fmt.Printf("Forwarding                    https://%s.%s -> %s\n", c.remoteAddr, c.serverAddr, c.targetAddr)
		} else {
			fmt.Printf("Forwarding                    https://%s -> %s\n", c.serverAddr, c.targetAddr)
		}
	}
	fmt.Printf("Active Workers                %d\n", c.uiWorkers.Load())
	fmt.Println()

	if c.tunnelType == "http" {
		fmt.Println("HTTP Requests")
		fmt.Println("-------------")
		if len(uiReqs) == 0 {
			fmt.Println("(No requests yet)")
		} else {
			for _, r := range uiReqs {
				color := "\033[32m" // green
				if r.status >= 500 {
					color = "\033[31m" // red
				} else if r.status >= 400 {
					color = "\033[33m" // yellow
				} else if r.status >= 300 {
					color = "\033[36m" // cyan
				}
				
				path := r.path
				if len(path) > 40 {
					path = path[:37] + "..."
				}
				
				fmt.Printf("%-6s %-42s %s%3d\033[0m  %s\n", r.method, path, color, r.status, r.dur.Round(time.Millisecond))
			}
		}
	}
}