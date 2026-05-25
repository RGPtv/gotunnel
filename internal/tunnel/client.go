package tunnel

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	apiKey     string
	targetAddr string
	noTLS      bool
	tlsConfig  *tls.Config
	httpClient *http.Client
	ctx        context.Context
	cancel     context.CancelFunc

	uiStatusMu sync.RWMutex
	uiStatus   string
	uiWorkers  atomic.Int32
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
	c.uiStatusMu.Lock()
	c.uiStatus = s
	c.uiStatusMu.Unlock()
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

func normalizeTargetAddr(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

func RunClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server    := fs.String("server",    "",             "Tunnel server — host:port or https://host[:port] (required)")
	token     := fs.String("token",     "",             "Auth token — must match server's -token (required)")
	target    := fs.String("target",    "localhost:8080","Local service to tunnel, e.g. localhost:3000")
	typeFlag  := fs.String("type",      "http",         "Tunnel type: 'http' (or websocket) or 'tcp'")
	subdomain := fs.String("subdomain", "",             "Request a specific subdomain (requires server to use -domain)")
	remote    := fs.String("remote",    "",             "Remote address/port to listen on for TCP tunnels, e.g. ':22222'")
	apiKey    := fs.String("apikey",    "",             "Optional API key for this tunnel (use 'auto' to auto-generate)")
	workers   := fs.Int("workers",      10,             "Number of parallel tunnel connections")
	insecure  := fs.Bool("k",           false,          "Skip TLS cert verification (for self-signed certs)")
	noTLS     := fs.Bool("notls",       false,          "Use plain TCP (when server runs -notls behind a TLS proxy)")
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

	if *apiKey == "auto" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate apikey: %v", err)
		}
		*apiKey = hex.EncodeToString(b)
	}
	if strings.ContainsAny(*apiKey, " \t\r\n") {
		log.Fatal("ERROR: -apikey must not contain whitespace")
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
		apiKey:     *apiKey,
		targetAddr: normalizeTargetAddr(*target),
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
				ResponseHeaderTimeout: 0, 
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
	if *apiKey != "" {
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", "API Key", *apiKey)
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
		if err := c.connectAndServe(id); err != nil {
			c.setStatus(fmt.Sprintf("connecting... (retrying in %v)", backoff))
			select {
			case <-time.After(backoff):
			case <-c.ctx.Done():
				return
			}
			jitter := time.Duration(0)
			if backoff > 0 {
				mRaw := make([]byte, 8)
				if _, rerr := rand.Read(mRaw); rerr == nil {
					var randInt int64
					for i := 0; i < 8; i++ {
						randInt = (randInt << 8) | int64(mRaw[i])
					}
					if randInt < 0 {
						randInt = -randInt
					}
					jitter = time.Duration(randInt % int64(backoff/2+1))
				}
			}
			backoff *= 2
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			backoff += jitter
		} else {
			backoff = time.Second
		}
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
	hijacked := false
	defer func() {
		if !hijacked {
			conn.Close()
		}
	}()

	// Ensure the connection is closed immediately when shutting down.
	// The done channel lets this goroutine exit when connectAndServe returns normally
	// (conn already closed), preventing a goroutine leak per worker per reconnect.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-c.ctx.Done():
			conn.Close()
		case <-watchDone:
		}
	}()

	reader := bufio.NewReaderSize(conn, 64*1024)

	wsRaw := make([]byte, 16)
	if _, err := rand.Read(wsRaw); err != nil {
		return fmt.Errorf("ws key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(wsRaw)
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
		return fmt.Errorf("upgrade rejected: %v", upgradeResp.Status)
	}

	chalLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	chalLine = strings.TrimSpace(chalLine)
	if !strings.HasPrefix(chalLine, "CHALLENGE ") {
		return fmt.Errorf("expected CHALLENGE, got %q", chalLine)
	}
	nonceHex := strings.TrimPrefix(chalLine, "CHALLENGE ")

	mac := hmac.New(sha256.New, []byte(c.token))
	mac.Write([]byte(nonceHex))
	clientHmac := hex.EncodeToString(mac.Sum(nil))

	remote := c.remoteAddr
	if remote == "" {
		remote = "-"
	}
	key := c.apiKey
	if key == "" {
		key = "-"
	}
	fmt.Fprintf(conn, "AUTH %s %s %s %s\n", clientHmac, c.tunnelType, remote, key)

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		return fmt.Errorf("auth rejected: %s", line)
	}

	c.setStatus("online")
	c.uiWorkers.Add(1)
	defer c.uiWorkers.Add(-1)

	if c.tunnelType == "tcp" {
		hijacked = true
		go func() {
			c.handleTCPWorker(id, conn, reader)
			conn.Close()
		}()
		return nil
	}

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}

		if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			hijacked = true
			go func() {
				c.handleWebSocket(id, conn, reader, req)
				conn.Close()
			}()
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

	targetConn, err := net.DialTimeout("tcp", strings.TrimPrefix(strings.TrimPrefix(c.targetAddr, "http://"), "https://"), 10*time.Second)
	if err != nil {
		log.Printf("[w%d] tcp dial target failed: %v", id, err)
		tunnelConn.Close() // forces server-side external client to get a clean reset
		return fmt.Errorf("dial target for tcp: %w", err)
	}
	defer targetConn.Close()

	log.Printf("[w%d] tcp session started: %s", id, c.targetAddr)

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(targetConn, tunnelReader) 
	go cp(tunnelConn, targetConn)   
	<-done
	tunnelConn.Close()
	targetConn.Close()
	<-done

	log.Printf("[w%d] tcp session closed", id)
	return nil
}

func (c *Client) handleWebSocket(id int, tunnelConn net.Conn, tunnelReader *bufio.Reader, req *http.Request) error {
	targetConn, err := net.DialTimeout("tcp", strings.TrimPrefix(strings.TrimPrefix(c.targetAddr, "http://"), "https://"), 10*time.Second)
	if err != nil {
		writeErrorResponse(tunnelConn, 502, err.Error())
		return fmt.Errorf("dial target for ws: %w", err)
	}
	defer targetConn.Close()

	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(strings.TrimPrefix(c.targetAddr, "http://"), "https://")
	req.Host = req.URL.Host
	req.RequestURI = ""
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Proto")

	if err := req.Write(targetConn); err != nil {
		return fmt.Errorf("ws write to target: %w", err)
	}

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

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(targetConn, tunnelReader)  
	go cp(tunnelConn, targetReader)  
	<-done
	targetConn.Close()
	tunnelConn.Close()
	<-done

	log.Printf("[w%d] ws closed: %s", id, req.URL.Path)
	return nil
}

func (c *Client) forwardToTarget(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(c.targetAddr, "https://") {
		req.URL.Scheme = "https"
		req.URL.Host = strings.TrimPrefix(c.targetAddr, "https://")
	} else {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(c.targetAddr, "http://")
	}
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.RequestURI = "" 

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
		fmt.Fprintf(os.Stderr, "warning: cannot open gotunnel.log: %v — logging disabled\n", err)
		log.SetOutput(io.Discard)
	}

	// Clear the screen once on startup before the ticker starts.
	fmt.Print("\033[2J")

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

	var b strings.Builder
	// Move cursor to top-left (screen was cleared once at startup).
	b.WriteString("\033[H")

	b.WriteString("gotunnel by @RGPtv                                      (Ctrl+C to quit)\n\n")
	c.uiStatusMu.RLock()
	uiStatus := c.uiStatus
	c.uiStatusMu.RUnlock()
	statusColor := "\033[32m" // green
	if uiStatus != "online" {
		statusColor = "\033[33m" // yellow
	}
	b.WriteString(fmt.Sprintf("Session Status                %s%s\033[0m\033[K\n", statusColor, uiStatus))

	if c.tunnelType == "tcp" {
		b.WriteString(fmt.Sprintf("Forwarding                    tcp://%s -> %s\033[K\n", c.serverAddr+c.remoteAddr, c.targetAddr))
	} else {
		if c.remoteAddr != "" {
			b.WriteString(fmt.Sprintf("Forwarding                    https://%s.%s -> %s\033[K\n", c.remoteAddr, c.serverAddr, c.targetAddr))
		} else {
			b.WriteString(fmt.Sprintf("Forwarding                    https://%s -> %s\033[K\n", c.serverAddr, c.targetAddr))
		}
	}
	b.WriteString(fmt.Sprintf("Active Workers                %d\033[K\n\n", c.uiWorkers.Load()))

	if c.tunnelType == "http" {
		b.WriteString("HTTP Requests\033[K\n")
		b.WriteString("-------------\033[K\n")
		if len(uiReqs) == 0 {
			b.WriteString("(No requests yet)\033[K\n")
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

				b.WriteString(fmt.Sprintf("%-6s %-42s %s%3d\033[0m  %s\033[K\n", r.method, path, color, r.status, r.dur.Round(time.Millisecond)))
			}
		}
	}

	// Clear any remaining lines from previous longer outputs.
	b.WriteString("\033[J")
	fmt.Print(b.String())
}
