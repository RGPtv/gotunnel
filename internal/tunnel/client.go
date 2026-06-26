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
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
	"github.com/RGPtv/gotunnel/internal/mux"
)

// Client connects to the tunnel server and forwards HTTP requests to the
// target service running locally.
type Client struct {
	name       string
	serverAddr string
	token      string
	tunnelType string
	remoteAddr string
	subdomain  string
	targetAddr string
	noTLS      bool
	tlsConfig  *tls.Config
	httpClient *http.Client
	ctx        context.Context
	cancel     context.CancelFunc

	uiStatusMu sync.RWMutex
	uiStatus   string
	uiStreams  atomic.Int32
}

type uiRequest struct {
	tunnel string
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

func (c *Client) getRemoteAddr() string {
	c.uiStatusMu.RLock()
	defer c.uiStatusMu.RUnlock()
	return c.remoteAddr
}

func (c *Client) setRemoteAddr(addr string) {
	c.uiStatusMu.Lock()
	c.remoteAddr = addr
	c.uiStatusMu.Unlock()
}

// serverError wraps a rejection message sent by the tunnel server (e.g.
// "listen tcp :22: bind: address already in use"). It is distinguished from
// a transient network error so the reconnect loop can surface it clearly.
type serverError struct{ msg string }

func (e *serverError) Error() string { return "server error: " + e.msg }

func addUIReq(tunnel, method, path string, status int, dur time.Duration) {
	uiMu.Lock()
	defer uiMu.Unlock()
	uiReqs = append(uiReqs, uiRequest{tunnel, method, path, status, dur})
	if len(uiReqs) > 50 {
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

func RunClient(cfg *ClientConfig) {
	// Set up log file output (shared across all tunnels).
	if f, err := os.OpenFile("gotunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		log.SetOutput(f)
	} else {
		fmt.Fprintf(os.Stderr, "warning: cannot open gotunnel.log: %v — logging disabled\n", err)
		log.SetOutput(io.Discard)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Graceful shutdown on SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	serverAddr := normalizeServerAddr(cfg.Server)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify,
		MinVersion:         tls.VersionTLS13,
	}
	singleTunnel := len(cfg.Tunnels) == 1

	// ── Startup banner ───────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  \x1b[1;36mgotunnel\x1b[0m client\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Server", serverAddr)
	fmt.Fprintf(os.Stderr, "  %-14s %d\n", "Tunnels", len(cfg.Tunnels))
	fmt.Fprintln(os.Stderr)

	// Build all client structs first so the IPC server (started below,
	// unconditionally) can reference them when the TUI polls for state.
	var wg sync.WaitGroup
	clients := make([]*Client, 0, len(cfg.Tunnels))

	for idx, t := range cfg.Tunnels {
		t := t // capture loop variable

		tunnelType := strings.ToLower(t.Type)
		if tunnelType == "" {
			tunnelType = "http"
		}

		remoteVal := t.Remote
		if tunnelType == "http" && t.Subdomain != "" {
			remoteVal = t.Subdomain
		}
		if tunnelType == "tcp" && t.Remote == "" && t.Subdomain != "" {
			// No explicit remote port — derive it from the target address so
			// the server opens the same port number locally.
			// e.g. target: "localhost:22", subdomain: "ssh"
			// → server listens on :22, exposed as ssh.example.com:22
			normTarget := normalizeTargetAddr(t.Target)
			_, derivedPort, pErr := net.SplitHostPort(targetHost(normTarget))
			if pErr == nil && derivedPort != "" {
				remoteVal = ":" + derivedPort
			}
			// If we cannot parse a port, remoteVal stays "" and the server
			// will return an error — which is the right thing to do.
		}

		name := t.Name
		if name == "" {
			name = fmt.Sprintf("tunnel-%d", idx+1)
		}

		c := &Client{
			name:       name,
			serverAddr: serverAddr,
			token:      cfg.Token,
			tunnelType: tunnelType,
			remoteAddr: remoteVal,
			subdomain:  t.Subdomain,
			targetAddr: normalizeTargetAddr(t.Target),
			noTLS:      cfg.NoTLS,
			httpClient: &http.Client{
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					MaxIdleConns:          200,
					MaxIdleConnsPerHost:   50,
					IdleConnTimeout:       90 * time.Second,
					ResponseHeaderTimeout: 10 * time.Minute,
				},
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
			tlsConfig: tlsCfg,
			uiStatus:  "connecting...",
			ctx:       ctx,
			cancel:    cancel,
		}

		if singleTunnel {
			// Single-tunnel mode: full banner.
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Type", tunnelType)
			if tunnelType == "tcp" {
				if t.Subdomain != "" {
					fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Subdomain", t.Subdomain)
				}
				remoteDisplay := remoteVal
				if remoteDisplay == "" {
					remoteDisplay = "(derived from target)"
				}
				fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Remote Port", remoteDisplay)
			}
			if tunnelType == "http" && t.Subdomain != "" {
				fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Subdomain", t.Subdomain)
			}
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Forwarding", t.Target)
			if cfg.SkipTLSVerify {
				fmt.Fprintf(os.Stderr, "  %-14s disabled (skipTLSVerify: true)\n", "TLS Verify")
			}
			fmt.Fprintln(os.Stderr)
		} else {
			// Multi-tunnel mode: compact per-tunnel summary line.
			fmt.Fprintf(os.Stderr, "  [%s] %s → %s\n", name, tunnelType, t.Target)
			if tunnelType == "tcp" {
				if t.Subdomain != "" {
					fmt.Fprintf(os.Stderr, "         subdomain: %s\n", t.Subdomain)
				}
				fmt.Fprintf(os.Stderr, "         remote: %s\n", remoteVal)
			}
			if tunnelType == "http" && t.Subdomain != "" {
				fmt.Fprintf(os.Stderr, "         subdomain: %s\n", t.Subdomain)
			}
		}

		clients = append(clients, c)
	}

	// ── IPC server — always start, regardless of tunnel count ────────────────
	// startMultiIPC aggregates state from every client so the TUI can show
	// all tunnels at once.  It must be called before workers launch so the
	// parent process finds the port open within its 2-second attach window.
	if len(clients) > 0 {
		startMultiIPC(clients)
	}

	// ── Launch workers ────────────────────────────────────────────────────────
	for _, c := range clients {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.run()
		}()
	}

	wg.Wait()
}

func (c *Client) run() {
	backoff := time.Second
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.setStatus("connecting")
		err := c.connectAndServe()
		if err != nil {
			// Permanent server-side rejections (port in use, not allowed, bad
			// token after the challenge, etc.) get a longer backoff and a
			// distinct status label so the user can see what went wrong.
			var srvErr *serverError
			if errors.As(err, &srvErr) {
				c.setStatus("⚠ " + srvErr.Error())
				log.Printf("[%s] %v", c.name, srvErr)
				// Jump straight to the max backoff — no point hammering the
				// server for a configuration problem.
				backoff = 30 * time.Second
			} else {
				// Apply jitter: ±25% of current backoff.
				jitter := time.Duration(mrand.Int63n(int64(backoff/2+1))) - backoff/4
				backoff += jitter
				if backoff < 0 {
					backoff = 0
				}
			}
			wait := backoff
			c.setStatus(fmt.Sprintf("⚠ %v — retrying in %v", err, wait.Round(time.Millisecond)))
			select {
			case <-time.After(wait):
			case <-c.ctx.Done():
				return
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		} else {
			backoff = time.Second
		}
	}
}

func (c *Client) connectAndServe() error {
	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if c.noTLS {
		conn, err = dialer.DialContext(c.ctx, "tcp", c.serverAddr)
	} else {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: c.tlsConfig}
		conn, err = tlsDialer.DialContext(c.ctx, "tcp", c.serverAddr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	// connCtx is cancelled when connectAndServe returns (normal or error), so
	// the close-on-shutdown goroutine below exits promptly instead of leaking
	// until the whole program shuts down.
	connCtx, connCancel := context.WithCancel(c.ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	reader := bufio.NewReaderSize(conn, 64*1024)

	// Set a handshake deadline matching the server's 15 s auth timeout.
	// This ensures a hung or slow server cannot hold a worker goroutine
	// indefinitely during the upgrade → challenge → auth sequence.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

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

	remote := c.getRemoteAddr()
	if remote == "" {
		remote = "-"
	}
	sub := c.subdomain
	if sub == "" {
		sub = "-"
	}
	fmt.Fprintf(conn, "AUTH %s %s %s %s\n", clientHmac, c.tunnelType, remote, sub)

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "OK" {
		// Strip the "ERROR " prefix the server always prepends, then wrap
		// as a serverError so run() can surface it clearly in the TUI.
		msg := strings.TrimPrefix(line, "ERROR ")
		return &serverError{msg: msg}
	}
	if c.tunnelType == "tcp" && len(fields) > 1 {
		c.setRemoteAddr(fields[1])
	}

	// Auth succeeded — clear the deadline so the data path is unbounded.
	conn.SetDeadline(time.Time{})

	c.setStatus("online")

	// Wrap conn so that mux.Server drains any bytes already buffered in reader
	// before falling back to the raw conn — identical to the server-side fix.
	session, err := mux.Server(&bufferedConn{Conn: conn, r: reader}, mux.DefaultConfig())
	if err != nil {
		return err
	}
	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return err
		}
		go c.handleStream(stream)
	}
}

func (c *Client) handleStream(stream net.Conn) {
	c.uiStreams.Add(1)
	defer c.uiStreams.Add(-1)
	defer stream.Close()

	reader := bufio.NewReader(stream)

	if c.tunnelType == "tcp" {
		stream.SetReadDeadline(time.Now().Add(10 * time.Second))
		peek, err := reader.Peek(6)
		stream.SetReadDeadline(time.Time{})
		if err == nil && string(peek) == "START\n" {
			if err := c.handleTCPWorker(0, stream, reader); err != nil {
				log.Printf("[stream] tcp worker error: %v", err)
			}
			return
		}
		// If not START, fall through to HTTP handling.
	}

	// Brief deadline on the initial request read so a stuck stream doesn't
	// hold a goroutine indefinitely. Cleared before any I/O proxy begins.
	stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Time{}) // clear before proxying

	if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
		if err := c.handleWebSocket(0, stream, reader, req); err != nil {
			log.Printf("[stream] ws error: %v", err)
		}
		return
	}

	start := time.Now()
	resp, proxyErr := c.forwardToTarget(req)

	if proxyErr != nil {
		log.Printf("[stream] forward error (not exposed to client): %v", proxyErr)
		writeErrorResponse(stream, 502, "Bad Gateway")
		return
	}

	if err := resp.Write(stream); err != nil {
		resp.Body.Close()
		return
	}
	resp.Body.Close()

	addUIReq(c.name, req.Method, req.URL.RequestURI(), resp.StatusCode, time.Since(start))
}

// targetHost returns the host:port of the target address, stripping any scheme.
func targetHost(addr string) string {
	if h := strings.TrimPrefix(addr, "https://"); h != addr {
		return h
	}
	if h := strings.TrimPrefix(addr, "http://"); h != addr {
		return h
	}
	return addr
}

func (c *Client) handleTCPWorker(id int, tunnelConn net.Conn, tunnelReader *bufio.Reader) error {
	// Consume the "START\n" that handleStream already confirmed via Peek.
	tunnelConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := tunnelReader.ReadString('\n')
	tunnelConn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("read tcp start: %w", err)
	}
	if strings.TrimSpace(line) != "START" {
		return fmt.Errorf("unexpected tcp command: %s", strings.TrimSpace(line))
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	targetConn, err := dialer.DialContext(c.ctx, "tcp", targetHost(c.targetAddr))
	if err != nil {
		log.Printf("[w%d] tcp dial target failed: %v", id, err)
		fmt.Fprintf(tunnelConn, "ERR %s\n", sanitizeControlLine(err.Error()))
		return fmt.Errorf("dial target for tcp: %w", err)
	}
	defer targetConn.Close()

	// Enable TCP keepalive on the local target connection so that long-lived
	// idle tunnels (SSH, DB, etc.) are not silently killed by NAT routers.
	if tc, ok := targetConn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}

	log.Printf("[w%d] tcp session started: %s", id, c.targetAddr)
	if _, err := fmt.Fprintf(tunnelConn, "OK\n"); err != nil {
		return fmt.Errorf("ack tcp target: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		relayTCP(dst, src)
	}
	go pipe(targetConn, tunnelReader)
	go pipe(tunnelConn, targetConn)
	wg.Wait()

	log.Printf("[w%d] tcp session closed", id)
	return nil
}

func (c *Client) handleWebSocket(id int, tunnelConn net.Conn, tunnelReader *bufio.Reader, req *http.Request) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	targetConn, err := dialer.DialContext(c.ctx, "tcp", targetHost(c.targetAddr))
	if err != nil {
		writeErrorResponse(tunnelConn, 502, err.Error())
		return fmt.Errorf("dial target for ws: %w", err)
	}
	defer targetConn.Close()

	req.URL.Scheme = "http"
	req.URL.Host = targetHost(c.targetAddr)
	req.Host = req.URL.Host
	req.RequestURI = ""

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
		bp := copyBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, *bp)
		copyBufPool.Put(bp)
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

	// Propagate the client's lifecycle context so that a shutdown or
	// disconnection cancels the upstream request immediately instead of
	// waiting up to ResponseHeaderTimeout (10 min).
	return c.httpClient.Do(req.WithContext(c.ctx))
}

// writeErrorResponse writes a minimal HTTP/1.1 error response to w.
func writeErrorResponse(w io.Writer, code int, msg string) error {
	bodyMsg := msg + "\n"
	resp := &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(bodyMsg)),
		ContentLength: int64(len(bodyMsg)),
	}
	return resp.Write(w)
}

// ── IPC Dashboard ─────────────────────────────────────────────────────────────

// startMultiIPC starts the IPC HTTP server on port 41401, exposing the
// aggregate state of all tunnels so the TUI can display them together.
// This is always called, regardless of tunnel count — without it the parent
// process (main.go) times out waiting for the daemon to become ready.
func startMultiIPC(clients []*Client) {
	if _, err := ipc.StartIPCServer(41401, func() interface{} {
		tunnels := make([]ipc.TunnelState, len(clients))
		for i, c := range clients {
			c.uiStatusMu.RLock()
			status := c.uiStatus
			remoteAddr := c.remoteAddr
			c.uiStatusMu.RUnlock()
			tunnels[i] = ipc.TunnelState{
				Name:       c.name,
				Status:     status,
				ServerAddr: c.serverAddr,
				RemoteAddr: remoteAddr,
				TargetAddr: c.targetAddr,
				TunnelType: c.tunnelType,
				Workers:    int(c.uiStreams.Load()),
			}
		}

		uiMu.Lock()
		reqs := make([]ipc.UIRequest, len(uiReqs))
		for i, r := range uiReqs {
			reqs[i] = ipc.UIRequest{
				Tunnel: r.tunnel,
				Method: r.method,
				Path:   r.path,
				Status: r.status,
				Dur:    r.dur.Milliseconds(),
			}
		}
		uiMu.Unlock()

		return ipc.MultiClientState{
			Tunnels:  tunnels,
			Requests: reqs,
		}
	}); err != nil {
		log.Printf("IPC server failed to start: %v", err)
	}
}
