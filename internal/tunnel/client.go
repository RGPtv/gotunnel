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

func RunClient(cfg *ClientConfig) {
	// Set up log file output (shared across all tunnels).
	if f, err := os.OpenFile("gotunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
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
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
	singleTunnel := len(cfg.Tunnels) == 1

	// ── Startup banner ───────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  \x1b[1;36mgotunnel\x1b[0m client\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Server", serverAddr)
	fmt.Fprintf(os.Stderr, "  %-14s %d\n", "Tunnels", len(cfg.Tunnels))
	fmt.Fprintln(os.Stderr)

	var wg sync.WaitGroup

	for idx, t := range cfg.Tunnels {
		t := t // capture loop variable

		tunnelType := strings.ToLower(t.Type)
		if tunnelType == "" {
			tunnelType = "http"
		}
		workers := t.Workers
		if workers <= 0 {
			workers = 10
		}

		remoteVal := t.Remote
		if tunnelType == "http" && t.Subdomain != "" {
			remoteVal = t.Subdomain
		}

		c := &Client{
			serverAddr: serverAddr,
			token:      cfg.Token,
			tunnelType: tunnelType,
			remoteAddr: remoteVal,
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
			// Single-tunnel mode: full banner + interactive TUI.
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Type", tunnelType)
			if tunnelType == "tcp" {
				fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Remote Port", t.Remote)
			}
			if tunnelType == "http" && t.Subdomain != "" {
				fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Subdomain", t.Subdomain)
			}
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Forwarding", t.Target)
			fmt.Fprintf(os.Stderr, "  %-14s %d\n", "Workers", workers)
			if cfg.SkipTLSVerify {
				fmt.Fprintf(os.Stderr, "  %-14s disabled (skipTLSVerify: true)\n", "TLS Verify")
			}
			fmt.Fprintln(os.Stderr)
			c.startIPC()
		} else {
			// Multi-tunnel mode: compact per-tunnel summary line.
			label := t.Name
			if label == "" {
				label = fmt.Sprintf("tunnel-%d", idx+1)
			}
			fmt.Fprintf(os.Stderr, "  [%s] %s → %s  (%d workers)\n", label, tunnelType, t.Target, workers)
			if tunnelType == "tcp" {
				fmt.Fprintf(os.Stderr, "         remote: %s\n", t.Remote)
			}
			if tunnelType == "http" && t.Subdomain != "" {
				fmt.Fprintf(os.Stderr, "         subdomain: %s\n", t.Subdomain)
			}
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				c.runWorker(id)
			}(i + 1)
		}
	}

	wg.Wait()
}

// runWorker dials the tunnel server and processes requests until an
// unrecoverable error occurs, then reconnects after a brief pause.
// connectAndServe returns (nil, true) for a normal data-path exit and
// (nil, false) for a hijacked session — hijacked workers must still
// back off so they don't hammer the server with rapid redials.
func (c *Client) runWorker(id int) {
	backoff := time.Second
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.setStatus("reconnecting")
		err, served := c.connectAndServe(id)
		if err != nil {
			c.setStatus(fmt.Sprintf("connecting... (retrying in %v)", backoff))
			select {
			case <-time.After(backoff):
			case <-c.ctx.Done():
				return
			}
			jitter := time.Duration(mrand.Int63n(int64(backoff/2 + 1)))
			backoff = backoff*2 + jitter
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
		} else if served {
			// Completed a full HTTP serving cycle cleanly — reset backoff.
			backoff = time.Second
		} else {
			// Hijacked (TCP/WS) or clean disconnect — brief pause before redial
			// to avoid hammering the server when the remote target disconnects.
			select {
			case <-time.After(time.Second):
			case <-c.ctx.Done():
				return
			}
			backoff = time.Second
		}
	}
}

// connectAndServe dials the server, authenticates, and processes requests.
// Returns (err, served):
//   - err != nil  → connection or protocol failure; caller should back off
//   - err == nil, served == true  → served at least one HTTP request cleanly
//   - err == nil, served == false → hijacked (TCP/WS) or clean disconnect
func (c *Client) connectAndServe(id int) (error, bool) {
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
		return err, false
	}
	hijacked := false
	watchDone := make(chan struct{})
	defer func() {
		if watchDone != nil {
			close(watchDone)
		}
		if !hijacked {
			conn.Close()
		}
	}()
	go func() {
		select {
		case <-c.ctx.Done():
			conn.Close()
		case <-watchDone:
		}
	}()

	reader := bufio.NewReaderSize(conn, 64*1024)

	// Set a handshake deadline matching the server's 15 s auth timeout.
	// This ensures a hung or slow server cannot hold a worker goroutine
	// indefinitely during the upgrade → challenge → auth sequence.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	wsRaw := make([]byte, 16)
	if _, err := rand.Read(wsRaw); err != nil {
		return fmt.Errorf("ws key: %w", err), false
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
		return err, false
	}
	upgradeResp.Body.Close()
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("upgrade rejected: %v", upgradeResp.Status), false
	}

	chalLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read challenge: %w", err), false
	}
	chalLine = strings.TrimSpace(chalLine)
	if !strings.HasPrefix(chalLine, "CHALLENGE ") {
		return fmt.Errorf("expected CHALLENGE, got %q", chalLine), false
	}
	nonceHex := strings.TrimPrefix(chalLine, "CHALLENGE ")

	mac := hmac.New(sha256.New, []byte(c.token))
	mac.Write([]byte(nonceHex))
	clientHmac := hex.EncodeToString(mac.Sum(nil))

	remote := c.remoteAddr
	if remote == "" {
		remote = "-"
	}
	fmt.Fprintf(conn, "AUTH %s %s %s\n", clientHmac, c.tunnelType, remote)

	line, err := reader.ReadString('\n')
	if err != nil {
		return err, false
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		return fmt.Errorf("auth rejected: %s", line), false
	}

	// Auth succeeded — clear the deadline so the data path is unbounded.
	conn.SetDeadline(time.Time{})

	c.setStatus("online")
	c.uiWorkers.Add(1)
	defer c.uiWorkers.Add(-1)

	if c.tunnelType == "tcp" {
		hijacked = true
		// Transfer ownership of watchDone to the goroutine so the context
		// watcher stays active for the full duration of the TCP session.
		wd := watchDone
		watchDone = nil // prevent the deferred close from firing
		go func() {
			defer close(wd)
			c.handleTCPWorker(id, conn, reader)
			conn.Close()
		}()
		return nil, false // hijacked
	}

	served := false
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if served {
				return nil, true // clean disconnect after serving at least one request
			}
			return err, false
		}

		if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			hijacked = true
			wd := watchDone
			watchDone = nil // prevent deferred close; keep ctx watcher alive for WS session
			go func() {
				defer close(wd)
				c.handleWebSocket(id, conn, reader, req)
				conn.Close()
			}()
			return nil, false // hijacked
		}

		start := time.Now()
		resp, proxyErr := c.forwardToTarget(req)
		if proxyErr != nil {
			// Drain the request body fully before sending the error response.
			// forwardToTarget may have failed before consuming the body; if we
			// continue without draining, unconsumed body bytes remain at the
			// head of `reader` and corrupt the next http.ReadRequest parse.
			if req.Body != nil {
				io.Copy(io.Discard, req.Body)
				req.Body.Close()
			}
			if werr := writeErrorResponse(conn, 502, proxyErr.Error()); werr != nil {
				return werr, served // tunnel conn is broken; let worker reconnect
			}
			continue
		}

		if err := resp.Write(conn); err != nil {
			resp.Body.Close()
			return err, served
		}
		resp.Body.Close()

		served = true
		addUIReq(req.Method, req.URL.RequestURI(), resp.StatusCode, time.Since(start))
	}
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
	line, err := tunnelReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read tcp start: %w", err)
	}
	if strings.TrimSpace(line) != "START" {
		return fmt.Errorf("unexpected command: %s", line)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	targetConn, err := dialer.DialContext(c.ctx, "tcp", targetHost(c.targetAddr))
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

	return c.httpClient.Do(req)
}

// writeErrorResponse writes a minimal HTTP/1.1 error response to w.
func writeErrorResponse(w io.Writer, code int, msg string) error {
	resp := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(msg + "\n")),
	}
	return resp.Write(w)
}

// ── IPC Dashboard ─────────────────────────────────────────────────────────────

func (c *Client) startIPC() {
	if _, err := ipc.StartIPCServer(41401, func() interface{} {
		c.uiStatusMu.RLock()
		uiStatus := c.uiStatus
		c.uiStatusMu.RUnlock()

		uiMu.Lock()
		reqs := make([]ipc.UIRequest, len(uiReqs))
		for i, r := range uiReqs {
			reqs[i] = ipc.UIRequest{
				Method: r.method,
				Path:   r.path,
				Status: r.status,
				Dur:    r.dur.Milliseconds(),
			}
		}
		uiMu.Unlock()

		return ipc.ClientState{
			Status:     uiStatus,
			ServerAddr: c.serverAddr,
			RemoteAddr: c.remoteAddr,
			TargetAddr: c.targetAddr,
			TunnelType: c.tunnelType,
			Workers:    int(c.uiWorkers.Load()),
			Requests:   reqs,
		}
	}); err != nil {
		log.Printf("IPC server failed to start: %v", err)
	}
}
