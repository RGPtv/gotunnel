package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// ServerState represents the live state of the tunnel server.
type ServerState struct {
	Token       string       `json:"token"`
	HTTPAddr    string       `json:"httpAddr"`
	HTTPSAddr   string       `json:"httpsAddr"`
	TunAddr     string       `json:"tunAddr"`
	InspectAddr string       `json:"inspectAddr"`
	DashUser    string       `json:"dashUser"`
	DashPass    string       `json:"dashPass"`
	ActiveConns int64        `json:"activeConns"`
	TotalReqs   int64        `json:"totalReqs"`
	Uptime      int64        `json:"uptime"` // in seconds
	Tunnels     []TunnelInfo `json:"tunnels"`
	Logs        []LogEntry   `json:"logs"`
}

type TunnelInfo struct {
	Endpoint    string `json:"endpoint"`
	Type        string `json:"type"`
	Connections int    `json:"connections"`
	ClientIP    string `json:"clientIP"`
	ProxyURL    string `json:"proxyURL"`
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   int       `json:"level"`
	Message string    `json:"message"`
}

// ClientState represents the live state of the tunnel client.
type ClientState struct {
	Status     string      `json:"status"`
	ServerAddr string      `json:"serverAddr"`
	RemoteAddr string      `json:"remoteAddr"`
	TargetAddr string      `json:"targetAddr"`
	TunnelType string      `json:"tunnelType"`
	Workers    int         `json:"workers"`
	Requests   []UIRequest `json:"requests"`
}

type UIRequest struct {
	Tunnel string `json:"tunnel"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Dur    int64  `json:"dur"` // in milliseconds
}

// TunnelState holds live state for a single tunnel in a multi-tunnel client.
type TunnelState struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ServerAddr string `json:"serverAddr"`
	RemoteAddr string `json:"remoteAddr"`
	TargetAddr string `json:"targetAddr"`
	TunnelType string `json:"tunnelType"`
	Workers    int    `json:"workers"`
}

// MultiClientState holds the aggregate live state of all tunnels plus the
// combined HTTP request log.  This is what the client daemon exposes on /state.
type MultiClientState struct {
	Tunnels  []TunnelState `json:"tunnels"`
	Requests []UIRequest   `json:"requests"`
}

// IPC Client to fetch state or send shutdown
type Client struct {
	client *http.Client
	url    string
}

func NewClient(port int) *Client {
	return &Client{
		client: &http.Client{Timeout: 2 * time.Second},
		url:    fmt.Sprintf("http://127.0.0.1:%d", port),
	}
}

func (c *Client) Ping() bool {
	resp, err := c.client.Get(c.url + "/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *Client) Shutdown() error {
	resp, err := c.client.Post(c.url+"/shutdown", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("shutdown failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) GetServerState() (ServerState, error) {
	var s ServerState
	resp, err := c.client.Get(c.url + "/state")
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&s)
	return s, err
}

func (c *Client) GetClientState() (ClientState, error) {
	var s ClientState
	resp, err := c.client.Get(c.url + "/state")
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&s)
	return s, err
}

func (c *Client) GetMultiClientState() (MultiClientState, error) {
	var s MultiClientState
	resp, err := c.client.Get(c.url + "/state")
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&s)
	return s, err
}

// StartIPCServer starts the IPC HTTP server in the background.
// getState is a function that returns either ServerState or ClientState.
func StartIPCServer(port int, getState func() interface{}) (net.Listener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(getState()); err != nil {
			fmt.Fprintf(os.Stderr, "ipc /state encode: %v\n", err)
		}
	})
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Flush before triggering shutdown so the client receives the 200.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			// Send SIGINT to our own process so registered signal handlers
			// and deferred cleanup run.  Falls back to os.Exit if the
			// signal cannot be sent (e.g. on some Windows configurations).
			p, err := os.FindProcess(os.Getpid())
			if err != nil {
				os.Exit(0)
			}
			if err := p.Signal(os.Interrupt); err != nil {
				os.Exit(0)
			}
		}()
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Only log unexpected errors; ErrServerClosed is normal on shutdown.
			fmt.Fprintf(os.Stderr, "ipc server: %v\n", err)
		}
	}()

	return ln, nil
}
