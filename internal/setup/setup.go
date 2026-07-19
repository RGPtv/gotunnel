// Package setup provides a first-time web-based configuration wizard that runs
// when no config.yaml is present.  It starts a temporary HTTP server, serves
// the embedded wizard UI, validates the submitted settings, hashes the admin
// password with bcrypt, writes config.yaml, and then re-execs (Unix) or
// restarts (Windows) the current process so the normal server can start.
package setup

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed ui
var staticFiles embed.FS

const (
	setupPort    = 3000
	bcryptCost   = 12
	maxBodyBytes = 64 * 1024 // 64 KB guard on the setup POST body
)

// setupRequest is the JSON body sent by the wizard when the user clicks Finish.
type setupRequest struct {
	// Step 1 — Administrator account
	Username string `json:"username"`
	Password string `json:"password"`

	// Step 2 — Domain & network
	Domain   string `json:"domain"`
	HTTPAddr string `json:"http_addr"` // e.g. ":80"  (empty → default ":80")
	TunAddr  string `json:"tun_addr"`  // e.g. ":2222" (empty → default ":2222")

	// Step 2 — SSL / TLS
	EnableHTTPS bool   `json:"enable_https"` // serve public traffic over HTTPS on port 443
	CertFile    string `json:"cert_file"`    // required when EnableHTTPS
	KeyFile     string `json:"key_file"`     // required when EnableHTTPS
	Wildcard    bool   `json:"wildcard"`     // cert is a wildcard cert (SNI subdomain routing)
	NoTLS       bool   `json:"no_tls"`       // plain TCP tunnel (behind a TLS-terminating proxy)

	// Step 2 — Dashboard
	DashboardPort int `json:"dashboard_port"` // inspect port, e.g. 4040

	// Step 2 — Auth token
	TokenMode string `json:"token_mode"` // "auto" or "custom"
	Token     string `json:"token"`      // used when TokenMode == "custom"

	// Step 2 — Advanced
	PoolSize int `json:"pool_size"` // max idle connections per pool
}

// RunSetupWizard starts the setup HTTP server and blocks until the user
// completes the wizard and config.yaml has been written.  It then restarts
// the current process so the normal startup path runs with the new config.
func RunSetupWizard() {
	// The wizard writes credentials and configuration, so it must never be
	// reachable from the network without authentication.
	addr := fmt.Sprintf("127.0.0.1:%d", setupPort)

	mux := http.NewServeMux()
	done := make(chan struct{})
	var completeMu sync.Mutex

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			serveFile(w, "ui/index.html", "text/html; charset=utf-8")
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/setup/styles.css", func(w http.ResponseWriter, r *http.Request) {
		serveFile(w, "ui/styles.css", "text/css; charset=utf-8")
	})
	mux.HandleFunc("/setup/script.js", func(w http.ResponseWriter, r *http.Request) {
		serveFile(w, "ui/script.js", "application/javascript; charset=utf-8")
	})

	mux.HandleFunc("/api/setup/complete", func(w http.ResponseWriter, r *http.Request) {
		handleComplete(w, r, done, &completeMu)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Check that the port is available before printing the URL.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("setup: cannot listen on %s: %v\n(another process may be using port %d)", addr, err, setupPort)
	}

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("  GoTunnel — First-time Setup")
	log.Printf("  No config.yaml found. Open the setup wizard in your browser:")
	log.Printf("")
	log.Printf("      http://localhost:%d", setupPort)
	log.Printf("")
	log.Printf("  Complete the wizard to generate config.yaml and start the server.")
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("setup server error: %v", err)
		}
	}()

	// Block until the wizard signals completion.
	<-done

	// Gracefully stop the setup server before restarting.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)

	log.Println("setup: config.yaml written — restarting GoTunnel…")
	restartProcess()
}

// handleComplete validates the wizard payload, writes config.yaml, and signals done.
func handleComplete(w http.ResponseWriter, r *http.Request, done chan struct{}, completeMu *sync.Mutex) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Serialize completion so concurrent submissions cannot race the config
	// write or close(done) twice.
	completeMu.Lock()
	defer completeMu.Unlock()
	select {
	case <-done:
		http.Error(w, "setup already completed", http.StatusConflict)
		return
	default:
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req setupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// ── Server-side validation ────────────────────────────────────────────────
	if err := validateSetupRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// ── Generate auth token once (auto-mode) ─────────────────────────────────
	// Writing the concrete token value (not "auto") ensures the same secret is
	// reused across server restarts — clients never need to re-authenticate.
	if req.TokenMode == "auto" {
		tb := make([]byte, 32)
		if _, err := rand.Read(tb); err != nil {
			http.Error(w, "failed to generate token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		req.Token = hex.EncodeToString(tb)
	}

	// ── Hash the password ─────────────────────────────────────────────────────
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		http.Error(w, "failed to hash password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Build redirect URL ────────────────────────────────────────────────────
	var redirectURL string
	if req.Wildcard {
		// Wildcard: dashboard is on port 443 alongside the HTTPS proxy.
		redirectURL = "https://" + req.Domain + "/login"
	} else {
		redirectURL = fmt.Sprintf("http://localhost:%d/login", req.DashboardPort)
	}

	// ── Generate config.yaml ──────────────────────────────────────────────────
	yaml, err := buildConfigYAML(&req, string(hash))
	if err != nil {
		http.Error(w, "failed to build config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile("config.yaml", []byte(yaml), 0600); err != nil {
		http.Error(w, "failed to write config.yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("setup: config.yaml written (user=%s domain=%s https=%v wildcard=%v noTLS=%v token=%s pool=%d)",
		req.Username, req.Domain, req.EnableHTTPS, req.Wildcard, req.NoTLS, req.TokenMode, req.PoolSize)

	// ── Respond before restarting ─────────────────────────────────────────────
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":       "ok",
		"redirect_url": redirectURL,
	})

	// Shutdown is graceful, so the completed response remains deliverable
	// while RunSetupWizard stops accepting new configuration submissions.
	close(done)
}

// validateSetupRequest returns a descriptive error if any required field is missing or invalid.
// It also normalises optional fields (empty addresses → defaults, token mode).
func validateSetupRequest(req *setupRequest) error {
	req.Username = strings.TrimSpace(req.Username)
	req.Domain = strings.TrimSpace(req.Domain)
	req.CertFile = strings.TrimSpace(req.CertFile)
	req.KeyFile = strings.TrimSpace(req.KeyFile)
	req.Token = strings.TrimSpace(req.Token)
	req.HTTPAddr = strings.TrimSpace(req.HTTPAddr)
	req.TunAddr = strings.TrimSpace(req.TunAddr)

	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if req.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if req.EnableHTTPS && req.NoTLS {
		return fmt.Errorf("enable_https and no_tls are mutually exclusive")
	}
	if req.Wildcard && !req.EnableHTTPS {
		return fmt.Errorf("wildcard requires HTTPS to be enabled")
	}
	if req.EnableHTTPS {
		if req.CertFile == "" {
			return fmt.Errorf("cert_file is required when HTTPS is enabled")
		}
		if req.KeyFile == "" {
			return fmt.Errorf("key_file is required when HTTPS is enabled")
		}
	}
	if req.Wildcard {
		// Wildcard: dashboard runs on port 443 alongside the HTTPS proxy.
		// No separate dashboard_port is needed.
		req.DashboardPort = 443
	} else if req.DashboardPort < 1 || req.DashboardPort > 65535 {
		return fmt.Errorf("dashboard_port must be between 1 and 65535")
	}
	if req.TokenMode == "custom" && req.Token == "" {
		return fmt.Errorf("token is required when token mode is custom")
	}

	// Apply defaults for optional fields.
	if req.HTTPAddr == "" {
		req.HTTPAddr = ":80"
	}
	if req.TunAddr == "" {
		req.TunAddr = ":2222"
	}
	if req.TokenMode != "custom" {
		// Mark as auto; the actual hex value is generated in handleComplete.
		req.TokenMode = "auto"
	}
	if req.PoolSize < 1 {
		req.PoolSize = 512
	}
	return nil
}

// buildConfigYAML constructs the config.yaml content from the wizard inputs.
func buildConfigYAML(req *setupRequest, passwordHash string) (string, error) {
	var b strings.Builder

	b.WriteString("# gotunnel configuration file\n")
	b.WriteString("# Generated by the setup wizard on " + time.Now().Format(time.RFC3339) + "\n")
	b.WriteString("#\n")
	b.WriteString("# Run with: ./gotunnel\n")
	b.WriteString("# -------------------------------------------------------------------\n\n")

	b.WriteString("serverConfig:\n")

	// HTTP proxy address
	b.WriteString(fmt.Sprintf("  http:        %q\n", req.HTTPAddr))

	// HTTPS — independent of wildcard; wildcard is just a cert-type flag
	if req.EnableHTTPS {
		b.WriteString("  https:       \":443\"\n")
		b.WriteString(fmt.Sprintf("  cert:        %q\n", req.CertFile))
		b.WriteString(fmt.Sprintf("  key:         %q\n", req.KeyFile))
	}

	// Wildcard flag (SNI-based subdomain routing via GetCertificate)
	if req.Wildcard {
		b.WriteString("  wildcard:    true\n")
	} else {
		b.WriteString("  wildcard:    false\n")
	}

	// Tunnel listener
	b.WriteString(fmt.Sprintf("  tun:         %q\n", req.TunAddr))

	// noTLS — plain TCP tunnel (behind a TLS-terminating proxy)
	if req.NoTLS {
		b.WriteString("  noTLS:       true\n")
	}

	// Auth token
	b.WriteString(fmt.Sprintf("  token:       %q\n", req.Token))

	// Domain
	b.WriteString(fmt.Sprintf("  domain:      %q\n", req.Domain))

	// Dashboard (inspect)
	if req.Wildcard {
		// Wildcard: dashboard is on the same HTTPS port (443); no separate dashboard_port.
		b.WriteString("  inspect:     \":443\"\n")
	} else {
		inspectAddr := fmt.Sprintf(":%d", req.DashboardPort)
		b.WriteString(fmt.Sprintf("  inspect:     %q\n", inspectAddr))
		b.WriteString(fmt.Sprintf("  dashboard_port: %d\n", req.DashboardPort))
	}

	// Admin credentials (password is bcrypt-hashed)
	b.WriteString(fmt.Sprintf("  inspectUser: %q\n", req.Username))
	b.WriteString(fmt.Sprintf("  inspectPass: %q\n", passwordHash))

	// Connection pool
	b.WriteString(fmt.Sprintf("  poolSize:    %d\n", req.PoolSize))

	return b.String(), nil
}

// serveFile reads a file from the embedded FS and writes it with the given content type.
func serveFile(w http.ResponseWriter, path, contentType string) {
	data, err := staticFiles.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// restartProcess re-executes the current binary with the same arguments so the
// normal startup path runs with the newly created config.yaml.
// On Unix, syscall.Exec replaces the current process image.
// On Windows, it launches a new process and exits.
func restartProcess() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("setup: could not determine executable path: %v", err)
	}

	args := os.Args

	// Try syscall.Exec first (replaces process on Unix; will error on Windows).
	err = syscall.Exec(exe, args, os.Environ())
	if err != nil {
		// Fallback for Windows: launch a new process and exit the current one.
		cmd := exec.Command(exe, args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if startErr := cmd.Start(); startErr != nil {
			log.Fatalf("setup: failed to restart: %v", startErr)
		}
		os.Exit(0)
	}
}
