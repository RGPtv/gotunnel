package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/RGPtv/gotunnel/internal/ipc"
	"github.com/RGPtv/gotunnel/internal/setup"
	"github.com/RGPtv/gotunnel/internal/tui"
	"github.com/RGPtv/gotunnel/internal/tunnel"
)

const usage = `gotunnel — Expose any local service securely over a reverse tunnel

Configuration:
  gotunnel reads its configuration exclusively from a YAML file in the
  current working directory. No command-line flags are used.

  Searched in order:
    config.yml
    config.yaml

  The file must contain exactly one of:
    serverConfig:   — run as the tunnel server (on your VPS)
    clientConfig:   — run as the tunnel client (on your local machine)

Usage:
  ./gotunnel

Example server config (config.yaml):
  serverConfig:
    http:   ":8080"
    tun:    ":2222"
    token:  "your-secret-token"
    inspect: ":4040"

Example client config (config.yaml):
  clientConfig:
    server: "vps.example.com:2222"
    token:  "your-secret-token"
    tunnels:
      - name:   "web"
        target: "localhost:3000"
        type:   "http"
      - name:   "ssh"
        target: "localhost:22"
        type:   "tcp"
        remote: ":22222"

For full field reference, see README.md.
`

func main() {
	// Show help if explicitly requested.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			fmt.Print(usage)
			os.Exit(0)
		case "-daemon":
			// Handled later
		default:
			fmt.Fprintf(os.Stderr, "gotunnel: unexpected argument %q\n\n", os.Args[1])
			fmt.Fprintf(os.Stderr, "gotunnel reads all configuration from config.yml or config.yaml.\n")
			fmt.Fprintf(os.Stderr, "Run 'gotunnel --help' for usage information.\n")
			os.Exit(1)
		}
	}

	cfg, err := tunnel.LoadConfig()
	if err != nil {
		// If no config file exists at all, this is a first run — launch the
		// setup wizard instead of exiting with an error.
		if !tunnel.ConfigFileExists() {
			setup.RunSetupWizard()
			// RunSetupWizard() restarts the process after writing config.yaml,
			// so this line is only reached if restart itself failed.
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	isServer := cfg.ServerConfig != nil
	ipcPort := 41400
	if !isServer {
		ipcPort = 41401
	}

	isDaemon := false
	for _, arg := range os.Args {
		if arg == "-daemon" {
			isDaemon = true
			break
		}
	}

	if isDaemon {
		if isServer {
			tunnel.RunServer(cfg.ServerConfig)
		} else {
			tunnel.RunClient(cfg.ClientConfig)
		}
		return
	}

	// Try to attach
	ipcClient := ipc.NewClient(ipcPort)
	if !ipcClient.Ping() {
		// Start daemon
		cmd := exec.Command(os.Args[0], "-daemon")
		setDaemonAttr(cmd)
		err := cmd.Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to start daemon: %v\n", err)
			os.Exit(1)
		}

		// Wait for daemon to become ready
		ready := false
		for i := 0; i < 20; i++ {
			time.Sleep(100 * time.Millisecond)
			if ipcClient.Ping() {
				ready = true
				break
			}
		}
		if !ready {
			fmt.Fprintln(os.Stderr, "failed to attach to daemon")
			os.Exit(1)
		}
	}

	// Start UI
	if isServer {
		if err := tui.RunServerUI(ipcPort); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		if err := tui.RunClientUI(ipcPort); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
