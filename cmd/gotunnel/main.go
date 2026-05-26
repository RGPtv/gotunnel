package main

import (
	"fmt"
	"os"

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
		default:
			fmt.Fprintf(os.Stderr, "gotunnel: unexpected argument %q\n\n", os.Args[1])
			fmt.Fprintf(os.Stderr, "gotunnel reads all configuration from config.yml or config.yaml.\n")
			fmt.Fprintf(os.Stderr, "Run 'gotunnel --help' for usage information.\n")
			os.Exit(1)
		}
	}

	cfg, err := tunnel.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.ServerConfig != nil {
		tunnel.RunServer(cfg.ServerConfig)
	} else {
		tunnel.RunClient(cfg.ClientConfig)
	}
}
