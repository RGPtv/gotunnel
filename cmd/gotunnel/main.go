package main

import (
	"fmt"
	"os"

	"github.com/RGPtv/gotunnel/internal/tunnel"
)

const usage = `gotunnel — Expose any local service securely over a reverse tunnel

How it works:
  The server runs on your public VPS and accepts two kinds of connections:
    • HTTP clients  (port -http) — e.g. your apps, browsers, curl
    • Tunnel client (port -tun)  — your local machine running the target service

  Traffic flow:  HTTP client → VPS server → tunnel → local service

Commands:
  server   Run the tunnel server on your VPS / public host
  client   Run the tunnel client on your local machine
  start    Run a named tunnel from config.json
  genkey   Generate a random 256-bit auth token

Run 'gotunnel <command> -help' for all flags.

Quick start:
  # 1. On your VPS (token is auto-generated, shown in console + dashboard):
  gotunnel server -http :8080 -tun :2222

  # 2. Copy the token from the dashboard at http://localhost:4040
  #    or from the server console output.

  # 3. On your local machine (where your service is running):
  gotunnel client -server vps.example.com:2222 -token <TOKEN> -target localhost:3000 -k

  # 4. Use your service through the tunnel:
  curl http://vps.example.com:8080/

  # Or provide your own token:
  gotunnel server -token $TOKEN -http :8080 -tun :2222

Examples:
  # Tunnel Ollama
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:11434 -k

  # Tunnel a web app
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000 -k

  # Tunnel any HTTP service
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:5000 -k

  # Tunnel SSH over raw TCP
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:22 -type tcp -remote :22222 -k

Behind a TLS-terminating proxy (GitHub Codespaces, ngrok, Cloudflare Tunnel):
  # Server (proxy already handles TLS — no double-wrap):
  gotunnel server -token $TOKEN -http :8080 -tun :4444 -notls

  # Client (proxy presents a real cert — no -k needed):
  gotunnel client -server https://your-codespace-4444.app.github.dev/ -token $TOKEN -target localhost:11434

Optional: secure HTTP access with an API key
  Client: gotunnel client -server vps.example.com:2222 -token $TOKEN -apikey $APIKEY -target localhost:3000 -k
  User:   curl -H "Authorization: Bearer $APIKEY" http://vps.example.com:8080/

Dashboard:
  The server starts a web dashboard at http://localhost:4040 by default.
  It shows your auth token, active connections, and a live traffic inspector.
  Change the address with -inspect :4040 or disable with -inspect "".

Notes:
  • The tunnel uses TLS (auto-generated self-signed cert unless -cert/-key given).
  • If -token is omitted, a random token is generated and displayed on startup.
  • Streaming responses (SSE, chunked transfer) work end-to-end.
  • Use -workers on the client to allow more concurrent requests (default 10).
  • Any HTTP service works: web apps, APIs, notebooks, Ollama, etc.
  • For raw TCP protocols (SSH, MySQL, Redis, etc.), use -type tcp and specify a -remote port.
`


func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		tunnel.RunServer(os.Args[2:])
	case "client":
		tunnel.RunClient(os.Args[2:])
	case "start":
		tunnel.RunStart(os.Args[2:])
	case "genkey":
		tunnel.RunGenKey()
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}
