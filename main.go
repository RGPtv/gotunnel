package main

import (
	"fmt"
	"os"
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
  genkey   Generate a random 256-bit auth token

Run 'gotunnel <command> -help' for all flags.

Quick start:
  # 1. Generate a token
  TOKEN=$(gotunnel genkey)

  # 2. On your VPS:
  gotunnel server -token $TOKEN -http :8080 -tun :2222

  # 3. On your local machine (where your service is running):
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000 -k

  # 4. Use your service through the tunnel:
  curl http://vps.example.com:8080/

Examples:
  # Tunnel Ollama
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:11434 -k

  # Tunnel a web app
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000 -k

  # Tunnel a Jupyter notebook
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:8888 -k

  # Tunnel any HTTP service
  gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:5000 -k

Behind a TLS-terminating proxy (GitHub Codespaces, ngrok, Cloudflare Tunnel):
  # Server (proxy already handles TLS — no double-wrap):
  gotunnel server -token $TOKEN -http :8080 -tun :4444 -notls

  # Client (proxy presents a real cert — no -k needed):
  gotunnel client -server https://your-codespace-4444.app.github.dev/ -token $TOKEN -target localhost:11434

Optional: secure HTTP access with an API key
  Server: gotunnel server -token $TOKEN -apikey $APIKEY ...
  Client: curl -H "Authorization: Bearer $APIKEY" http://vps.example.com:8080/

Notes:
  • The tunnel uses TLS (auto-generated self-signed cert unless -cert/-key given).
  • Streaming responses (SSE, chunked transfer) work end-to-end.
  • Use -workers on the client to allow more concurrent requests (default 5).
  • Any HTTP service works: web apps, APIs, notebooks, Ollama, etc.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "genkey":
		runGenKey()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}
