# gotunnel

A lightweight, zero-dependency reverse tunnel written in pure Go. Securely expose any local HTTP service — Ollama, a web app, a Jupyter notebook, an API — through a public VPS.

```
Local machine                       Public VPS
┌─────────────────────┐             ┌──────────────────────────────┐
│  your service       │◄── TLS ───►│  gotunnel server             │◄── HTTP ── your apps / users
│  localhost:PORT     │   tunnel    │  :8080 (HTTP) :2222 (tunnel) │
│                     │             │                              │
│  gotunnel client    │             └──────────────────────────────┘
└─────────────────────┘
```

## Features

- **Pure Go stdlib** — no external dependencies, single binary
- **Any HTTP service** — web apps, APIs, Ollama, Jupyter, anything
- **TLS tunnel** — auto-generated self-signed cert or bring your own
- **Proxy-compatible** — works behind GitHub Codespaces, ngrok, Cloudflare Tunnel via WebSocket upgrade
- **Optional HTTP API key** — protect the public endpoint
- **Streaming support** — SSE and chunked transfer work end-to-end
- **Multi-worker** — parallel connections for concurrent requests
- **Auto-reconnect** — client reconnects automatically on disconnect

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/your-user/gotunnel
cd gotunnel
go build -o gotunnel .
```

### 2. Generate a shared secret

```bash
TOKEN=$(./gotunnel genkey)
echo $TOKEN   # save this — both server and client need it
```

### 3. Run the server (on your VPS)

```bash
./gotunnel server \
  -token $TOKEN \
  -http  :8080 \
  -tun   :2222
```

Open ports **8080** (HTTP, for your users/apps) and **2222** (TCP, for the tunnel client) in your firewall.

### 4. Run the client (on your local machine)

```bash
./gotunnel client \
  -server vps.example.com:2222 \
  -token  $TOKEN \
  -target localhost:3000 \
  -k                        # needed for the auto-generated self-signed cert
```

### 5. Use it

```bash
curl http://vps.example.com:8080/
```

---

## Examples

### Ollama

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:11434 -k

# List models
curl http://vps.example.com:8080/api/tags

# Chat (streaming)
curl http://vps.example.com:8080/api/generate \
  -d '{"model":"llama3","prompt":"Hello!","stream":true}'
```

### Web app / API server

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000 -k
```

### Jupyter notebook

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:8888 -k
```

### Any HTTP service

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:5000 -k
```

---

## Securing the HTTP endpoint

Add an API key so only authorised clients can reach your service:

```bash
# Server
./gotunnel server -token $TOKEN -apikey $APIKEY -http :8080 -tun :2222

# Clients send either header:
curl -H "Authorization: Bearer $APIKEY" http://vps.example.com:8080/
curl -H "X-API-Key: $APIKEY"            http://vps.example.com:8080/
```

---

## Using a real TLS cert (Let's Encrypt)

```bash
# Obtain a cert
certbot certonly --standalone -d vps.example.com

# Start server with your cert
./gotunnel server \
  -token $TOKEN \
  -http  :8080 \
  -tun   :2222 \
  -cert  /etc/letsencrypt/live/vps.example.com/fullchain.pem \
  -key   /etc/letsencrypt/live/vps.example.com/privkey.pem

# Client no longer needs -k
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000
```

---

## Behind a TLS-terminating proxy

When running inside **GitHub Codespaces**, **ngrok**, **Cloudflare Tunnel**, or any platform that terminates TLS before your process, the tunnel port must listen on plain TCP (the proxy already handles encryption). Use `-notls` on the server and point the client at the proxy's HTTPS URL.

```bash
# Server — plain TCP on the tunnel port
./gotunnel server -token $TOKEN -http :8080 -tun :4444 -notls

# Client — proxy's real cert means no -k needed
./gotunnel client \
  -server https://your-codespace-4444.app.github.dev/ \
  -token  $TOKEN \
  -target localhost:11434
```

Without `-notls` the server wraps the connection in TLS *again*, causing the proxy to reject it with a `tls: first record does not look like a TLS handshake` error.

The client automatically performs a proper WebSocket upgrade handshake (`Upgrade: websocket` + `Sec-WebSocket-Key`) so strict proxies accept the connection before the raw tunnel protocol takes over.

---

## Health check

```bash
curl http://vps.example.com:8080/_tunnel/health
# {"status":"ok","tunnel_clients":5,"pool_ready":5}
```

---

## All flags

### `server`

| Flag | Default | Description |
|------|---------|-------------|
| `-http` | `:8080` | HTTP listen address (for end users / apps) |
| `-tun` | `:2222` | Tunnel listen address (for tunnel client) |
| `-token` | *(required)* | Shared auth token |
| `-cert` | *(auto)* | TLS cert PEM file |
| `-key` | *(auto)* | TLS key PEM file |
| `-apikey` | *(none)* | Optional HTTP API key |
| `-notls` | `false` | Disable TLS on tunnel port (use behind a TLS-terminating proxy) |

### `client`

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(required)* | VPS address — `host:port` or `https://host[:port]` |
| `-token` | *(required)* | Shared auth token |
| `-target` | `localhost:8080` | Local service to tunnel |
| `-workers` | `5` | Parallel tunnel connections |
| `-k` | `false` | Skip TLS cert verification (for self-signed certs) |

---

## Running as a systemd service

```ini
# /etc/systemd/system/gotunnel.service
[Unit]
Description=gotunnel Server
After=network.target

[Service]
ExecStart=/usr/local/bin/gotunnel server -token YOUR_TOKEN -http :8080 -tun :2222
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now gotunnel
```

---

## How it works

1. The **server** opens two listeners: one for HTTP traffic from the outside world, one for the tunnel client.
2. The **client** connects to the tunnel listener, performs a WebSocket upgrade handshake (for proxy compatibility), then authenticates with `AUTH <token>`.
3. Each authenticated connection is placed in a pool. Worker count controls how many concurrent requests can be in flight.
4. When an HTTP request arrives at the server, it dequeues a pooled tunnel connection, writes the raw HTTP request through it, reads the response back, and streams it to the caller — including chunked/SSE bodies.
5. The connection is returned to the pool after each request. If it breaks, the client reconnects automatically with exponential backoff.
