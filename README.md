# gotunnel

A lightweight, zero-dependency reverse tunnel written in pure Go. Securely expose any local HTTP service — websites, web apps, APIs, Ollama, Jupyter, anything — through a public VPS.

```
Local machine                       Public VPS
┌──────────────────────┐            ┌──────────────────────────────┐
│  your service        │◄── TLS ───►│  gotunnel server             │◄── HTTP/WS ── browsers / apps
│  localhost:PORT      │   tunnel   │  :8080 (HTTP) :2222 (tunnel) │
│                      │            │                              │
│  gotunnel client     │            └──────────────────────────────┘
└──────────────────────┘
```

## Features

- **Pure Go stdlib** — no external dependencies, single binary
- **Any HTTP service** — websites, SPAs, APIs, Ollama, Jupyter, anything that speaks HTTP
- **Full WebSocket support** — bidirectional WS connections proxied end-to-end
- **Correct HTTP proxying** — hop-by-hop header stripping, `Connection: close` handling, `Host` header preservation
- **`X-Forwarded-*` headers** — apps see the real client IP, host, and scheme
- **TLS tunnel** — auto-generated self-signed cert or bring your own
- **Proxy-compatible** — works behind GitHub Codespaces, ngrok, Cloudflare Tunnel via WebSocket upgrade
- **Optional HTTP API key** — protect the public endpoint
- **Streaming support** — SSE and chunked transfer work end-to-end
- **Multi-worker** — parallel connections for concurrent requests (default: 10)
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

Open ports **8080** (HTTP, for users/apps) and **2222** (TCP, for the tunnel client) in your firewall.

### 4. Run the client (on your local machine)

```bash
./gotunnel client \
  -server vps.example.com:2222 \
  -token  $TOKEN \
  -target localhost:3000 \
  -k                        # only needed with the auto-generated self-signed cert
```

### 5. Open in your browser

```
http://vps.example.com:8080
```

---

## Examples

### Static website or web app (React, Vue, Next.js, etc.)

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:3000 -k
```

Supports full-page navigation, static assets (JS/CSS/images), WebSocket hot-reload, and `fetch`/`XHR` calls.

### Ollama

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:11434 -k

curl http://vps.example.com:8080/api/tags
curl http://vps.example.com:8080/api/generate \
  -d '{"model":"llama3","prompt":"Hello!","stream":true}'
```

### Jupyter notebook

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:8888 -k
# Open http://vps.example.com:8080 in your browser — WebSocket kernel connections work too
```

### FastAPI / Flask / Django

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:8000 -k
```

### Any HTTP service

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -target localhost:5000 -k
```

---

## WebSocket support

WebSocket connections (used by chat apps, live dashboards, hot-reload dev servers, Jupyter kernels, etc.) are proxied transparently. When the server detects a `Upgrade: websocket` request it hijacks the browser connection and splices it directly to the tunnel, giving full bidirectional streaming with no HTTP overhead.

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
certbot certonly --standalone -d vps.example.com

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

When running inside **GitHub Codespaces**, **ngrok**, **Cloudflare Tunnel**, or any platform that terminates TLS before your process, use `-notls` on the server. The proxy already handles encryption — without this flag the server wraps the connection in TLS again, causing a handshake failure.

```bash
# Server — plain TCP on the tunnel port
./gotunnel server -token $TOKEN -http :8080 -tun :4444 -notls

# Client — no -k needed, proxy provides a real cert
./gotunnel client \
  -server https://your-codespace-4444.app.github.dev/ \
  -token  $TOKEN \
  -target localhost:3000
```

The client performs a real WebSocket upgrade handshake (`Upgrade: websocket` + `Sec-WebSocket-Accept`) so strict proxies accept the connection before the tunnel protocol takes over.

---

## Health check

```bash
curl http://vps.example.com:8080/_tunnel/health
# {"status":"ok","tunnel_clients":10,"pool_ready":10}
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
| `-workers` | `10` | Parallel tunnel connections |
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

1. The **server** opens two listeners: one for HTTP/WebSocket traffic from the outside world, one for the tunnel client.
2. The **client** connects to the tunnel listener, performs a WebSocket upgrade handshake (for proxy compatibility), then authenticates with `AUTH <token>`.
3. Each authenticated connection is placed in a worker pool. The `-workers` flag controls how many concurrent requests can be in flight.
4. **Regular HTTP:** the server dequeues a tunnel connection, writes the raw request through it (stripping hop-by-hop headers, adding `X-Forwarded-*`), reads the response, and streams it back — including SSE and chunked bodies.
5. **WebSockets:** the server detects `Upgrade: websocket`, hijacks the browser-side TCP connection, and splices it directly to the tunnel connection for full bidirectional streaming.
6. After each HTTP response, the tunnel connection is returned to the pool (unless the server sent `Connection: close`). After a WebSocket session ends, that tunnel connection is closed and the worker reconnects automatically.