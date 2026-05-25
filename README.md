# gotunnel

A lightweight, zero-dependency reverse tunnel written in pure Go. Securely expose any local HTTP service — websites, web apps, APIs, Ollama, Jupyter, anything — through a public VPS. Now featuring a beautiful **Live Terminal Dashboard** and an **Inspector UI** with 1-click replay functionality!

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

- **Pure Go stdlib** — no external dependencies, single binary.
- **Live Terminal Dashboard** — beautiful, flicker-free TUI for monitoring live traffic and tunnel status (just like `ngrok`).
- **Configuration Files** — easily manage all your tunnels in a `config.json` file.
- **Request Inspector with Replay** — live web UI at `localhost:4040` showing traffic. Instantly replay requests with one click!
- **Subdomain Routing** — route multiple client tunnels using custom subdomains on the same server.
- **HTTP Basic Authentication** — natively password-protect your exposed tunnels natively right from the browser.
- **Full WebSocket support** — bidirectional WS connections proxied end-to-end.
- **TLS tunnel** — auto-generated self-signed cert or bring your own.
- **Proxy-compatible** — works behind GitHub Codespaces, ngrok, Cloudflare Tunnel via WebSocket upgrade.
- **TCP Tunneling** — native raw TCP streams for exposing SSH, MySQL, Redis, and more.

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/your-user/gotunnel
cd gotunnel
go build -o gotunnel .
```

### 2. Run the server (on your VPS)

```bash
./gotunnel server \
  -http  :8080 \
  -tun   :2222 \
  -domain example.com \  # Optional: enables subdomain routing
  -auth  admin:secret    # Optional: basic authentication
```

The server will **auto-generate** a secure 256-bit token. You can copy it from the terminal output or the Web Dashboard (`http://localhost:4040`).

Open ports **8080** (HTTP, for users/apps) and **2222** (TCP, for the tunnel client) in your firewall.

### 3. Run the client (on your local machine)

```bash
./gotunnel client \
  -server vps.example.com:2222 \
  -token  <YOUR_AUTO_GENERATED_TOKEN> \
  -target localhost:3000 \
  -k                        # only needed with the auto-generated self-signed cert
```

### 4. Open in your browser

```
http://vps.example.com:8080
```

---

## Using Configuration Files (New!)

Tired of typing long terminal commands? You can define your tunnels in a `config.json` file in the same directory:

```json
{
  "server": "vps.example.com:2222",
  "token": "YOUR_SECRET_TOKEN",
  "tunnels": {
    "web": {
      "target": "localhost:3000",
      "subdomain": "api",
      "type": "http"
    },
    "ssh": {
      "target": "localhost:22",
      "type": "tcp",
      "remote": ":22222"
    }
  }
}
```

Now, simply start your tunnel using its name:
```bash
./gotunnel start web -k
```

---

## Web Dashboard & Inspector

The server includes a beautiful ngrok-style web dashboard.

Open **http://127.0.0.1:4040** in your browser while the server is running to see:
- **Secured Login**: Protected dashboard access with auto-generated or custom credentials.
- **Auth Token**: Easily view and copy your auto-generated shared secret token.
- **Active Tunnels**: View all active HTTP/TCP tunnel endpoints and their worker connections.
  - *Click any tunnel* to filter the traffic inspector to show only requests for that tunnel!
- **Live Traffic Inspector**: Every HTTP request flowing through the selected tunnel in real time.
  - Method, path, status code, and response time
  - Expandable request/response headers
  - **Replay Button**: Instantly re-trigger any captured request with a single click!

---

## Subdomain Routing

If you run multiple microservices, you can host them concurrently on the same server using subdomains!
1. Start the server with `-domain yourdomain.com`
2. Start the client with `-subdomain api`
3. Your local service is now available securely at `api.yourdomain.com:8080`!

---

## Securing the HTTP endpoint

### HTTP Basic Auth (Browser Prompt)
```bash
./gotunnel server -token $TOKEN -auth admin:supersecret -http :8080 -tun :2222
```

### API Key (Header)
```bash
./gotunnel server -token $TOKEN -apikey $APIKEY -http :8080 -tun :2222
# Clients send: curl -H "Authorization: Bearer $APIKEY" http://vps.example.com:8080/
```

---

## TCP Tunneling (SSH, MySQL, etc.)

Expose raw TCP ports (like SSH):

```bash
./gotunnel client -server vps.example.com:2222 -token $TOKEN -type tcp -target localhost:22 -remote :22222 -k
```
Connect to your local machine from anywhere:
```bash
ssh user@vps.example.com -p 22222
```

---

## Native HTTPS (No NGINX Required)

If you don't want to use NGINX or any reverse proxy, `gotunnel` can serve HTTPS natively using your own TLS certificates (e.g. from Let's Encrypt):

```bash
sudo ./gotunnel server \
  -token $TOKEN \
  -http  :80 \
  -https :443 \
  -tun   :2222 \
  -domain yourdomain.com \
  -cert  /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  -key   /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

This runs both HTTP (`:80`) and HTTPS (`:443`) listeners. Clients and browsers can connect directly to `https://yourdomain.com` — no proxy needed!

---

## Behind a TLS-terminating proxy (e.g. NGINX, Cloudflare)

When running behind NGINX, GitHub Codespaces, or Cloudflare Tunnel, the proxy usually terminates TLS (HTTPS) before the connection reaches your process. 

In this case, you should use the `-notls` flag on the server so it doesn't try to wrap the connection in TLS again (which would cause a handshake failure).

```bash
# Server — run plain TCP on the tunnel port
./gotunnel server -token $TOKEN -notls -http :8080 -tun :4444
```

Then, configure NGINX to proxy WebSocket traffic to the tunnel port (`:4444` in this example). Here is a sample `nginx.conf` block for the tunnel endpoint:

```nginx
server {
    listen 443 ssl;
    server_name tunnel.yourdomain.com;
    
    # ... your SSL cert config ...

    location / {
        proxy_pass http://127.0.0.1:4444;
        
        # Crucial for WebSocket upgrade!
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

Now, your clients can connect securely through NGINX. Because NGINX provides a real SSL certificate, the client no longer needs the `-k` (insecure) flag!

```bash
# Client connects via wss:// (HTTPS) through NGINX
./gotunnel client -server https://tunnel.yourdomain.com -token $TOKEN -target localhost:3000
```

---

## All flags

### `server`

| Flag | Default | Description |
|------|---------|-------------|
| `-http` | `:8080` | HTTP listen address (for end users / apps) |
| `-https` | *(none)* | HTTPS listen address (e.g. `:443`) — requires `-cert` and `-key` |
| `-tun` | `:2222` | Tunnel listen address (for tunnel client) |
| `-token` | *(auto-generated)* | Shared auth token |
| `-cert` | *(auto)* | TLS cert PEM file |
| `-key` | *(auto)* | TLS key PEM file |
| `-apikey` | *(none)* | Optional HTTP API key |
| `-auth` | *(none)* | Optional HTTP Basic Auth (`user:pass`) |
| `-domain` | *(none)* | Base domain for subdomain routing |
| `-inspect` | `:4040` | Inspector web UI address (empty to disable) |
| `-inspect-user` | `admin` | Dashboard login username |
| `-inspect-pass` | *(auto)* | Dashboard login password |
| `-notls` | `false` | Disable TLS on tunnel port |

### `client`

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(prompt)* | VPS address — `host:port` or `https://host[:port]` |
| `-token` | *(prompt)* | Shared auth token |
| `-target` | `localhost:8080` | Local service to tunnel |
| `-type` | `http` | Tunnel type (`http` or `tcp`) |
| `-subdomain`| *(none)* | Request a specific subdomain |
| `-remote` | *(none)* | Remote address/port for TCP tunnels |
| `-workers` | `10` | Parallel tunnel connections |
| `-k` | `false` | Skip TLS cert verification |
| `-notls` | `false` | Use plain TCP (for TLS proxies) |

---

## How it works

1. The **server** opens two listeners: one for HTTP/WebSocket traffic from the outside world, one for the tunnel client.
2. The **client** connects to the tunnel listener, performs a WebSocket upgrade handshake (for proxy compatibility), then authenticates with `AUTH <token>`.
3. Each authenticated connection is placed in a worker pool. The `-workers` flag controls how many concurrent requests can be in flight.
4. **Regular HTTP:** the server dequeues a tunnel connection, writes the raw request through it (stripping hop-by-hop headers, adding `X-Forwarded-*`), reads the response, and streams it back — including SSE and chunked bodies.
5. **WebSockets:** the server detects `Upgrade: websocket`, hijacks the browser-side TCP connection, and splices it directly to the tunnel connection for full bidirectional streaming.
6. After each HTTP response, the tunnel connection is returned to the pool (unless the server sent `Connection: close`). After a WebSocket session ends, that tunnel connection is closed and the worker reconnects automatically.