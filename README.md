# GoTunnel

`GoTunnel` is a reverse tunneling solution written in Go. Expose local HTTP, WebSocket, or raw TCP services to the public internet via a remote server — similar to ngrok or Cloudflare Tunnels, but self-hosted.

```text
Local machine                       Public VPS
┌──────────────────────┐            ┌──────────────────────────────┐
│  your service        │◄── TLS ───►│  GoTunnel server             │◄── HTTP/WS ── browsers / apps
│  localhost:PORT      │   tunnel   │  :8080 (HTTP) :2222 (tunnel) │
│                      │            │                              │
│  GoTunnel client     │            └──────────────────────────────┘
└──────────────────────┘
```

## Features

- **Zero-flag Startup**: All configuration lives in a single `config.yaml` file. Run `./gotunnel` with no arguments.
- **YAML Configuration**: Human-readable, well-commented config. No CLI flags to memorise.
- **Multiple Tunnels**: Define any number of tunnels in one config file — all start concurrently.
- **Protocol Support**: HTTP, WebSockets, and raw TCP tunnels.
- **Subdomain Routing**: Route traffic to multiple local services using subdomains.
- **Rich Terminal UI**: Beautiful, real-time traffic monitoring and event logs for both the Server and Client.
- **Background Daemon**: Runs as a background daemon automatically. Detach from the UI (`ctrl+d`) while keeping tunnels alive, and re-attach anytime.
- **Modern Web Dashboard**: Tabbed inspector at `localhost:4040` with metrics, token display, and request replay.
- **Security**: HTTP Basic Auth, auto-generated TLS certificates, per-tunnel API key authentication.
- **Minimal Dependencies**: Only `gopkg.in/yaml.v3` beyond the Go standard library.

---

## Installation

```bash
git clone https://github.com/RGPtv/gotunnel.git
cd gotunnel
go build -o gotunnel ./cmd/gotunnel
```

---

## Quick Start

### 1. Create your config file

GoTunnel reads **`config.yml`** or **`config.yaml`** from the current working directory. The file must contain exactly one root section — either `serverConfig:` or `clientConfig:`.

### 2. Run

```bash
./gotunnel
```

That's it. No subcommands. No flags.

When you run `./gotunnel`, it starts the background daemon and attaches a real-time Terminal UI.
- Press `ctrl+d` to detach from the UI and leave the tunnel running in the background.
- Press `ctrl+c` to stop the background daemon entirely.
- Run `./gotunnel` again anytime to re-attach to the running daemon.

---

## Server Setup

Create `config.yaml` on your VPS:

```yaml
serverConfig:
  http:    ":8080"   # Public HTTP port
  tun:     ":2222"   # Tunnel port (clients connect here)
  token:   "YOUR_SECRET_TOKEN"
  inspect: ":4040"   # Web dashboard (omit to disable)
```

Then run:

```bash
./gotunnel
```

> [!NOTE]
> - If `token` is set to `"auto"`, a secure 256-bit token is auto-generated and printed on startup. Copy it from the dashboard or the console.
> - Ensure your firewall allows the HTTP port (e.g., `8080`) and the tunnel port (e.g., `2222`).

---

## Client Setup

Create `config.yaml` on your local machine:

```yaml
clientConfig:
  server: "vps.example.com:2222"
  token:  "YOUR_SECRET_TOKEN"
  skipTLSVerify: true   # required when server uses self-signed cert

  tunnels:
    - name:   "web"
      target: "localhost:3000"
      type:   "http"
      workers: 10
```

Then run:

```bash
./gotunnel
```

Your local service at `:3000` is now accessible at `http://vps.example.com:8080`.

---

## Full Configuration Reference

### Server (`serverConfig:`)

| Field | Default | Description |
|-------|---------|-------------|
| `http` | `:8080` | HTTP listen address for external users |
| `https` | *(off)* | HTTPS listen address — requires `cert` and `key` |
| `tun` | `:2222` | Tunnel listen address for clients |
| `token` | `""` | Shared auth token — auto-generated if set to `"auto"` |
| `cert` | *(auto)* | Path to TLS certificate PEM file |
| `key` | *(auto)* | Path to TLS private key PEM file |
| `auth` | *(off)* | HTTP Basic Auth for all traffic (`user:pass`) |
| `domain` | *(off)* | Base domain for subdomain routing (e.g. `example.com`) |
| `inspect` | `:4040` | Web dashboard address — omit or set `""` to disable |
| `inspectUser` | `admin` | Dashboard login username |
| `inspectPass` | *(auto)* | Dashboard password — auto-generated and saved to `.gotunnel-admin` |
| `noTLS` | `false` | Disable TLS on tunnel port (use when behind a TLS-terminating proxy) |
| `poolSize` | `512` | Max idle connections per tunnel pool |

**Full example:**

```yaml
serverConfig:
  http:        ":8080"
  https:       ":8443"
  tun:         ":2222"
  token:       "YOUR_TOKEN"
  domain:      "example.com"
  cert:        "/etc/letsencrypt/live/example.com/fullchain.pem"
  key:         "/etc/letsencrypt/live/example.com/privkey.pem"
  auth:        "admin:secret"
  inspect:     ":4040"
  inspectUser: "admin"
  inspectPass: "dashboard-password"
  noTLS:       false
  poolSize:    512
```

---

### Client (`clientConfig:`)

| Field | Default | Description |
|-------|---------|-------------|
| `server` | *(required)* | Server address — `host:port` or `https://host[:port]` |
| `token` | *(required)* | Must match server's `token` |
| `skipTLSVerify` | `false` | Skip TLS cert check (required for self-signed certs) |
| `noTLS` | `false` | Use plain TCP (when server uses `noTLS: true`) |
| `tunnels` | *(required)* | List of tunnel definitions — see below |

---

### Tunnel Fields (`tunnels:`)

Each entry in `tunnels:` is a tunnel that starts when `./gotunnel` runs.

| Field | Default | Description |
|-------|---------|-------------|
| `name` | *(optional)* | Human-readable label shown in startup output |
| `target` | *(required)* | Local service to forward to (e.g. `localhost:3000`) |
| `type` | `http` | Tunnel type: `http` or `tcp` |
| `subdomain` | *(optional)* | Request a subdomain — requires server `domain` to be set |
| `remote` | *(required for tcp)* | Port opened on the server for TCP traffic (e.g. `:22222`) |
| `apiKey` | *(optional)* | Bearer token gate — use `"auto"` to generate one |
| `workers` | `10` | Parallel tunnel connections to maintain |

**Full example — multiple tunnels:**

```yaml
clientConfig:
  server:        "vps.example.com:2222"
  token:         "YOUR_TOKEN"
  skipTLSVerify: false
  noTLS:         false

  tunnels:
    - name:      "api"
      target:    "localhost:3000"
      type:      "http"
      subdomain: "api"
      apiKey:    "auto"
      workers:   10

    - name:      "ollama"
      target:    "localhost:11434"
      type:      "http"
      workers:   5

    - name:      "ssh"
      target:    "localhost:22"
      type:      "tcp"
      remote:    ":22222"
      workers:   3
```

---

## Validation

GoTunnel validates your config on startup and exits with a descriptive error if anything is wrong:

| Error | Cause |
|-------|-------|
| `No configuration file found` | No `config.yml` or `config.yaml` in CWD |
| `both 'serverConfig' and 'clientConfig' are present` | Only one root section is allowed |
| `neither 'serverConfig' nor 'clientConfig' is present` | Config file has no recognised root section |
| `field X not found in type ...` | Unknown YAML key — includes line number |
| `tunnel "ssh" (type 'tcp') requires 'remote' field` | TCP tunnel missing `remote` |
| `'server' is required` | Missing required client field |

---

## Web Dashboard & Traffic Inspector

When the server is running, navigate to `http://127.0.0.1:4040` (or your configured `inspect` address) to access the dashboard.

> [!IMPORTANT]
> The default username is `admin`. If `inspectPass` is not set, a random password is generated on startup and saved to `.gotunnel-admin` in the server's working directory.

### Overview Panel
- Real-time metrics: total requests, active connections, proxy endpoints, tunnel ports
- Client auth token: view, reveal, and copy
- Per-tunnel API key display

### Traffic Inspector
- Live HTTP request stream with method, path, status, and duration
- Search and filter by path or method
- Full request/response header and body inspection
- One-click request replay to your local service

---

## Advanced Configuration

### Subdomain Routing

Serve multiple local services from a single public server using subdomains.

**Server `config.yaml`:**
```yaml
serverConfig:
  http:   ":8080"
  tun:    ":2222"
  token:  "YOUR_TOKEN"
  domain: "example.com"
```

**Client `config.yaml`:**
```yaml
clientConfig:
  server: "vps.example.com:2222"
  token:  "YOUR_TOKEN"
  skipTLSVerify: true

  tunnels:
    - name:      "api"
      target:    "localhost:3000"
      subdomain: "api"       # → api.example.com:8080
    - name:      "docs"
      target:    "localhost:4000"
      subdomain: "docs"      # → docs.example.com:8080
```

---

### TCP Tunneling (SSH, databases, etc.)

```yaml
clientConfig:
  server: "vps.example.com:2222"
  token:  "YOUR_TOKEN"
  skipTLSVerify: true

  tunnels:
    - name:   "ssh"
      target: "localhost:22"
      type:   "tcp"
      remote: ":22222"
```

Connect remotely:
```bash
ssh user@vps.example.com -p 22222
```

---

### Per-Tunnel API Key Authentication

Secure a specific tunnel so only requests bearing a valid API key are forwarded:

```yaml
tunnels:
  - name:   "private-api"
    target: "localhost:8000"
    type:   "http"
    apiKey: "auto"   # printed on startup; use a fixed string to set your own
```

Clients must then pass the key in one of:
```
X-API-Key: <key>
Authorization: Bearer <key>
```

---

### Native HTTPS (Let's Encrypt)

**1. Obtain certificates:**

```bash
# Standard domain
sudo certbot certonly --standalone -d example.com

# Wildcard for subdomain routing
sudo certbot certonly --manual --preferred-challenges dns -d example.com -d "*.example.com"
```

**2. Server `config.yaml`:**

```yaml
serverConfig:
  http:   ":80"
  https:  ":443"
  tun:    ":2222"
  token:  "YOUR_TOKEN"
  domain: "example.com"
  cert:   "/etc/letsencrypt/live/example.com/fullchain.pem"
  key:    "/etc/letsencrypt/live/example.com/privkey.pem"
```

---

### Behind a TLS-Terminating Proxy (NGINX, Cloudflare)

**Server `config.yaml`:**
```yaml
serverConfig:
  http:  ":8080"
  tun:   ":4444"
  token: "YOUR_TOKEN"
  noTLS: true   # proxy handles TLS — no double-wrap
```

**NGINX config (tunnel port):**
```nginx
server {
    listen 443 ssl;
    server_name tunnel.example.com;

    # SSL config here

    location / {
        proxy_pass http://127.0.0.1:4444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

**Client `config.yaml`:**
```yaml
clientConfig:
  server: "https://tunnel.example.com"
  token:  "YOUR_TOKEN"
  noTLS:  false   # proxy presents a real cert — no skipTLSVerify needed

  tunnels:
    - name:   "web"
      target: "localhost:3000"
```

---

## Architecture Overview

1. The **server** exposes two listeners: one for external HTTP/WebSocket traffic, and one for incoming tunnel client connections.
2. The **client** connects to the tunnel listener, authenticates via HMAC-SHA256 challenge/response, and maintains a pool of idle worker connections.
3. **HTTP/WS Proxying**: The server reads each incoming HTTP request, dequeues an idle tunnel connection from the pool, forwards the request, and streams the response back. WebSocket connections are spliced bidirectionally at the TCP level.
4. **TCP Tunneling**: The server opens a dedicated TCP listener per `remote` port. When an external connection arrives, it signals a pooled tunnel worker to start a raw bidirectional pipe to the local target.
5. **Pool Management**: A background janitor probes idle connections every 5 seconds and evicts dead ones. Named pools (per subdomain or TCP remote) are cleaned up automatically when all clients disconnect.
6. **Daemon & IPC**: `gotunnel` automatically runs as a background process. The frontend CLI attaches to the daemon via local IPC (port 41400 for server, 41401 for client) to render the real-time Terminal UI, allowing you to seamlessly detach and re-attach without dropping connections.