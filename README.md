# GoTunnel

`GoTunnel` is a self-hosted reverse tunnel written in Go. Expose local HTTP, WebSocket, or raw TCP services to the public internet via a remote VPS — no third-party services required.

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

- **Zero-flag Startup** — all configuration lives in a single `config.yaml`. Run `./gotunnel` with no arguments.
- **Multiple Tunnels** — define any number of tunnels in one config file; all start concurrently.
- **Protocol Support** — HTTP, WebSockets, and raw TCP tunnels.
- **Subdomain Routing** — route traffic to multiple local services using subdomains.
- **Rich Terminal UI** — real-time traffic monitoring and event logs for both the server and client.
- **Background Daemon** — runs detached automatically. Press `ctrl+d` to leave tunnels alive and re-attach anytime with `./gotunnel`.
- **Web Dashboard** — tabbed inspector at `localhost:4040` with live metrics, token display, and request replay.
- **Security** — HMAC-SHA256 challenge/response auth, TLS on the tunnel port, per-tunnel API key gating, HTTP Basic Auth.
- **Minimal Dependencies** — only `gopkg.in/yaml.v3` (config parsing) and `golang.org/x/term` (terminal raw mode). Stream multiplexing is implemented with a purpose-built stdlib-only engine — no external mux library.

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

When you run `./gotunnel` it starts a background daemon and attaches a real-time Terminal UI.

| Key | Action |
|-----|--------|
| `ctrl+d` | Detach from the UI — daemon and tunnels keep running |
| `ctrl+c` | Stop the daemon entirely |
| `./gotunnel` (again) | Re-attach to the running daemon |

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
> If `token` is set to `"auto"`, a secure 256-bit token is auto-generated and printed on startup.
> Ensure your firewall allows the HTTP port (e.g. `8080`) and the tunnel port (e.g. `2222`).

---

## Client Setup

Create `config.yaml` on your local machine:

```yaml
clientConfig:
  server: "vps.example.com:2222"
  token:  "YOUR_SECRET_TOKEN"
  skipTLSVerify: true   # required when server uses a self-signed cert

  tunnels:
    - name:    "web"
      target:  "localhost:3000"
      type:    "http"
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
| `auth` | *(off)* | HTTP Basic Auth for all proxied traffic (`user:pass`) |
| `domain` | *(off)* | Base domain for subdomain routing (e.g. `example.com`) |
| `inspect` | `:4040` | Web dashboard address — omit or set `""` to disable |
| `inspectUser` | `admin` | Dashboard login username |
| `inspectPass` | *(auto)* | Dashboard password — auto-generated and saved to `.gotunnel-admin` |
| `noTLS` | `false` | Disable TLS on tunnel port (use when behind a TLS-terminating proxy) |
| `poolSize` | `512` | Max idle connections per tunnel pool |
| `allowedTCPPorts`| *(optional)* | List of allowed remote addresses for TCP tunnels (e.g. `[":22222"]`) |

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
| `skipTLSVerify` | `false` | Skip TLS cert check (use with self-signed certs) |
| `noTLS` | `false` | Use plain TCP (when server sets `noTLS: true`) |
| `tunnels` | *(required)* | List of tunnel definitions — see below |

---

### Tunnel Fields (`tunnels:`)

| Field | Default | Description |
|-------|---------|-------------|
| `name` | *(optional)* | Human-readable label shown in startup output |
| `target` | *(required)* | Local service to forward to (e.g. `localhost:3000`) |
| `type` | `http` | Tunnel type: `http` or `tcp` |
| `subdomain` | *(optional)* | Request a subdomain — requires server `domain` to be set |
| `remote` | *(required for tcp)* | Port opened on the server for TCP traffic (e.g. `:22222`) |

**Full example — multiple tunnels:**

```yaml
clientConfig:
  server:        "vps.example.com:2222"
  token:         "YOUR_TOKEN"
  skipTLSVerify: false

  tunnels:
    - name:      "api"
      target:    "localhost:3000"
      type:      "http"
      subdomain: "api"

    - name:      "ollama"
      target:    "localhost:11434"
      type:      "http"

    - name:      "ssh"
      target:    "localhost:22"
      type:      "tcp"
      remote:    ":22222"
```

---

## Validation

GoTunnel validates your config on startup and exits with a descriptive error if anything is wrong:

| Error | Cause |
|-------|-------|
| `No configuration file found` | No `config.yml` or `config.yaml` in CWD |
| `both 'serverConfig' and 'clientConfig' are present` | Only one root section is allowed |
| `neither 'serverConfig' nor 'clientConfig' is present` | No recognised root section |
| `field X not found in type ...` | Unknown YAML key — includes line number |
| `tunnel "ssh" (type 'tcp') requires 'remote' field` | TCP tunnel missing `remote` |
| `'server' is required` | Missing required client field |

---

## Web Dashboard & Traffic Inspector

Navigate to `http://127.0.0.1:4040` (or your configured `inspect` address) while the server is running.

> [!IMPORTANT]
> The default username is `admin`. If `inspectPass` is not set, a random password is generated on startup and saved to `.gotunnel-admin` in the server's working directory.

### Overview Panel
- Real-time metrics: total requests, active connections, proxy endpoints, tunnel ports
- Client auth token: view, reveal, and copy
- Dynamic per-tunnel settings: toggle API Key auth, Basic Auth, and AI/Ollama optimizations

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

### Per-Tunnel API Key and Basic Auth

Secure specific HTTP tunnels on the fly via the Web Dashboard. Tunnels can be dynamically gated with:
- **API Key Auth**: Clients must pass the key in `X-API-Key: <key>` or `Authorization: Bearer <key>`.
- **Basic Auth**: Standard HTTP Basic Authentication.
- **AI Mode**: Specific optimizations (CORS, no body cap, long timeouts) for AI services like Ollama.

These settings are managed in the Dashboard's Overview panel for each active tunnel.

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
  noTLS: true   # proxy handles TLS — avoids double-wrapping
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

## Architecture

```
                              ┌────────────────────────────────────────┐
                              │            GoTunnel Server             │
   Browser / app              │                                        │
        │                     │  ┌──────────┐     ┌─────────────────┐ │
        │  HTTP / WS          │  │  HTTP    │     │  Tunnel         │ │
        └────────────────────►│  │  Proxy   │◄───►│  Listener :2222 │ │
                              │  │  :8080   │     └────────┬────────┘ │
                              │  └──────────┘              │          │
                              └───────────────────────────┼──────────┘
                                                          │ TLS + HMAC auth
                                                          │
                              ┌───────────────────────────┼──────────┐
                              │           GoTunnel Client  │          │
                              │                            │          │
                              │  ┌─────────────────────────┘          │
                              │  │  mux.Session (stdlib multiplexer)  │
                              │  │  ┌────────┐ ┌────────┐ ┌────────┐ │
                              │  │  │Stream 1│ │Stream 2│ │Stream N│ │
                              │  └──┴────────┴─┴────────┴─┴────────┘ │
                              │             │                          │
                              │  ┌──────────▼──────────┐              │
                              │  │  Local service       │              │
                              │  │  localhost:PORT      │              │
                              │  └─────────────────────┘              │
                              └────────────────────────────────────────┘
```

### How it works

1. **Authentication** — the client connects to the tunnel port and completes an HMAC-SHA256 challenge/response. Invalid tokens are rejected and rate-limited per IP.

2. **Multiplexing (`internal/mux`)** — a single authenticated TCP connection is promoted into a full-duplex multiplexed session using GoTunnel's built-in stream multiplexer (`internal/mux`). This engine is written entirely against the Go standard library with no external dependencies. It provides:
   - Bidirectional streams with independent flow control (256 KB per-stream window)
   - Graceful half-close (FIN) and hard reset (RST)
   - SYN/ACK stream handshake
   - Ping/Pong keepalive (30 s interval, 10 s timeout)
   - Full `net.Conn` compliance including deadline support

3. **HTTP/WebSocket proxying** — the server opens a new mux stream for each incoming HTTP request, forwards the request, and streams the response back. WebSocket upgrades are spliced at the TCP level through the same stream.

4. **TCP tunneling** — the server opens a dedicated TCP listener per `remote` port. Each inbound connection opens a mux stream and pipes raw bytes bidirectionally to the client's local target.

5. **Daemon & IPC** — `./gotunnel` automatically daemonises. The CLI frontend attaches to the daemon via local IPC to render the Terminal UI and can detach or re-attach without dropping tunnels.

6. **Janitor** — a background goroutine runs every 10 seconds to detect dead sessions (via yamux's `IsClosed()`), close their TCP listeners, and correct the active-connection counter.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `gopkg.in/yaml.v3` | YAML config parsing |
| `golang.org/x/term` | Terminal raw mode and size detection for the TUI |

All other functionality — TLS, HTTP, stream multiplexing, cryptography, IPC — uses the Go standard library only.
