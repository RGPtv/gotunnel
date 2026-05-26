# GoTunnel

`gotunnel` is a reverse tunneling solution written in Go. It allows you to expose local services (HTTP, WebSockets, or raw TCP) to the public internet via a remote server, similar to tools like ngrok or Cloudflare Tunnels.

```text
Local machine                       Public VPS
┌──────────────────────┐            ┌──────────────────────────────┐
│  your service        │◄── TLS ───►│  gotunnel server             │◄── HTTP/WS ── browsers / apps
│  localhost:PORT      │   tunnel   │  :8080 (HTTP) :2222 (tunnel) │
│                      │            │                              │
│  gotunnel client     │            └──────────────────────────────┘
└──────────────────────┘
```

## Features

- **Standard Library Only**: Built entirely with the Go standard library. No external dependencies.
- **Terminal UI**: Real-time traffic monitoring in the client terminal.
- **Modern Dashboard UI**: A tabbed web inspector (`localhost:4040` by default) featuring a navigation sidebar, overview metrics, and a full traffic inspector panel.
- **Protocol Support**: HTTP, WebSockets, and raw TCP.
- **Subdomain Routing**: Route traffic to multiple local services using subdomains.
- **Security**: Supports HTTP Basic Auth, auto-generated self-signed TLS certificates, and API key authentication (with automatic secure key generation).
- **Configuration**: Manage tunnels via JSON configuration files.

---

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/RGPtv/gotunnel.git
cd gotunnel
go build -o gotunnel ./cmd/gotunnel
```

---

## Usage

### 1. Generate an Auth Token (Optional)
While the server can auto-generate a secure token on startup, you can generate your own custom 256-bit token beforehand:
```bash
./gotunnel genkey
```

### 2. Start the Server
Run the server on your remote machine (e.g., a public VPS). By default, it listens for HTTP traffic on port `:8080` and tunnel connections on port `:2222`.

```bash
# Basic startup (with a custom token)
./gotunnel server -token <YOUR_TOKEN>

# Advanced startup (with subdomain routing and HTTP basic authentication)
./gotunnel server \
  -http :8080 \
  -tun :2222 \
  -domain example.com \
  -auth admin:secret
```

> [!NOTE]
> - **Auto-generated Token**: If `-token` is omitted, the server will auto-generate a secure 256-bit token. The console will display a masked version (e.g., `abcde...`), but you can retrieve and copy the full token from the web dashboard.
> - **Firewall**: Ensure that the HTTP/HTTPS ports (e.g., `8080`, `443`) and the tunnel port (e.g., `2222`) are open in your firewall.

### 3. Start the Client
Run the client on your local machine (where the target service is running) to connect to the server.

#### Option A: Interactive Command (Simplest)
If you run the client without arguments, it will interactively prompt you for the server address and token:
```bash
./gotunnel client
```

#### Option B: CLI Arguments
Specify the server details and target service directly via flags:
```bash
# Expose local port 3000 to the public server
./gotunnel client -server vps.example.com:2222 -token <YOUR_TOKEN> -target localhost:3000 -k
```

> [!TIP]
> - **Self-Signed Certificates**: By default, `gotunnel` uses an auto-generated, in-memory self-signed certificate for the tunnel connection. You **must** pass the `-k` flag to the client to skip TLS certificate verification.
> - **Gateway API Key Authentication**: You can secure a specific tunnel by requiring an API key. Pass `-apikey auto` to generate a random key, or `-apikey your_secret_key`. Requests accessing the tunnel must then provide the key in the `X-API-Key` or `Authorization: Bearer <key>` header.

Your local service at `:3000` is now accessible via the server at `http://vps.example.com:8080`.

---

## Configuration Files

Instead of specifying long command-line arguments every time, you can manage multiple complex tunnel configurations using a `config.json` file. 

Place `config.json` in the working directory from which you run the client.

### `config.json` Structure

```json
{
  "server": "vps.example.com:2222",
  "token": "YOUR_TOKEN",
  "tunnels": {
    "api": {
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

### Configuration Fields

- **Root Fields**:
  - `server` (string): The remote server address (maps to client's `-server` flag).
  - `token` (string): The shared authentication token (maps to client's `-token` flag).
  - `tunnels` (object): A map of named tunnel configurations.
- **Tunnel Fields**:
  - `target` (string): The local address/port to tunnel (maps to client's `-target` flag).
  - `type` (string): The tunnel protocol, either `"http"` or `"tcp"` (maps to client's `-type` flag).
  - `subdomain` (string): The requested subdomain for HTTP routing (maps to client's `-subdomain` flag).
  - `remote` (string): The remote TCP address/port to bind on the server (maps to client's `-remote` flag).

### Running a Configured Tunnel

To start a specific tunnel configuration, use the `start` command followed by the name of the tunnel:

```bash
./gotunnel start api
```

#### Appending Extra Arguments
Any additional command-line flags you pass to the `start` command are automatically appended to the client. This allows you to combine configured settings with runtime client flags (such as skipping TLS verification or adding an API key):

```bash
# Start the "api" tunnel, skip TLS verification, and enable gateway API key security
./gotunnel start api -k -apikey auto

# Start the "ssh" tunnel and skip TLS verification
./gotunnel start ssh -k
```

---

## Web Dashboard & Traffic Inspector

The server provides a modern, responsive web-based dashboard for monitoring, configuration overview, and request inspection.

When the server is running, navigate to `http://127.0.0.1:4040` (or your configured inspector address) and log in. The dashboard is divided into two primary views managed by the left sidebar navigation:

> [!IMPORTANT]
> - **Credentials**: The default username is `admin`.
> - **Password**: If `-inspect-pass` is not specified, a random password is generated and printed to the console on startup, and saved to a `.gotunnel-admin` file in the server's working directory.

### 1. Overview
The default landing view, offering:
- **Server Metrics**: Real-time tracking of total requests, active connections, proxy endpoints, and tunnel ports.
- **Client Auth Token**: View, reveal, and quickly copy the shared client authentication token.
- **API Key**: If a tunnel client connects with an API key, this section displays the key with fully integrated reveal and copy actions.

### 2. Traffic Inspector
An advanced request/response monitoring suite that provides:
- **Real-Time Request Stream**: Instant updates of incoming HTTP requests with method, path, hostname, response status, and duration metrics.
- **Search & Filters**: Quickly locate specific requests by searching their paths or methods.
- **Deep Inspection**: View detailed HTTP headers and formatted body payloads for both requests and responses.
- **Request Replay**: Trigger one-click replays of captured requests directly to your local service.

---

## Advanced Configuration

### Subdomain Routing

Host multiple services on the same server using subdomains.

1. Start the server with a base domain: `-domain example.com`
2. Start the client and specify a subdomain: `-subdomain api`
3. The service will be routed via `api.example.com:8080`.

### TCP Tunneling

Expose raw TCP services, such as SSH or databases.

```bash
./gotunnel client -server vps.example.com:2222 -token <TOKEN> -type tcp -target localhost:22 -remote :22222 -k
```

Connect remotely:
```bash
ssh user@vps.example.com -p 22222
```

### TLS and Reverse Proxies

#### Native HTTPS

`gotunnel` can serve HTTPS directly without a reverse proxy. To do this, you need an SSL/TLS certificate (e.g., from Let's Encrypt).

**1. Obtain Certificates (Certbot)**

You can use `certbot` to generate a free SSL certificate. 

```bash
# Standard certificate (Standalone mode, requires port 80 to be free)
sudo certbot certonly --standalone -d example.com

# Wildcard certificate for subdomain routing (Requires DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns -d example.com -d "*.example.com"
```

**2. Start the Server**

Run the server with root privileges to bind to ports 80 and 443, providing the paths to your generated certificates:

```bash
sudo ./gotunnel server \
  -token <TOKEN> \
  -http :80 \
  -https :443 \
  -tun :2222 \
  -domain example.com \
  -cert /etc/letsencrypt/live/example.com/fullchain.pem \
  -key /etc/letsencrypt/live/example.com/privkey.pem
```

#### Behind a Proxy (NGINX / Cloudflare)

If you are using a proxy that terminates TLS, disable TLS on the tunnel port using `-notls`.

```bash
# Server configuration
./gotunnel server -token <TOKEN> -notls -http :8080 -tun :4444
```

Example NGINX configuration for WebSocket upgrade on the tunnel port:

```nginx
server {
    listen 443 ssl;
    server_name tunnel.example.com;
    
    # SSL configuration here

    location / {
        proxy_pass http://127.0.0.1:4444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

Connect the client through the proxy:

```bash
./gotunnel client -server https://tunnel.example.com -token <TOKEN> -target localhost:3000
```

---

## Command Line Reference

| Command | Description |
|---------|-------------|
| `server` | Run the tunnel server on your VPS / public host |
| `client` | Run the tunnel client on your local machine |
| `start` | Run a named tunnel from config.json |
| `genkey` | Generate a random 256-bit auth token |

### `server` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-http` | `:8080` | HTTP listen address for external users |
| `-https` | | HTTPS listen address (requires `-cert` and `-key`) |
| `-tun` | `:2222` | Tunnel listen address for clients |
| `-token` | *(auto)* | Shared client authentication token (auto-generated if empty, first 8 characters printed on startup) |
| `-cert` | | TLS certificate PEM file (auto-generated if empty) |
| `-key` | | TLS key PEM file (auto-generated if empty) |
| `-auth` | | Optional HTTP Basic Auth (`user:pass`) for external HTTP traffic |
| `-domain` | | Base domain for subdomain routing |
| `-inspect` | `:4040` | Inspector web UI address (empty to disable) |
| `-inspect-user` | `admin` | Dashboard login username |
| `-inspect-pass` | *(auto)* | Dashboard login password (auto-generated if empty and saved to `.gotunnel-admin`) |
| `-notls` | `false` | Disable TLS on tunnel port (useful when behind a TLS-terminating proxy) |
| `-poolsize` | `512` | Maximum connection capacity per tunnel pool |

### `client` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(prompt)* | Remote server address (host:port or https://host[:port]) |
| `-token` | *(prompt)* | Shared authentication token |
| `-target` | `localhost:8080` | Local service to tunnel (e.g. `localhost:3000` or `http://localhost:3000`) |
| `-type` | `http` | Tunnel type (`http` or `tcp`) |
| `-subdomain` | | Request a specific subdomain (requires server to use `-domain`) |
| `-remote` | | Remote address/port for TCP tunnels (e.g. `:22222`) |
| `-apikey` | | Optional API key for this tunnel (use `auto` to auto-generate one) |
| `-workers` | `10` | Parallel tunnel connections |
| `-k` | `false` | Skip TLS certificate verification (required when server uses self-signed certificate) |
| `-notls` | `false` | Use plain TCP (when server runs `-notls` behind a TLS proxy) |

---

## Architecture Overview

1. The **server** exposes two listeners: one for external HTTP/WebSocket traffic, and one for incoming tunnel client connections.
2. The **client** initiates a connection to the tunnel listener, authenticates, and maintains a pool of worker connections (`-workers`).
3. **HTTP/WS Proxying**: For standard HTTP, the server reads the request, forwards it through an available tunnel connection, and streams the response back. For WebSockets, the server hijacks the TCP connection after the `Upgrade` header is detected and splices it directly with the tunnel connection.
