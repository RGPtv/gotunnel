# gotunnel

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
- **Terminal UI**: Real-time traffic monitoring in the terminal.
- **Web Inspector**: Local web interface (`localhost:4040`) for traffic inspection and request replay.
- **Protocol Support**: HTTP, WebSockets, and raw TCP.
- **Subdomain Routing**: Route traffic to multiple local services using subdomains.
- **Security**: Supports HTTP Basic Auth, auto-generated self-signed TLS certificates, and API keys.
- **Configuration**: Manage tunnels via JSON configuration files.

## Installation

Clone the repository and build the binary:

```bash
git clone https://github.com/RGPtv/gotunnel.git
cd gotunnel
go build -o gotunnel .
```

## Usage

### 1. Start the Server

Run the server on your remote machine (e.g., a public VPS). By default, it listens for HTTP traffic on `:8080` and tunnel connections on `:2222`.

```bash
./gotunnel server \
  -http :8080 \
  -tun :2222 \
  -domain example.com \  # Optional: enable subdomain routing
  -auth admin:secret     # Optional: HTTP basic authentication
```

The server generates a secure 256-bit token on startup. Note this token as it is required for the client. Ensure ports `8080` and `2222` are open in your firewall.

### 2. Start the Client

Run the client on your local machine, pointing it to the server's address and providing the authentication token.

```bash
./gotunnel client \
  -server vps.example.com:2222 \
  -token <YOUR_TOKEN> \
  -target localhost:3000 \
  -k  # Required if the server is using an auto-generated self-signed certificate
```

Your local service at `:3000` is now accessible at `http://vps.example.com:8080`.

## Configuration Files

You can manage complex tunnel setups using a `config.json` file rather than CLI arguments. Place this file in the directory where you run the client.

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

Start a specific tunnel from the configuration:

```bash
./gotunnel start api -k
```

## Traffic Inspector

The server provides a web-based dashboard for monitoring and inspecting traffic.

When the server is running, navigate to `http://127.0.0.1:4040` (or your configured inspector address). The dashboard provides:
- Authentication management (view/copy tokens).
- Active tunnel endpoints and connection states.
- Real-time HTTP request/response inspection.
- Request replay capabilities.

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

#### Behind a Proxy (NGINX/Cloudflare)

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

Connect the client using `wss://` (HTTPS):

```bash
./gotunnel client -server https://tunnel.example.com -token <TOKEN> -target localhost:3000
```

## Command Line Reference

### `server`

| Flag | Default | Description |
|------|---------|-------------|
| `-http` | `:8080` | HTTP listen address |
| `-https` | | HTTPS listen address (requires `-cert` and `-key`) |
| `-tun` | `:2222` | Tunnel listen address |
| `-token` | *(auto)* | Shared authentication token |
| `-cert` | *(auto)* | TLS certificate PEM file |
| `-key` | *(auto)* | TLS key PEM file |
| `-apikey` | | Optional HTTP API key |
| `-auth` | | Optional HTTP Basic Auth (`user:pass`) |
| `-domain` | | Base domain for routing |
| `-inspect` | `:4040` | Inspector web UI address |
| `-inspect-user`| `admin` | Dashboard username |
| `-inspect-pass`| *(auto)* | Dashboard password |
| `-notls` | `false` | Disable TLS on tunnel port |

### `client`

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(prompt)* | Remote server address |
| `-token` | *(prompt)* | Shared authentication token |
| `-target` | `localhost:8080`| Local service to tunnel |
| `-type` | `http` | Tunnel type (`http` or `tcp`) |
| `-subdomain`| | Request a specific subdomain |
| `-remote` | | Remote address/port for TCP tunnels |
| `-workers` | `10` | Parallel tunnel connections |
| `-k` | `false` | Skip TLS certificate verification |
| `-notls` | `false` | Use plain TCP (for TLS proxies) |

## Architecture Overview

1. The **server** exposes two listeners: one for external HTTP/WebSocket traffic, and one for incoming tunnel client connections.
2. The **client** initiates a connection to the tunnel listener, authenticates, and maintains a pool of worker connections (`-workers`).
3. **HTTP/WS Proxying**: For standard HTTP, the server reads the request, forwards it through an available tunnel connection, and streams the response back. For WebSockets, the server hijacks the TCP connection after the `Upgrade` header is detected and splices it directly with the tunnel connection.
