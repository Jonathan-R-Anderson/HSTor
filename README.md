# High-Speed Tor

A protocol-agnostic SOCKS5 proxy that load-balances outbound traffic across multiple Tor circuits, optionally routing through a multipath relay server for true multi-path forwarding.

## Architecture

```
Client (any protocol)
    │  SOCKS5
    ▼
proxy_pool.py  (:1080)
    │  round-robins across N Tor SOCKS5 circuits
    │  TCP  →  RELAY host:port\r\n
    │  UDP  →  RELAY_UDP\r\n + length-framed datagrams
    ▼
[Tor Network]
    ▼
relay_server.py  (:9999)
    │  reconstructs destination from RELAY header
    │  binds outbound socket to next source IP (ECMP / multipath)
    ▼
Real destination
```

### Two operating modes

| Mode | How to enable | Behaviour |
|------|--------------|-----------|
| **Direct** | Leave `RELAY_HOST` unset | Proxy connects through Tor directly to the destination |
| **Relay** | Set `RELAY_HOST` | Proxy sends traffic through Tor to `relay_server.py`, which forwards to the real destination via configurable outbound paths |

## Components

| File | Role |
|------|------|
| `proxy_pool.py` | SOCKS5 server — accepts client connections, distributes across Tor circuits |
| `relay_server.py` | Relay server — receives tunnelled traffic, forwards using multipath outbound |
| `start.sh` | Launches N `tor` processes then starts `proxy_pool.py` |
| `Dockerfile` | Image for the proxy pool (includes Tor) |
| `Dockerfile.relay` | Minimal image for the relay server (no Tor dependency) |
| `docker-compose.yml` | Runs both services together |

## SOCKS5 support

- **CMD CONNECT (0x01)** — TCP relay for any protocol (HTTP, HTTPS, SSH, SMTP, custom binary, etc.)
- **CMD UDP ASSOCIATE (0x03)** — UDP relay, tunnelled over TCP through Tor to the relay server, which sends real UDP packets to the destination

Address types supported: IPv4, IPv6, and domain names.

## Relay wire protocol

The proxy speaks a simple line-based protocol to the relay server over a plain TCP connection:

```
# TCP session
RELAY host:port\r\n          → relay connects to host:port via TCP
OK\r\n                        ← tunnel is ready; raw bytes flow both ways

# UDP session
RELAY_UDP\r\n                 → relay opens a UDP socket
OK\r\n                        ← ready; datagrams are length-framed over this TCP conn
```

UDP datagram framing (both directions):
```
[2 bytes: payload length][1 byte: host length][host][2 bytes: port][data]
```

## Configuration

All settings are controlled via environment variables (or `.env`).

### Proxy pool (`proxy_pool.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `1080` | SOCKS5 listen port |
| `TOR_INSTANCES` | `3` | Number of Tor circuits to start |
| `BASE_SOCKS_PORT` | `9050` | First Tor SOCKS5 port (`9050`, `9051`, …) |
| `RELAY_HOST` | _(unset)_ | Relay server hostname or IP; enables relay mode |
| `RELAY_PORT` | `9999` | Relay server port |

### Relay server (`relay_server.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `9999` | Listen port |
| `BIND_ADDRESSES` | _(unset)_ | Comma-separated source IPs for multipath outbound routing |

### Multipath routing

Set `BIND_ADDRESSES` on the relay server to distribute outbound connections across multiple source IPs. Each new session round-robins to the next address, so packets leave via different network interfaces or uplinks:

```
BIND_ADDRESSES=10.0.0.1,10.0.0.2,203.0.113.5
```

When combined with ECMP routing on the host, this gives true multipath forwarding. Leave unset to use the OS default interface.

## Quick start

### Docker Compose (both services)

```bash
# Build and start
docker compose up --build

# Scale Tor circuits
TOR_INSTANCES=10 docker compose up --build
```

The proxy listens on `localhost:1080` as a SOCKS5 proxy.

### Relay server on a separate host

On the relay host:
```bash
BIND_ADDRESSES=10.0.0.1,10.0.0.2 python3 relay_server.py
```

In `.env` on the proxy host:
```
RELAY_HOST=<relay-server-ip>
RELAY_PORT=9999
```

### Direct mode (no relay server)

Leave `RELAY_HOST` empty in `.env`. The proxy will connect directly through Tor to the destination without a relay hop.

## Usage

Any SOCKS5-capable client works without modification:

```bash
# curl
curl --socks5 localhost:1080 https://check.torproject.org

# SSH through SOCKS5
ssh -o ProxyCommand='nc -X 5 -x localhost:1080 %h %p' user@host

# wget
wget -e "use_proxy=yes" -e "socks_proxy=socks5://localhost:1080" https://example.com

# System-wide (Linux)
export ALL_PROXY=socks5://localhost:1080
```

## Requirements

- Docker & Docker Compose, or
- Python 3.11+ with `pip install -r requirements.txt` and `tor` installed

```
# requirements.txt should include:
PySocks
```
