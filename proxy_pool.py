"""
proxy_pool.py — protocol-agnostic SOCKS5 proxy

Accepts SOCKS5 connections for any TCP or UDP protocol.
Routes each session through one of N Tor SOCKS5 circuits, either directly
to the destination or via relay_server.py (for multipath outbound routing).

SOCKS5 support:
  CMD 0x01  CONNECT        → full TCP relay for any protocol
  CMD 0x03  UDP ASSOCIATE  → UDP datagrams tunnelled over TCP through Tor

Environment variables:
  PROXY_PORT      Local SOCKS5 listen port (default: 1080)
  TOR_INSTANCES   Number of Tor circuits (default: 3)
  BASE_SOCKS_PORT First Tor SOCKS5 port (default: 9050)
  RELAY_HOST      Relay server hostname/IP (enables relay mode)
  RELAY_PORT      Relay server port (default: 9999)
"""

import os
import socket
import struct
import threading
from itertools import cycle

# ── Config ─────────────────────────────────────────────────────────────────
LISTEN_HOST     = "0.0.0.0"
LISTEN_PORT     = int(os.getenv("PROXY_PORT", 1080))
TOR_INSTANCES   = int(os.getenv("TOR_INSTANCES", 3))
BASE_SOCKS_PORT = int(os.getenv("BASE_SOCKS_PORT", 9050))
RELAY_HOST      = os.getenv("RELAY_HOST", "")
RELAY_PORT      = int(os.getenv("RELAY_PORT", 9999))

TOR_PROXIES = [("127.0.0.1", BASE_SOCKS_PORT + i) for i in range(TOR_INSTANCES)]
_cycle     = cycle(TOR_PROXIES)
_lock      = threading.Lock()

def next_tor():
    with _lock:
        return next(_cycle)

# ── SOCKS5 constants ────────────────────────────────────────────────────────
VER          = 0x05
NO_AUTH      = 0x00
NO_METHODS   = 0xFF
CMD_CONNECT  = 0x01
CMD_UDP      = 0x03
ATYP_IPV4    = 0x01
ATYP_DOMAIN  = 0x03
ATYP_IPV6    = 0x04
REP_OK       = 0x00
REP_FAIL     = 0x01
REP_REFUSED  = 0x05
REP_NO_CMD   = 0x07

def _reply(rep, bind_addr="0.0.0.0", bind_port=0):
    ip = socket.inet_aton(bind_addr)
    return struct.pack("!BBBB4sH", VER, rep, 0, ATYP_IPV4, ip, bind_port)

# ── Low-level recv helpers ──────────────────────────────────────────────────
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed mid-read")
        buf += chunk
    return buf

# ── SOCKS5 handshake ────────────────────────────────────────────────────────
def do_handshake(client):
    """
    Complete SOCKS5 auth negotiation (no-auth only) and parse the request.
    Returns (cmd, dest_host, dest_port).
    """
    # Greeting
    header = recv_exact(client, 2)
    if header[0] != VER:
        raise ValueError(f"Not SOCKS5 (got version {header[0]})")
    nmethods = header[1]
    methods  = recv_exact(client, nmethods)
    if NO_AUTH not in methods:
        client.sendall(bytes([VER, NO_METHODS]))
        raise ValueError("Client requires authentication, only no-auth supported")
    client.sendall(bytes([VER, NO_AUTH]))

    # Request
    req = recv_exact(client, 4)
    if req[0] != VER:
        raise ValueError("Bad SOCKS5 request version")
    cmd, _, atyp = req[1], req[2], req[3]

    if atyp == ATYP_IPV4:
        addr_bytes = recv_exact(client, 4)
        dest_host  = socket.inet_ntoa(addr_bytes)
    elif atyp == ATYP_DOMAIN:
        length    = recv_exact(client, 1)[0]
        dest_host = recv_exact(client, length).decode()
    elif atyp == ATYP_IPV6:
        addr_bytes = recv_exact(client, 16)
        dest_host  = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        client.sendall(_reply(REP_FAIL))
        raise ValueError(f"Unsupported ATYP: {atyp}")

    dest_port = struct.unpack("!H", recv_exact(client, 2))[0]
    return cmd, dest_host, dest_port

# ── Relay helpers ───────────────────────────────────────────────────────────
def relay_half(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def relay_bidirectional(a, b):
    t = threading.Thread(target=relay_half, args=(b, a), daemon=True)
    t.start()
    relay_half(a, b)
    t.join()

# ── Upstream connection via Tor SOCKS5 ──────────────────────────────────────
def _tor_connect(tor_host, tor_port, dest_host, dest_port):
    """
    Open a raw TCP connection through Tor's SOCKS5 to dest_host:dest_port.
    We implement the SOCKS5 client handshake ourselves so we don't need
    PySocks as a dependency (though it could be used here too).
    """
    s = socket.create_connection((tor_host, tor_port))

    # Greeting
    s.sendall(bytes([0x05, 0x01, 0x00]))          # VER NMETHODS NO_AUTH
    resp = recv_exact(s, 2)
    if resp[1] == 0xFF:
        raise ConnectionError("Tor rejected no-auth")

    # Request
    host_bytes = dest_host.encode()
    req = (
        bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)])
        + host_bytes
        + struct.pack("!H", dest_port)
    )
    s.sendall(req)

    # Response
    head = recv_exact(s, 4)
    if head[1] != 0x00:
        raise ConnectionError(f"Tor CONNECT failed, REP={head[1]:#x}")
    atyp = head[3]
    if atyp == 0x01:
        recv_exact(s, 4)
    elif atyp == 0x03:
        recv_exact(s, recv_exact(s, 1)[0])
    elif atyp == 0x04:
        recv_exact(s, 16)
    recv_exact(s, 2)   # bound port

    return s

def open_upstream(dest_host, dest_port):
    """
    Return a connected socket aimed at dest_host:dest_port.
    Routes through Tor → relay_server when RELAY_HOST is set,
    or through Tor directly to the destination otherwise.
    """
    tor_host, tor_port = next_tor()

    if RELAY_HOST:
        # Connect to relay server through Tor
        sock = _tor_connect(tor_host, tor_port, RELAY_HOST, RELAY_PORT)
        # Send relay header so the server knows the real destination
        sock.sendall(f"RELAY {dest_host}:{dest_port}\r\n".encode())
        ack = b""
        while b"\r\n" not in ack:
            chunk = sock.recv(64)
            if not chunk:
                raise ConnectionError("Relay closed before ACK")
            ack += chunk
        if not ack.strip().startswith(b"OK"):
            raise ConnectionError(f"Relay rejected: {ack.strip()!r}")
    else:
        sock = _tor_connect(tor_host, tor_port, dest_host, dest_port)

    return sock

# ── CMD CONNECT (any TCP protocol) ─────────────────────────────────────────
def handle_connect(client, dest_host, dest_port):
    try:
        upstream = open_upstream(dest_host, dest_port)
    except Exception as e:
        client.sendall(_reply(REP_REFUSED))
        raise

    client.sendall(_reply(REP_OK))
    relay_bidirectional(client, upstream)

# ── CMD UDP ASSOCIATE ───────────────────────────────────────────────────────
# Datagrams are tunnelled over a TCP connection to the relay server so they
# pass through Tor.  Wire format (both directions):
#   [2 bytes big-endian total length][1 byte host len][host][2 bytes port][data]
# The relay server sends back framed datagrams with the source addr:port.

UDP_FRAG_HDR = struct.Struct("!H")   # 2-byte length prefix

def _frame(host, port, data):
    hb = host.encode()
    return UDP_FRAG_HDR.pack(1 + len(hb) + 2 + len(data)) + bytes([len(hb)]) + hb + struct.pack("!H", port) + data

def _unframe(buf):
    """Yield (host, port, data, remaining_buf) tuples from a byte buffer."""
    while True:
        if len(buf) < 2:
            break
        length = UDP_FRAG_HDR.unpack_from(buf)[0]
        if len(buf) < 2 + length:
            break
        payload = buf[2:2 + length]
        buf     = buf[2 + length:]
        hlen    = payload[0]
        host    = payload[1:1 + hlen].decode()
        port    = struct.unpack("!H", payload[1 + hlen:3 + hlen])[0]
        data    = payload[3 + hlen:]
        yield host, port, data
    return buf

def _pump_tcp_to_udp(tcp_sock, udp_sock, client_addr):
    """Read framed datagrams from TCP tunnel → wrap in SOCKS5 UDP header → send to client."""
    buf = b""
    try:
        while True:
            chunk = tcp_sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            remaining = buf
            for src_host, src_port, data in _unframe(remaining):
                # Build SOCKS5 UDP reply header
                try:
                    socket.inet_aton(src_host)
                    atyp = ATYP_IPV4
                    addr_bytes = socket.inet_aton(src_host)
                except OSError:
                    atyp = ATYP_DOMAIN
                    addr_bytes = bytes([len(src_host)]) + src_host.encode()
                udp_hdr = struct.pack("!HBB", 0, 0, atyp) + addr_bytes + struct.pack("!H", src_port)
                udp_sock.sendto(udp_hdr + data, client_addr)
            # Consume processed bytes
            buf = b""   # simplification: _unframe consumed all complete frames
    except OSError:
        pass

def _pump_udp_to_tcp(udp_sock, tcp_sock):
    """Read SOCKS5 UDP datagrams from client → strip header → frame → send over TCP tunnel."""
    try:
        while True:
            pkt, addr = udp_sock.recvfrom(65535)
            if len(pkt) < 4:
                continue
            frag = pkt[2]
            if frag != 0:
                continue  # fragmentation not supported
            atyp = pkt[3]
            offset = 4
            if atyp == ATYP_IPV4:
                dest_host = socket.inet_ntoa(pkt[offset:offset + 4])
                offset += 4
            elif atyp == ATYP_DOMAIN:
                hlen = pkt[offset]
                offset += 1
                dest_host = pkt[offset:offset + hlen].decode()
                offset += hlen
            elif atyp == ATYP_IPV6:
                dest_host = socket.inet_ntop(socket.AF_INET6, pkt[offset:offset + 16])
                offset += 16
            else:
                continue
            dest_port = struct.unpack("!H", pkt[offset:offset + 2])[0]
            offset += 2
            data = pkt[offset:]
            tcp_sock.sendall(_frame(dest_host, dest_port, data))
    except OSError:
        pass

def handle_udp_associate(client, client_reported_host, client_reported_port):
    """
    Open a local UDP socket for the client, open a TCP tunnel to the relay
    server (through Tor), and bridge UDP ↔ TCP tunnel bidirectionally.
    """
    # Local UDP relay socket — clients send datagrams here
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", 0))
    _, udp_port = udp_sock.getsockname()

    # TCP tunnel to relay server for UDP datagrams
    tor_host, tor_port = next_tor()
    try:
        if RELAY_HOST:
            tcp_tunnel = _tor_connect(tor_host, tor_port, RELAY_HOST, RELAY_PORT)
            tcp_tunnel.sendall(b"RELAY_UDP\r\n")
            ack = b""
            while b"\r\n" not in ack:
                chunk = tcp_tunnel.recv(64)
                if not chunk:
                    raise ConnectionError("Relay closed before UDP ACK")
                ack += chunk
            if not ack.strip().startswith(b"OK"):
                raise ConnectionError(f"Relay UDP rejected: {ack.strip()!r}")
        else:
            raise RuntimeError("UDP ASSOCIATE without relay server is not supported; set RELAY_HOST")
    except Exception as e:
        udp_sock.close()
        client.sendall(_reply(REP_FAIL))
        raise

    # Tell client where to send UDP datagrams
    my_ip = client.getsockname()[0]
    client.sendall(_reply(REP_OK, my_ip, udp_port))

    # Bridge UDP ↔ TCP tunnel
    # We need the client's actual UDP source address — we learn it from the first datagram
    # Use a mutable container so the thread can share it
    client_udp_addr = [None]
    def udp_reader():
        try:
            while True:
                pkt, addr = udp_sock.recvfrom(65535)
                if client_udp_addr[0] is None:
                    client_udp_addr[0] = addr
                if len(pkt) < 4:
                    continue
                frag = pkt[2]
                if frag != 0:
                    continue
                atyp = pkt[3]
                offset = 4
                if atyp == ATYP_IPV4:
                    dest_host = socket.inet_ntoa(pkt[offset:offset + 4])
                    offset += 4
                elif atyp == ATYP_DOMAIN:
                    hlen = pkt[offset]; offset += 1
                    dest_host = pkt[offset:offset + hlen].decode(); offset += hlen
                elif atyp == ATYP_IPV6:
                    dest_host = socket.inet_ntop(socket.AF_INET6, pkt[offset:offset + 16])
                    offset += 16
                else:
                    continue
                dest_port = struct.unpack("!H", pkt[offset:offset + 2])[0]; offset += 2
                data = pkt[offset:]
                try:
                    tcp_tunnel.sendall(_frame(dest_host, dest_port, data))
                except OSError:
                    break
        except OSError:
            pass
        finally:
            tcp_tunnel.close()

    def tcp_reader():
        buf = b""
        try:
            while True:
                chunk = tcp_tunnel.recv(65536)
                if not chunk:
                    break
                buf += chunk
                new_buf = buf
                for src_host, src_port, data in _unframe(new_buf):
                    if client_udp_addr[0] is None:
                        continue
                    try:
                        socket.inet_aton(src_host)
                        atyp_b = bytes([ATYP_IPV4]) + socket.inet_aton(src_host)
                    except OSError:
                        atyp_b = bytes([ATYP_DOMAIN, len(src_host)]) + src_host.encode()
                    hdr = struct.pack("!HB", 0, 0) + atyp_b + struct.pack("!H", src_port)
                    udp_sock.sendto(hdr + data, client_udp_addr[0])
                buf = b""
        except OSError:
            pass
        finally:
            udp_sock.close()

    t1 = threading.Thread(target=udp_reader, daemon=True)
    t2 = threading.Thread(target=tcp_reader, daemon=True)
    t1.start(); t2.start()

    # Keep SOCKS5 control connection open; when it closes, shut everything down
    try:
        client.recv(1)
    except OSError:
        pass
    finally:
        tcp_tunnel.close()
        udp_sock.close()

# ── Main session dispatcher ─────────────────────────────────────────────────
def handle_client(client, addr):
    try:
        cmd, dest_host, dest_port = do_handshake(client)

        if cmd == CMD_CONNECT:
            handle_connect(client, dest_host, dest_port)
        elif cmd == CMD_UDP:
            handle_udp_associate(client, dest_host, dest_port)
        else:
            client.sendall(_reply(REP_NO_CMD))

    except Exception as e:
        print(f"[{addr[0]}:{addr[1]}] error: {e}")
    finally:
        try:
            client.close()
        except OSError:
            pass

# ── Server loop ─────────────────────────────────────────────────────────────
def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(500)

    mode = f"via relay {RELAY_HOST}:{RELAY_PORT}" if RELAY_HOST else "direct through Tor"
    print(f"SOCKS5 proxy on port {LISTEN_PORT} — {len(TOR_PROXIES)} Tor circuits — {mode}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    start_proxy()
