"""
relay_server.py — multipath traffic relay (TCP + UDP)

Wire protocol — client sends one of:
  RELAY host:port\\r\\n       → TCP CONNECT relay
  RELAY_UDP\\r\\n             → UDP tunnel (datagrams framed over TCP)

Framing for UDP datagrams (both directions over TCP):
  [2 bytes big-endian: total payload length]
  [1 byte: host length][host bytes][2 bytes big-endian: port][data bytes]

Multipath outbound:
  BIND_ADDRESSES=10.0.0.1,10.0.0.2,203.0.113.5
  Each new session uses the next source IP in round-robin order.
  Different source IPs traverse different uplinks / ECMP paths.
  Unset → OS default interface.

Environment variables:
  RELAY_PORT      Listen port (default: 9999)
  BIND_ADDRESSES  Comma-separated source IPs for multipath
"""

import os
import socket
import struct
import threading
from itertools import cycle

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("RELAY_PORT", 9999))

_raw       = os.getenv("BIND_ADDRESSES", "")
BIND_ADDRS = [b.strip() for b in _raw.split(",") if b.strip()]

_cycle     = cycle(BIND_ADDRS) if BIND_ADDRS else cycle([None])
_lock      = threading.Lock()

def next_bind():
    with _lock:
        return next(_cycle)

# ── Framing helpers ─────────────────────────────────────────────────────────
LEN_HDR = struct.Struct("!H")

def frame(host, port, data):
    hb = host.encode()
    payload = bytes([len(hb)]) + hb + struct.pack("!H", port) + data
    return LEN_HDR.pack(len(payload)) + payload

def parse_frames(buf):
    """Yield (host, port, data) tuples; return unconsumed buf tail."""
    while len(buf) >= 2:
        length = LEN_HDR.unpack_from(buf)[0]
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

# ── Helpers ─────────────────────────────────────────────────────────────────
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def read_line(sock):
    """Read bytes until \\r\\n; return (line_str, leftover_bytes)."""
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(256)
        if not chunk:
            raise ConnectionError("client closed before header")
        buf += chunk
        if len(buf) > 512:
            raise ValueError("header too large")
    line, rest = buf.split(b"\r\n", 1)
    return line.decode("ascii").strip(), rest

def outbound_tcp(host, port, bind_addr=None):
    """Open a TCP connection to host:port, optionally from bind_addr."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if bind_addr:
        s.bind((bind_addr, 0))
    s.connect((host, port))
    return s

def outbound_udp(bind_addr=None):
    """Create an unconnected UDP socket, optionally bound to bind_addr."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind_addr:
        s.bind((bind_addr, 0))
    return s

# ── Relay half ──────────────────────────────────────────────────────────────
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

# ── TCP session ─────────────────────────────────────────────────────────────
def handle_tcp(client, dest_host, dest_port, leftover, bind_addr, label):
    print(f"TCP  {dest_host}:{dest_port}  via {label}")
    try:
        upstream = outbound_tcp(dest_host, dest_port, bind_addr)
    except OSError as e:
        client.sendall(f"ERR {e}\r\n".encode())
        return

    client.sendall(b"OK\r\n")
    if leftover:
        upstream.sendall(leftover)

    t = threading.Thread(target=relay_half, args=(upstream, client), daemon=True)
    t.start()
    relay_half(client, upstream)
    t.join()

# ── UDP session ─────────────────────────────────────────────────────────────
def handle_udp(client, leftover, bind_addr, label):
    """
    Datagrams arrive from the proxy as length-framed TCP messages.
    Each frame contains (dest_host, dest_port, data).
    We send them out as real UDP and return any responses the same way.
    """
    print(f"UDP  tunnel  via {label}")
    udp = outbound_udp(bind_addr)
    client.sendall(b"OK\r\n")

    # Track which (host, port) pairs we've seen so we can route replies
    # back.  Map: (dest_host, dest_port) → True (all share one UDP socket).
    udp.settimeout(0.1)

    def read_from_proxy():
        """TCP → UDP: proxy sends framed datagrams, we forward as real UDP."""
        buf = leftover
        try:
            while True:
                try:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                except OSError:
                    break
                consumed = buf
                for dest_host, dest_port, data in parse_frames(consumed):
                    try:
                        udp.sendto(data, (dest_host, dest_port))
                    except OSError:
                        pass
                buf = b""   # parse_frames consumed all complete frames
        finally:
            udp.close()

    def read_from_network():
        """UDP → TCP: real UDP replies, reframe and send back to proxy."""
        try:
            while True:
                try:
                    data, (src_host, src_port) = udp.recvfrom(65535)
                    client.sendall(frame(src_host, src_port, data))
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=read_from_proxy,   daemon=True)
    t2 = threading.Thread(target=read_from_network, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

# ── Session dispatcher ───────────────────────────────────────────────────────
def handle_client(client, addr):
    bind_addr = next_bind()
    label     = bind_addr if bind_addr else "default"
    try:
        line, leftover = read_line(client)

        if line.startswith("RELAY "):
            dest = line[6:].strip()
            if ":" not in dest:
                raise ValueError(f"bad RELAY target: {dest!r}")
            host, port_s = dest.rsplit(":", 1)
            handle_tcp(client, host, int(port_s), leftover, bind_addr, label)

        elif line == "RELAY_UDP":
            handle_udp(client, leftover, bind_addr, label)

        else:
            client.sendall(b"ERR unknown command\r\n")

    except Exception as e:
        print(f"[{addr[0]}:{addr[1]}] error: {e}")
        try:
            client.sendall(f"ERR {e}\r\n".encode())
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass

# ── Server loop ──────────────────────────────────────────────────────────────
def start_relay():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(500)

    paths = ", ".join(BIND_ADDRS) if BIND_ADDRS else "OS default"
    print(f"Relay listening on :{LISTEN_PORT} — outbound paths: {paths}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    start_relay()
