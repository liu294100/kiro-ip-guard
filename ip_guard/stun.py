"""Minimal STUN (RFC 5389) Binding client.

A request is sent either directly over UDP (OS routes, including TUN, still
apply) or through a SOCKS5 UDP relay such as the mixed port of Clash/mihomo,
so the mapped address reflects the proxy route for that STUN server.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from typing import Callable, Optional
from urllib.parse import urlparse

DEFAULT_STUN_PORT = 3478
MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_MAPPED_ADDRESS = 0x0001
_XOR_MAPPED_ADDRESS = 0x0020
_FIRST_RETRANSMIT_SECONDS = 0.5


def _parse_endpoint(
    text: str,
    default_port: Optional[int],
    allowed_schemes: set[str],
    implicit_scheme: str,
) -> tuple[str, int]:
    raw = str(text or "").strip()
    value = raw
    if not value:
        raise ValueError("地址为空")
    if "://" not in value:
        value = f"{implicit_scheme}://{value}"
    parsed = urlparse(value)
    if parsed.scheme.lower() not in allowed_schemes:
        raise ValueError(f"不支持的协议 {parsed.scheme}: {raw}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError(f"地址格式无效: {raw}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"端口无效: {raw}") from exc
    host = parsed.hostname
    if not host:
        raise ValueError(f"缺少主机名: {raw}")
    port = port or default_port
    if not port:
        raise ValueError(f"缺少端口: {raw}")
    return host, port


def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def parse_stun_server(text: str) -> tuple[str, int]:
    value = str(text or "").strip()
    # Accept the RFC 7064 URI form "stun:host:port" as well as "host:port".
    if value.lower().startswith("stun:") and not value.lower().startswith("stun://"):
        value = value[5:]
    return _parse_endpoint(value, DEFAULT_STUN_PORT, {"udp", "stun"}, "udp")


def normalize_stun_server(text: str) -> str:
    return format_host_port(*parse_stun_server(text))


def parse_socks_proxy(text: str) -> tuple[str, int]:
    return _parse_endpoint(text, None, {"socks5", "socks5h", "socks"}, "socks5")


def parse_binding_response(data: bytes, transaction_id: bytes) -> Optional[str]:
    """Return the mapped address, or None when the packet is not our response."""
    if len(data) < 20:
        return None
    message_type, length, cookie = struct.unpack("!HHI", data[:8])
    if cookie != MAGIC_COOKIE or data[8:20] != transaction_id:
        return None
    if message_type != _BINDING_SUCCESS:
        raise ValueError(f"STUN 服务器返回错误响应 0x{message_type:04x}")
    body = data[20 : 20 + length]
    mapped: Optional[str] = None
    index = 0
    while index + 4 <= len(body):
        attribute, size = struct.unpack("!HH", body[index : index + 4])
        value = body[index + 4 : index + 4 + size]
        index += 4 + size + (-size % 4)
        if attribute not in (_MAPPED_ADDRESS, _XOR_MAPPED_ADDRESS) or len(value) < 8:
            continue
        family = value[1]
        if family == 1:
            raw = value[4:8]
        elif family == 2 and len(value) >= 20:
            raw = value[4:20]
        else:
            continue
        if attribute == _XOR_MAPPED_ADDRESS:
            key = struct.pack("!I", MAGIC_COOKIE) + transaction_id
            raw = bytes(byte ^ key[position] for position, byte in enumerate(raw))
            return str(ipaddress.ip_address(raw))
        mapped = mapped or str(ipaddress.ip_address(raw))
    if mapped:
        return mapped
    raise ValueError("STUN 响应缺少映射地址")


def stun_binding(
    host: str,
    port: int,
    timeout: float,
    socks_proxy: Optional[tuple[str, int]] = None,
) -> str:
    """Send a Binding Request and return the public address seen by the server."""
    transaction_id = os.urandom(12)
    request = struct.pack("!HHI", _BINDING_REQUEST, 0, MAGIC_COOKIE) + transaction_id
    deadline = time.monotonic() + timeout
    if socks_proxy is None:
        return _exchange_direct(host, port, request, transaction_id, deadline)
    return _exchange_socks5(socks_proxy, host, port, request, transaction_id, deadline)


def _exchange_direct(
    host: str,
    port: int,
    request: bytes,
    transaction_id: bytes,
    deadline: float,
) -> str:
    candidates = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    if not candidates:
        raise OSError(f"无法解析 {host}")
    # Prefer IPv4 so the result matches the IPv4 egress used by most HTTPS checks.
    family, _, _, _, address = sorted(candidates, key=lambda item: item[0] != socket.AF_INET)[0]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        return _transact(sock, lambda: sock.sendto(request, address), lambda data: data, transaction_id, deadline)


def _exchange_socks5(
    proxy: tuple[str, int],
    host: str,
    port: int,
    request: bytes,
    transaction_id: bytes,
    deadline: float,
) -> str:
    connect_timeout = max(0.5, min(5.0, deadline - time.monotonic()))
    with socket.create_connection(proxy, timeout=connect_timeout) as control:
        control.sendall(b"\x05\x01\x00")
        if _recv_exact(control, 2) != b"\x05\x00":
            raise ValueError("代理不支持无认证 SOCKS5")
        # UDP ASSOCIATE; the client address is unknown in advance.
        control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        head = _recv_exact(control, 4)
        if head[0] != 5 or head[1] != 0:
            raise ValueError(f"代理拒绝 SOCKS5 UDP 转发（REP={head[1]}）")
        relay_host = _read_socks_address(control, head[3])
        relay_port = struct.unpack("!H", _recv_exact(control, 2))[0]
        try:
            if ipaddress.ip_address(relay_host).is_unspecified:
                relay_host = proxy[0]
        except ValueError:
            pass
        relay = socket.getaddrinfo(relay_host, relay_port, type=socket.SOCK_DGRAM)[0]
        # Send the domain name so the proxy applies its domain rules, as it
        # would for a real application.
        header = b"\x00\x00\x00" + _encode_socks_address(host) + struct.pack("!H", port)
        with socket.socket(relay[0], socket.SOCK_DGRAM) as udp:
            # The TCP control connection must stay open while the relay is used.
            return _transact(
                udp,
                lambda: udp.sendto(header + request, relay[4]),
                _strip_socks_udp_header,
                transaction_id,
                deadline,
            )


def probe_socks5_udp(proxy: tuple[str, int], timeout: float = 0.6) -> bool:
    """Return True when the endpoint accepts a no-auth SOCKS5 UDP ASSOCIATE.

    HTTP-only proxy ports (e.g. v2rayN 10809) fail here, while SOCKS or mixed
    ports (Clash/mihomo 7890, v2rayN 10808) pass.
    """
    try:
        with socket.create_connection(proxy, timeout=timeout) as control:
            control.settimeout(timeout)
            control.sendall(b"\x05\x01\x00")
            if _recv_exact(control, 2) != b"\x05\x00":
                return False
            control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
            head = _recv_exact(control, 4)
            return head[0] == 5 and head[1] == 0
    except (OSError, ValueError):
        return False


def _transact(
    sock: socket.socket,
    send: Callable[[], object],
    unwrap: Callable[[bytes], Optional[bytes]],
    transaction_id: bytes,
    deadline: float,
) -> str:
    # UDP can drop packets; retransmit with doubling intervals until the deadline.
    interval = _FIRST_RETRANSMIT_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("STUN 请求超时")
        send()
        wait_until = time.monotonic() + min(interval, remaining)
        while True:
            left = wait_until - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            except ConnectionResetError:
                # Windows reports an ICMP "port unreachable" this way.
                break
            payload = unwrap(data)
            if payload is None:
                continue
            address = parse_binding_response(payload, transaction_id)
            if address:
                return address
        interval *= 2


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("代理提前关闭连接")
        data += chunk
    return data


def _read_socks_address(sock: socket.socket, address_type: int) -> str:
    if address_type == 1:
        return socket.inet_ntop(socket.AF_INET, _recv_exact(sock, 4))
    if address_type == 4:
        return socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    if address_type == 3:
        size = _recv_exact(sock, 1)[0]
        return _recv_exact(sock, size).decode("idna")
    raise ValueError(f"未知 SOCKS5 地址类型 {address_type}")


def _encode_socks_address(host: str) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna")
        return b"\x03" + bytes([len(name)]) + name
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed


def _strip_socks_udp_header(data: bytes) -> Optional[bytes]:
    if len(data) < 4 or data[2] != 0:  # fragmented datagrams are not supported
        return None
    address_type = data[3]
    if address_type == 1:
        offset = 10
    elif address_type == 4:
        offset = 22
    elif address_type == 3 and len(data) > 4:
        offset = 7 + data[4]
    else:
        return None
    return data[offset:]
