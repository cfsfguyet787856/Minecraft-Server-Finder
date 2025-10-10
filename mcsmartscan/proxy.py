"""SOCKS5 proxy rotation and health tracking helpers."""

from __future__ import annotations

import heapq
import itertools
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional, Sequence, Tuple


class ProxyError(Exception):
    """Base class for proxy related errors."""


class ProxyAcquireTimeout(ProxyError):
    """Raised when no proxy could be acquired within the requested timeout."""


class ProxyHandshakeError(ProxyError):
    """Raised when the SOCKS5 handshake with the proxy fails."""


class ProxyTargetError(ProxyError):
    """Raised when the proxy cannot reach the requested target host."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass
class ProxyStats:
    host: str
    port: int
    index: int
    successes: int = 0
    proxy_failures: int = 0
    target_failures: int = 0
    consecutive_proxy_failures: int = 0
    last_latency_ms: Optional[float] = None
    last_error: Optional[str] = None
    last_stage: Optional[str] = None
    in_use: bool = False
    assigned_at: float = 0.0
    cooldown_until: float = 0.0
    total_sessions: int = 0

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


EventCallback = Callable[[dict], None]


class ProxyLease:
    """Represents a temporary reservation of a proxy endpoint."""

    def __init__(self, pool: "ProxyPool", stats: ProxyStats) -> None:
        self._pool = pool
        self._stats = stats
        self._closed = False

    @property
    def label(self) -> str:
        return self._stats.label

    @property
    def stats(self) -> ProxyStats:
        return self._stats

    def connector(self, host: str, port: int, timeout: float) -> socket.socket:
        """Return an established TCP socket to the target via this proxy."""
        return self._pool.open_tcp(self._stats, host, port, timeout)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pool.release(self._stats)

    def __enter__(self) -> "ProxyLease":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class ProxyPool:
    """Broker that doles out SOCKS5 proxies to worker threads."""

    def __init__(
        self,
        proxies: Iterable[Tuple[str, int]],
        *,
        event_callback: Optional[EventCallback] = None,
    ) -> None:
        self._stats: List[ProxyStats] = []
        self._event_callback = event_callback
        self._cv = threading.Condition()
        self._lock = threading.RLock()
        self._heap: List[Tuple[float, int, ProxyStats]] = []
        self._counter = itertools.count()

        for idx, (host, port) in enumerate(proxies):
            stats = ProxyStats(host=host, port=port, index=idx)
            self._stats.append(stats)
            self._push(stats, available_at=0.0)

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        default_port: int = 1080,
        event_callback: Optional[EventCallback] = None,
    ) -> "ProxyPool":
        proxies: List[Tuple[str, int]] = []
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    host, _, port_str = line.partition(":")
                    host = host.strip()
                    try:
                        port = int(port_str.strip())
                    except ValueError:
                        port = default_port
                else:
                    host = line
                    port = default_port
                if not host:
                    continue
                proxies.append((host, port))
        except FileNotFoundError:
            proxies = []
        except Exception:
            proxies = []
        return cls(proxies, event_callback=event_callback)

    def set_event_callback(self, callback: Optional[EventCallback]) -> None:
        self._event_callback = callback

    # ------------------------------------------------------------------ #
    # Public properties
    # ------------------------------------------------------------------ #
    @property
    def total(self) -> int:
        return len(self._stats)

    def available_now(self) -> int:
        now = time.time()
        with self._cv:
            return sum(1 for available, _, stats in self._heap if available <= now and not stats.in_use)

    def prepare_for_run(self) -> None:
        with self._lock:
            for stats in self._stats:
                stats.consecutive_proxy_failures = 0
                stats.last_error = None
                stats.last_stage = None
                stats.last_latency_ms = None

    # ------------------------------------------------------------------ #
    # Acquisition and release
    # ------------------------------------------------------------------ #
    def acquire(self, timeout: Optional[float] = None) -> ProxyLease:
        deadline = None if timeout is None else time.time() + timeout
        event: Optional[dict] = None
        lease: Optional[ProxyLease] = None
        with self._cv:
            while True:
                now = time.time()
                if self._heap:
                    available_at, _, stats = heapq.heappop(self._heap)
                    if available_at > now:
                        heapq.heappush(self._heap, (available_at, next(self._counter), stats))
                        wait_for = available_at - now
                        if timeout is not None:
                            remaining = deadline - now
                            if remaining <= 0:
                                raise ProxyAcquireTimeout("Timed out waiting for available proxy.")
                            self._cv.wait(min(wait_for, remaining))
                        else:
                            self._cv.wait(wait_for)
                        continue
                    if stats.in_use:
                        continue
                    with self._lock:
                        stats.in_use = True
                        stats.assigned_at = now
                        stats.total_sessions += 1
                    lease = ProxyLease(self, stats)
                    event = {"type": "acquire", "proxy": stats.label, "index": stats.index}
                    break

                wait_for = 0.5
                if timeout is not None:
                    remaining = deadline - now
                    if remaining <= 0:
                        raise ProxyAcquireTimeout("Timed out waiting for available proxy.")
                    wait_for = min(wait_for, remaining)
                self._cv.wait(wait_for)

        if event:
            self._emit(event)
        if lease is None:
            raise ProxyAcquireTimeout("Failed to acquire proxy.")
        return lease

    def release(self, stats: ProxyStats) -> None:
        event: Optional[dict] = None
        with self._cv:
            with self._lock:
                stats.in_use = False
                cooldown = self._compute_cooldown(stats)
                available_at = time.time() + cooldown
                event = {
                    "type": "release",
                    "proxy": stats.label,
                    "cooldown": cooldown,
                    "index": stats.index,
                }
            self._push(stats, available_at)
        if event:
            self._emit(event)

    # ------------------------------------------------------------------ #
    # TCP connection handling
    # ------------------------------------------------------------------ #
    def open_tcp(self, stats: ProxyStats, host: str, port: int, timeout: float) -> socket.socket:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((stats.host, stats.port))
        except OSError as exc:
            sock.close()
            self._record_proxy_failure(stats, "connect", f"{exc}")
            raise ProxyHandshakeError(f"{stats.label} connection failed: {exc}") from exc

        try:
            sock.sendall(b"\x05\x01\x00")
            resp = self._recv_exact(sock, 2)
            if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
                raise ProxyHandshakeError("SOCKS5 authentication rejected.")

            request = self._build_connect_request(host, port)
            sock.sendall(request)
            header = self._recv_exact(sock, 4)
            if len(header) < 4:
                raise ProxyHandshakeError("SOCKS5 response truncated.")
            rep = header[1]
            atyp = header[3]
            self._consume_bound_address(sock, atyp)
            if rep != 0x00:
                msg = self._decode_rep(rep)
                self._record_target_failure(stats, msg)
                sock.close()
                raise ProxyTargetError(rep, msg)
        except ProxyTargetError:
            raise
        except Exception as exc:
            sock.close()
            self._record_proxy_failure(stats, "handshake", f"{exc}")
            raise ProxyHandshakeError(f"{stats.label} handshake failed: {exc}") from exc

        latency_ms = (time.perf_counter() - start) * 1000.0
        self._record_success(stats, latency_ms)
        return sock

    # ------------------------------------------------------------------ #
    # Health reporting
    # ------------------------------------------------------------------ #
    def health_snapshot(self) -> List[dict]:
        now = time.time()
        with self._lock:
            snapshot = []
            for stats in self._stats:
                snapshot.append(
                    {
                        "label": stats.label,
                        "index": stats.index,
                        "in_use": stats.in_use,
                        "cooldown": max(0.0, stats.cooldown_until - now),
                        "successes": stats.successes,
                        "proxy_failures": stats.proxy_failures,
                        "target_failures": stats.target_failures,
                        "consecutive_proxy_failures": stats.consecutive_proxy_failures,
                        "last_latency_ms": stats.last_latency_ms,
                        "last_error": stats.last_error,
                        "last_stage": stats.last_stage,
                    }
                )
            return snapshot

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _push(self, stats: ProxyStats, available_at: float) -> None:
        stats.cooldown_until = available_at
        heapq.heappush(self._heap, (available_at, next(self._counter), stats))
        self._cv.notify()

    def _emit(self, event: dict) -> None:
        if not self._event_callback:
            return
        try:
            self._event_callback(dict(event))
        except Exception:
            pass

    def _record_success(self, stats: ProxyStats, latency_ms: float) -> None:
        with self._lock:
            stats.successes += 1
            stats.last_latency_ms = latency_ms
            stats.last_stage = "success"
            stats.last_error = None
            stats.consecutive_proxy_failures = 0
        self._emit(
            {
                "type": "success",
                "proxy": stats.label,
                "latency_ms": latency_ms,
                "index": stats.index,
            }
        )

    def _record_proxy_failure(self, stats: ProxyStats, stage: str, message: str) -> None:
        with self._lock:
            stats.proxy_failures += 1
            stats.consecutive_proxy_failures += 1
            stats.last_error = message
            stats.last_stage = stage
        self._emit(
            {
                "type": "proxy-failure",
                "proxy": stats.label,
                "stage": stage,
                "error": message,
                "index": stats.index,
            }
        )

    def _record_target_failure(self, stats: ProxyStats, message: str) -> None:
        with self._lock:
            stats.target_failures += 1
            stats.last_error = message
            stats.last_stage = "target"
        self._emit(
            {
                "type": "target-failure",
                "proxy": stats.label,
                "error": message,
                "index": stats.index,
            }
        )

    def _compute_cooldown(self, stats: ProxyStats) -> float:
        consecutive = stats.consecutive_proxy_failures
        if consecutive <= 0:
            return 0.05
        return min(30.0, 1.5 ** min(consecutive, 8))

    @staticmethod
    def _recv_exact(sock: socket.socket, length: int) -> bytes:
        buf = bytearray()
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                raise ProxyHandshakeError("Unexpected EOF during SOCKS5 exchange.")
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _build_connect_request(host: str, port: int) -> bytes:
        atyp = 0x03
        payload: bytes
        try:
            payload = socket.inet_aton(host)
            atyp = 0x01
        except OSError:
            try:
                payload = socket.inet_pton(socket.AF_INET6, host)
                atyp = 0x04
            except OSError:
                encoded = host.encode("idna")
                if len(encoded) > 255:
                    encoded = encoded[:255]
                payload = bytes([len(encoded)]) + encoded
        return b"\x05\x01\x00" + bytes([atyp]) + payload + port.to_bytes(2, "big", signed=False)

    @classmethod
    def _consume_bound_address(cls, sock: socket.socket, atyp: int) -> None:
        if atyp == 0x01:
            cls._recv_exact(sock, 4)
        elif atyp == 0x04:
            cls._recv_exact(sock, 16)
        elif atyp == 0x03:
            length = cls._recv_exact(sock, 1)[0]
            if length:
                cls._recv_exact(sock, length)
        else:
            raise ProxyHandshakeError(f"Unsupported ATYP {atyp}")
        cls._recv_exact(sock, 2)  # bound port

    @staticmethod
    def _decode_rep(code: int) -> str:
        mapping = {
            0x01: "General SOCKS server failure",
            0x02: "Connection not allowed by ruleset",
            0x03: "Network unreachable",
            0x04: "Host unreachable",
            0x05: "Connection refused by target host",
            0x06: "TTL expired",
            0x07: "Command not supported",
            0x08: "Address type not supported",
        }
        return mapping.get(code, f"Proxy reported error code {code}")

