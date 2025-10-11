"""SOCKS5 proxy rotation and health tracking helpers."""

from __future__ import annotations

import concurrent.futures
import http.client
import heapq
import itertools
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import ssl
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.error import URLError
from urllib.parse import urlsplit

from . import constants as const

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore

__all__ = [
    "ProxyError",
    "ProxyAcquireTimeout",
    "ProxyHandshakeError",
    "ProxyTargetError",
    "ProxyStats",
    "ProxyLease",
    "ProxyPool",
    "ProxyEvent",
    "ProxyEventBuffer",
    "emit_event",
    "get_event_buffer",
    "make_connector",
]

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

FAIL_QUARANTINE_THRESHOLD = 3
FAIL_DISABLE_THRESHOLD = 6
BASE_QUARANTINE_SECONDS = 5.0
MAX_QUARANTINE_SECONDS = 180.0
HARD_DISABLE_SECONDS = 300.0

HEALTH_TTL_SECONDS = const.PROXY_HEALTH_TTL_SECONDS
DEFAULT_HEALTH_TIMEOUT = const.PROXY_HEALTH_TIMEOUT
DEFAULT_HEALTH_THREADS = const.PROXY_HEALTH_THREADS
DEFAULT_HEALTH_URL = os.getenv("MULLVAD_CHECK_URL", "https://am.i.mullvad.net/json")

BASELINE_PROXIES: Sequence[Tuple[str, int]] = (
    ("10.64.0.1", 1080),
    ("10.8.0.1", 1080),
)


@dataclass(frozen=True)
class ProxyEvent:
    """Immutable record describing a proxy event."""

    timestamp: float
    level: str
    type: str
    message: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        data = dict(self.extra)
        data.setdefault("timestamp", self.timestamp)
        data.setdefault("level", self.level)
        data.setdefault("type", self.type)
        data.setdefault("message", self.message)
        return data


class ProxyEventBuffer:
    """Thread-safe ring buffer of :class:ProxyEvent objects."""

    def __init__(self, capacity: int) -> None:
        self._capacity = max(1, capacity)
        self._events: Deque[ProxyEvent] = deque(maxlen=self._capacity)
        self._lock = threading.RLock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def append(self, event: ProxyEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(
        self,
        *,
        level_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[ProxyEvent]:
        with self._lock:
            events = list(self._events)
        if level_filter:
            lf = level_filter.lower()
            if lf == "ok":
                allowed = {"INFO", "SUCCESS"}
                events = [event for event in events if event.level in allowed]
            elif lf == "errors":
                allowed = {"ERROR", "WARN"}
                events = [event for event in events if event.level in allowed]
        if search:
            needle = search.lower()
            filtered: List[ProxyEvent] = []
            for event in events:
                if needle in event.message.lower() or needle in event.type.lower():
                    filtered.append(event)
                    continue
                for value in event.extra.values():
                    if value is None:
                        continue
                    if needle in str(value).lower():
                        filtered.append(event)
                        break
            events = filtered
        if limit is not None and limit > 0 and len(events) > limit:
            events = events[-limit:]
        return events


_event_buffer = ProxyEventBuffer(const.PROXY_LOG_CAPACITY)

_event_logger = logging.getLogger("mcsmartscan.proxy.events")
_event_logger.setLevel(logging.INFO)
_event_logger.addHandler(logging.NullHandler())
_event_logger.propagate = False
if const.PROXY_LOG_FILE_DIR:
    try:
        log_dir = Path(const.PROXY_LOG_FILE_DIR).expanduser()
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_dir / "proxy-events.log",
            maxBytes=const.PROXY_EVENT_FILE_MAX_BYTES,
            backupCount=const.PROXY_EVENT_FILE_BACKUPS,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _event_logger.addHandler(handler)
    except Exception:  # pragma: no cover - configuration issue
        logger.exception("Failed to configure proxy event file logging.")



def emit_event(level: str, type_: str, message: str, **extra: Any) -> ProxyEvent:
    """Create and record a proxy event."""

    level_norm = level.upper()
    extra_dict = dict(extra)
    event = ProxyEvent(time.time(), level_norm, type_, message, extra_dict)
    _event_buffer.append(event)
    try:
        extra_str = ""
        if extra_dict:
            try:
                extra_str = " | " + json.dumps(extra_dict, default=str, ensure_ascii=False)
            except Exception:
                extra_str = " | " + str(extra_dict)
        log_method = {
            "ERROR": _event_logger.error,
            "WARN": _event_logger.warning,
            "WARNING": _event_logger.warning,
            "SUCCESS": _event_logger.info,
            "INFO": _event_logger.info,
            "DEBUG": _event_logger.debug,
        }.get(level_norm, _event_logger.info)
        log_method("%s: %s%s", type_, message, extra_str)
    except Exception:  # pragma: no cover - logging failures shouldn't break callers
        pass
    return event



def get_event_buffer() -> ProxyEventBuffer:
    """Return the global proxy event buffer."""

    return _event_buffer


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
    last_success_ts: float = 0.0
    last_failure_ts: float = 0.0
    quarantine_until: float = 0.0
    disabled_until: float = 0.0
    disabled_reason: Optional[str] = None
    health_inflight: bool = False
    health_last_probe_ts: float = 0.0
    health_last_success_ts: float = 0.0
    health_last_failure_ts: float = 0.0
    health_latency_ms: Optional[float] = None
    health_ok: bool = False
    health_exit_ip: Optional[str] = None
    health_exit_country: Optional[str] = None
    health_exit_server_type: Optional[str] = None
    health_payload: Optional[Dict[str, Any]] = None
    health_failures: int = 0
    health_successes: int = 0

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
        self._health_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=DEFAULT_HEALTH_THREADS,
            thread_name_prefix="socks-health",
        )
        self._health_timeout = DEFAULT_HEALTH_TIMEOUT
        self._health_target = self._parse_health_url(DEFAULT_HEALTH_URL)
        self._mullvad_connected = True
        self._closed = False

        for idx, (host, port) in enumerate(proxies):
            stats = ProxyStats(host=host, port=port, index=idx)
            self._stats.append(stats)
            with self._cv:
                self._push(stats, available_at=0.0)

        emit_event(
            "INFO",
            "pool-init",
            f"Proxy pool initialised with {len(self._stats)} endpoints",
            total=len(self._stats),
        )

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
        seen: set[Tuple[str, int]] = set()
        for host, port in BASELINE_PROXIES:
            if (host, port) not in seen:
                proxies.append((host, port))
                seen.add((host, port))

        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            emit_event("WARN", "proxy-file-missing", f"Proxy list missing: {path}")
        except Exception as exc:
            emit_event("ERROR", "proxy-file-error", f"Failed to read proxy list: {exc}", path=str(path))
        else:
            for raw in text.splitlines():
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
                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)
                proxies.append(key)
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
            return sum(
                1
                for _, _, stats in self._heap
                if not stats.in_use
                and stats.cooldown_until <= now
                and stats.quarantine_until <= now
                and stats.disabled_until <= now
            )

    @property
    def mullvad_connected(self) -> bool:
        return self._mullvad_connected

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def prepare_for_run(self) -> None:
        with self._cv:
            self._heap.clear()
            with self._lock:
                for stats in self._stats:
                    stats.consecutive_proxy_failures = 0
                    stats.last_error = None
                    stats.last_stage = None
                    stats.last_latency_ms = None
                    stats.last_success_ts = 0.0
                    stats.quarantine_until = 0.0
                    stats.disabled_until = 0.0
                    stats.disabled_reason = None
                    stats.cooldown_until = 0.0
                    stats.in_use = False
                    stats.health_inflight = False
                    stats.health_last_probe_ts = 0.0
                    stats.health_last_success_ts = 0.0
                    stats.health_last_failure_ts = 0.0
                    stats.health_latency_ms = None
                    stats.health_ok = False
                    stats.health_exit_ip = None
                    stats.health_exit_country = None
                    stats.health_exit_server_type = None
                    stats.health_payload = None
                    stats.health_failures = 0
                    stats.health_successes = 0
            for stats in self._stats:
                self._push(stats, available_at=0.0)
                self._ensure_health_probe(stats, force=True)

    def shutdown(self, wait: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        self._health_executor.shutdown(wait=wait)
        emit_event("INFO", "pool-shutdown", "Proxy pool shutdown")

    # ------------------------------------------------------------------ #
    # Mullvad awareness
    # ------------------------------------------------------------------ #
    def set_mullvad_connected(self, connected: Optional[bool]) -> None:
        if connected is None:
            return
        new_state = bool(connected)
        if new_state == self._mullvad_connected:
            return
        self._mullvad_connected = new_state
        message = "Mullvad connected" if new_state else "Mullvad disconnected"
        level = "SUCCESS" if new_state else "WARN"
        self._emit({"type": "mullvad-status", "connected": new_state}, level=level, message=message)

    # ------------------------------------------------------------------ #
    # Acquisition and release
    # ------------------------------------------------------------------ #
    def acquire(self, timeout: Optional[float] = None) -> ProxyLease:
        deadline = None if timeout is None else time.time() + timeout
        with self._cv:
            while True:
                if self._closed:
                    raise ProxyAcquireTimeout("Proxy pool has been shut down.")
                now = time.time()
                if self._heap:
                    _, _, stats = heapq.heappop(self._heap)
                    effective_at = max(stats.cooldown_until, stats.quarantine_until, stats.disabled_until)
                    if stats.in_use or effective_at > now:
                        self._push(stats, available_at=effective_at)
                        wait_for = max(0.0, effective_at - now)
                        if timeout is not None:
                            remaining = deadline - now
                            if remaining <= 0:
                                raise ProxyAcquireTimeout("Timed out waiting for available proxy.")
                            wait_for = min(wait_for if wait_for > 0 else 0.05, remaining)
                        else:
                            wait_for = wait_for if wait_for > 0 else 0.05
                        self._cv.wait(wait_for)
                        continue
                    with self._lock:
                        stats.in_use = True
                        stats.assigned_at = now
                        stats.total_sessions += 1
                        if stats.disabled_until <= now:
                            stats.disabled_reason = None
                        needs_probe = self._needs_health_refresh(stats, now)
                    lease = ProxyLease(self, stats)
                    self._emit(
                        {"type": "acquire", "proxy": stats.label, "index": stats.index},
                        level="INFO",
                        message=f"Lease acquired for {stats.label}",
                    )
                    if needs_probe:
                        self._ensure_health_probe(stats)
                    return lease

                wait_for = 0.5
                if timeout is not None:
                    remaining = deadline - now
                    if remaining <= 0:
                        raise ProxyAcquireTimeout("Timed out waiting for available proxy.")
                    wait_for = min(wait_for, remaining)
                self._cv.wait(wait_for)

    def release(self, stats: ProxyStats) -> None:
        with self._cv:
            with self._lock:
                stats.in_use = False
                now = time.time()
                cooldown = self._compute_cooldown(stats)
                available_at = now + cooldown
                event = {
                    "type": "release",
                    "proxy": stats.label,
                    "cooldown": cooldown,
                    "index": stats.index,
                    "quarantine": max(0.0, stats.quarantine_until - now),
                    "disabled": max(0.0, stats.disabled_until - now),
                }
            self._push(stats, available_at)
        self._emit(event, level="INFO", message=f"Lease released for {stats.label}")
        if not stats.health_ok:
            self._ensure_health_probe(stats)

    # ------------------------------------------------------------------ #
    # TCP connection handling
    # ------------------------------------------------------------------ #
    def open_tcp(self, stats: ProxyStats, host: str, port: int, timeout: float) -> socket.socket:
        sock, _ = self._connect_via_proxy(stats, host, port, timeout, record_metrics=True)
        return sock

    def _connect_via_proxy(
        self,
        stats: ProxyStats,
        host: str,
        port: int,
        timeout: float,
        *,
        record_metrics: bool,
    ) -> Tuple[socket.socket, float]:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        try:
            sock.connect((stats.host, stats.port))
        except OSError as exc:
            sock.close()
            detail = str(exc)
            self._record_proxy_failure(stats, "connect", detail)
            self._ensure_health_probe(stats, force=True)
            raise ProxyHandshakeError(f"{stats.label} connection failed: {detail}") from exc

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
                self._ensure_health_probe(stats)
                sock.close()
                raise ProxyTargetError(rep, msg)
        except ProxyTargetError:
            raise
        except Exception as exc:
            sock.close()
            detail = str(exc)
            self._record_proxy_failure(stats, "handshake", detail)
            self._ensure_health_probe(stats, force=True)
            raise ProxyHandshakeError(f"{stats.label} handshake failed: {detail}") from exc

        latency_ms = (time.perf_counter() - start) * 1000.0
        if record_metrics:
            self._record_success(stats, latency_ms)
        return sock, latency_ms

    def get_requests_session(self, country: Optional[str] = None):
        if requests is None:
            raise RuntimeError("requests[socks] is required for proxy sessions.")
        stats = self._select_session_proxy(country)
        session = requests.Session()
        if stats is not None:
            proxy_url = f"socks5h://{stats.host}:{stats.port}"
            session.proxies.update({"http": proxy_url, "https": proxy_url})
            emit_event(
                "INFO",
                "session-proxy",
                f"Requests session pinned to {stats.label}",
                proxy=stats.label,
                country_filter=country,
            )
        else:
            emit_event("WARN", "session-proxy-miss", "No proxy available for requests session", country_filter=country)
        return session
    # ------------------------------------------------------------------ #
    # Health reporting
    # ------------------------------------------------------------------ #
    def snapshot_health(self) -> List[dict]:
        now = time.time()
        snapshot: List[dict] = []
        with self._lock:
            for stats in self._stats:
                disabled_for = max(0.0, stats.disabled_until - now)
                quarantine_for = max(0.0, stats.quarantine_until - now)
                cooldown_for = max(0.0, stats.cooldown_until - now)
                status = "OK"
                if disabled_for > 0:
                    status = "Disabled"
                elif quarantine_for > 0:
                    status = "Quarantine"
                health_fresh = self._is_health_fresh(stats, now)
                health_ok = stats.health_ok and health_fresh
                entry = {
                    "label": stats.label,
                    "index": stats.index,
                    "in_use": stats.in_use,
                    "status": status,
                    "cooldown": cooldown_for,
                    "quarantine": quarantine_for,
                    "disabled": disabled_for,
                    "disabled_reason": stats.disabled_reason,
                    "successes": stats.successes,
                    "proxy_failures": stats.proxy_failures,
                    "target_failures": stats.target_failures,
                    "consecutive_proxy_failures": stats.consecutive_proxy_failures,
                    "last_latency_ms": stats.last_latency_ms,
                    "last_error": stats.last_error,
                    "last_stage": stats.last_stage,
                    "last_success_ts": stats.last_success_ts,
                    "last_failure_ts": stats.last_failure_ts,
                    "total_sessions": stats.total_sessions,
                    "health_ok": health_ok,
                    "health_latency_ms": stats.health_latency_ms,
                    "health_fresh": health_fresh,
                    "health_last_probe_ts": stats.health_last_probe_ts,
                    "health_last_success_ts": stats.health_last_success_ts,
                    "health_last_failure_ts": stats.health_last_failure_ts,
                    "health_exit_ip": stats.health_exit_ip,
                    "health_exit_country": stats.health_exit_country,
                    "health_exit_server_type": stats.health_exit_server_type,
                    "pool_mullvad_connected": self._mullvad_connected,
                }
                snapshot.append(entry)
        return snapshot

    def health_snapshot(self) -> List[dict]:
        return self.snapshot_health()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _emit(self, event: Dict[str, Any], *, level: str = "INFO", message: Optional[str] = None) -> None:
        event_dict = dict(event)
        event_type = event_dict.setdefault("type", "event")
        event_dict.setdefault("timestamp", time.time())
        level_norm = level.upper()
        event_dict["level"] = level_norm
        if message is None:
            message = event_dict.get("message") or event_type
        event_dict["message"] = message
        extra = {
            key: value
            for key, value in event_dict.items()
            if key not in {"type", "timestamp", "level", "message"}
        }
        emit_event(level_norm, event_type, message, **extra)
        callback = self._event_callback
        if callback:
            try:
                callback(dict(event_dict))
            except Exception:  # pragma: no cover - UI callback issues shouldn't crash the pool
                logger.exception("Proxy event callback failed.")

    def _record_success(self, stats: ProxyStats, latency_ms: float) -> None:
        now = time.time()
        restored = False
        with self._lock:
            stats.successes += 1
            stats.last_latency_ms = latency_ms
            stats.last_stage = "success"
            stats.last_error = None
            stats.consecutive_proxy_failures = 0
            if stats.quarantine_until > now or stats.disabled_until > now:
                restored = True
            stats.quarantine_until = 0.0
            stats.disabled_until = 0.0
            stats.disabled_reason = None
            stats.last_success_ts = now
        self._emit(
            {
                "type": "success",
                "proxy": stats.label,
                "latency_ms": latency_ms,
                "index": stats.index,
            },
            level="SUCCESS",
            message=f"{stats.label} handshake OK ({latency_ms:.1f} ms)",
        )
        if restored:
            self._emit(
                {"type": "proxy-restored", "proxy": stats.label, "index": stats.index},
                level="SUCCESS",
                message=f"{stats.label} restored to pool",
            )

    def _record_proxy_failure(self, stats: ProxyStats, stage: str, detail: str) -> None:
        now = time.time()
        with self._lock:
            stats.proxy_failures += 1
            stats.consecutive_proxy_failures += 1
            stats.last_error = detail
            stats.last_stage = stage
            stats.last_failure_ts = now
            penalty_events = self._apply_failure_penalty(stats, now)
        self._emit(
            {
                "type": "proxy-failure",
                "proxy": stats.label,
                "stage": stage,
                "error": detail,
                "index": stats.index,
            },
            level="ERROR",
            message=f"{stats.label} failure during {stage}: {detail}",
        )
        for event in penalty_events:
            level = "WARN" if event.get("type") == "proxy-quarantine" else "ERROR"
            message = self._format_penalty_message(event, stats)
            self._emit(event, level=level, message=message)

    def _record_target_failure(self, stats: ProxyStats, detail: str) -> None:
        with self._lock:
            stats.target_failures += 1
            stats.last_error = detail
            stats.last_stage = "target"
        self._emit(
            {
                "type": "target-failure",
                "proxy": stats.label,
                "error": detail,
                "index": stats.index,
            },
            level="WARN",
            message=f"{stats.label} target error: {detail}",
        )

    def _compute_cooldown(self, stats: ProxyStats) -> float:
        consecutive = stats.consecutive_proxy_failures
        if consecutive <= 0:
            return 0.05
        return min(30.0, 1.5 ** min(consecutive, 8))

    def _health_priority_penalty(self, stats: ProxyStats, now: float) -> float:
        if stats.in_use:
            return 0.0
        if stats.disabled_until > now or stats.quarantine_until > now:
            return 0.0
        if stats.health_ok and self._is_health_fresh(stats, now):
            return 0.0
        if stats.health_ok:
            return 0.05
        if stats.health_last_failure_ts > 0 and (now - stats.health_last_failure_ts) <= HEALTH_TTL_SECONDS:
            return 0.25
        if stats.health_last_probe_ts <= 0:
            return 0.1
        return 0.15

    def _is_health_fresh(self, stats: ProxyStats, now: Optional[float] = None) -> bool:
        ts_now = now if now is not None else time.time()
        return stats.health_last_probe_ts > 0 and (ts_now - stats.health_last_probe_ts) <= HEALTH_TTL_SECONDS

    def _needs_health_refresh(self, stats: ProxyStats, now: Optional[float] = None) -> bool:
        ts_now = now if now is not None else time.time()
        if stats.health_inflight:
            return False
        if stats.disabled_until > ts_now:
            return False
        if stats.health_last_probe_ts <= 0:
            return True
        if (ts_now - stats.health_last_probe_ts) >= HEALTH_TTL_SECONDS:
            return True
        if not stats.health_ok:
            return True
        return False

    def _ensure_health_probe(self, stats: ProxyStats, *, force: bool = False) -> None:
        if self._closed:
            return
        if not force and not self._needs_health_refresh(stats):
            return
        with self._lock:
            if stats.health_inflight:
                return
            stats.health_inflight = True
        self._emit(
            {"type": "health-start", "proxy": stats.label, "index": stats.index},
            level="INFO",
            message=f"Health probe started for {stats.label}",
        )
        self._health_executor.submit(self._run_health_probe, stats)

    def _requeue_for_health(self, stats: ProxyStats) -> None:
        if stats.in_use or self._closed:
            return
        with self._cv:
            self._push(stats, available_at=stats.cooldown_until)
    def _run_health_probe(self, stats: ProxyStats) -> None:
        if self._closed:
            return
        target = self._health_target
        host = target["host"]
        port = int(target["port"])
        path = target["path"]
        scheme = target["scheme"]

        payload: Dict[str, Any] = {}
        latency_ms: Optional[float] = None
        ok = False
        error_text: Optional[str] = None
        response: Optional[http.client.HTTPResponse] = None
        stream: Optional[socket.socket] = None
        probe_start = time.perf_counter()

        try:
            sock, _ = self._connect_via_proxy(
                stats,
                host,
                port,
                self._health_timeout,
                record_metrics=False,
            )
            stream = sock
            try:
                stream.settimeout(self._health_timeout)
            except OSError:
                pass
            if scheme == "https":
                try:
                    context = ssl.create_default_context()
                    stream = context.wrap_socket(stream, server_hostname=host)
                except Exception as exc:  # pragma: no cover - SSL edge cases
                    error_text = f"TLS failed: {exc}"
                    self._record_proxy_failure(stats, "health", error_text)
                    try:
                        sock.close()
                    except Exception:
                        pass
                    stream = None
            if stream is not None:
                try:
                    request_bytes = (
                        f"GET {path or '/'} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "User-Agent: mcsmartscan/1.0\r\n"
                        "Accept: application/json\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii", "ignore")
                    stream.sendall(request_bytes)
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    body = response.read()
                    status_code = response.status
                    if status_code != 200:
                        raise RuntimeError(f"Health endpoint HTTP {status_code}")
                    try:
                        payload = json.loads(body.decode("utf-8", "replace"))
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(f"Invalid JSON: {exc}") from exc
                    latency_ms = (time.perf_counter() - probe_start) * 1000.0
                    ok = bool(isinstance(payload, dict) and payload.get("mullvad_exit_ip"))
                    if not ok:
                        error_text = "Mullvad exit flag false"
                        self._record_proxy_failure(stats, "health", error_text)
                except ProxyTargetError as exc:
                    error_text = str(exc)
                except (OSError, URLError, RuntimeError, ValueError) as exc:
                    error_text = str(exc)
                    self._record_proxy_failure(stats, "health", error_text)
        except (ProxyError, OSError) as exc:
            error_text = str(exc)
        finally:
            if latency_ms is None:
                latency_ms = (time.perf_counter() - probe_start) * 1000.0
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
            with self._lock:
                stats.health_inflight = False
                stats.health_last_probe_ts = time.time()
                if ok:
                    stats.health_ok = True
                    stats.health_successes += 1
                    stats.health_latency_ms = latency_ms
                    stats.health_last_success_ts = stats.health_last_probe_ts
                    if isinstance(payload, dict):
                        stats.health_exit_ip = str(payload.get("ip")) if payload.get("ip") else None
                        stats.health_exit_country = payload.get("country") or None
                        stats.health_exit_server_type = payload.get("mullvad_server_type") or None
                        stats.health_payload = payload
                    else:
                        stats.health_payload = None
                        stats.health_exit_ip = None
                        stats.health_exit_country = None
                        stats.health_exit_server_type = None
                    stats.health_failures = 0
                else:
                    stats.health_ok = False
                    stats.health_failures += 1
                    stats.health_last_failure_ts = stats.health_last_probe_ts
                    if latency_ms is not None:
                        stats.health_latency_ms = latency_ms
                    if payload:
                        stats.health_payload = payload if isinstance(payload, dict) else None
            event_level = "SUCCESS" if ok else "ERROR"
            if ok:
                latency_display = f"{latency_ms:.1f} ms" if latency_ms is not None else "-"
                message = f"{stats.label} health OK ({latency_display})"
            else:
                message = f"{stats.label} health failed: {error_text or 'unknown error'}"
            self._emit(
                {
                    "type": "health",
                    "proxy": stats.label,
                    "index": stats.index,
                    "ok": ok,
                    "latency_ms": latency_ms,
                    "exit_ip": payload.get("ip") if isinstance(payload, dict) else None,
                    "country": payload.get("country") if isinstance(payload, dict) else None,
                    "server_type": payload.get("mullvad_server_type") if isinstance(payload, dict) else None,
                    "error": error_text,
                },
                level=event_level,
                message=message,
            )
            self._requeue_for_health(stats)

    def _apply_failure_penalty(self, stats: ProxyStats, now: float) -> List[dict]:
        events: List[dict] = []
        consecutive = stats.consecutive_proxy_failures
        if consecutive >= FAIL_QUARANTINE_THRESHOLD:
            exponent = max(0, consecutive - FAIL_QUARANTINE_THRESHOLD)
            duration = min(MAX_QUARANTINE_SECONDS, BASE_QUARANTINE_SECONDS * (2 ** exponent))
            if stats.quarantine_until < now + duration:
                stats.quarantine_until = now + duration
                events.append(
                    {
                        "type": "proxy-quarantine",
                        "proxy": stats.label,
                        "index": stats.index,
                        "duration": duration,
                        "until": stats.quarantine_until,
                        "consecutive": consecutive,
                    }
                )
        if (
            stats.successes == 0
            and stats.total_sessions >= FAIL_DISABLE_THRESHOLD
            and stats.proxy_failures >= FAIL_DISABLE_THRESHOLD
        ):
            disable_until = now + HARD_DISABLE_SECONDS
            if stats.disabled_until < disable_until:
                stats.disabled_until = disable_until
                stats.disabled_reason = f"{stats.proxy_failures} failures without success"
                events.append(
                    {
                        "type": "proxy-disabled",
                        "proxy": stats.label,
                        "index": stats.index,
                        "duration": HARD_DISABLE_SECONDS,
                        "until": stats.disabled_until,
                        "reason": stats.disabled_reason,
                    }
                )
        return events

    @staticmethod
    def _format_penalty_message(event: Dict[str, Any], stats: ProxyStats) -> str:
        event_type = event.get("type")
        if event_type == "proxy-quarantine":
            duration = float(event.get("duration") or 0.0)
            consecutive = event.get("consecutive")
            return f"{stats.label} quarantined for {duration:.1f}s after {consecutive} failures"
        if event_type == "proxy-disabled":
            duration = float(event.get("duration") or 0.0)
            reason = event.get("reason") or "cool-off"
            return f"{stats.label} disabled for {duration:.0f}s ({reason})"
        return f"{stats.label} event {event_type}"

    def _push(self, stats: ProxyStats, available_at: float) -> None:
        ready_at = max(available_at, stats.quarantine_until, stats.disabled_until)
        stats.cooldown_until = ready_at
        priority = ready_at + self._health_priority_penalty(stats, time.time())
        heapq.heappush(self._heap, (priority, next(self._counter), stats))
        self._cv.notify()

    def _select_session_proxy(self, country: Optional[str]) -> Optional[ProxyStats]:
        now = time.time()
        country_norm = country.lower() if country else None
        with self._lock:

            def usable(stat: ProxyStats) -> bool:
                return (
                    not stat.in_use
                    and stat.disabled_until <= now
                    and stat.quarantine_until <= now
                )

            healthy = [
                stat
                for stat in self._stats
                if usable(stat) and stat.health_ok and self._is_health_fresh(stat, now)
            ]
            if country_norm:
                healthy_country = [
                    stat
                    for stat in healthy
                    if (stat.health_exit_country or "").lower() == country_norm
                ]
            else:
                healthy_country = []

            def sort_key(stat: ProxyStats) -> Tuple[float, int]:
                latency = stat.health_latency_ms if stat.health_latency_ms is not None else float("inf")
                return (latency, stat.index)

            pool: List[ProxyStats]
            if healthy_country:
                pool = healthy_country
            elif healthy:
                pool = healthy
            else:
                pool = [stat for stat in self._stats if usable(stat)]
            if not pool:
                return None
            pool.sort(key=sort_key)
            candidate = pool[0]
            if not self._is_health_fresh(candidate, now):
                self._ensure_health_probe(candidate)
            return candidate

    @staticmethod
    def _parse_health_url(url: str) -> Dict[str, Any]:
        parts = urlsplit(url)
        scheme = (parts.scheme or "https").lower()
        host = parts.hostname or "am.i.mullvad.net"
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if scheme not in {"http", "https"}:
            scheme = "https"
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return {"scheme": scheme, "host": host, "port": port, "path": path}

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
        cls._recv_exact(sock, 2)

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

def make_connector(pool: ProxyPool, timeout: float) -> Callable[[str, int, Optional[float]], socket.socket]:
    """Return a connector that leases a proxy, performs CONNECT, and returns the socket."""

    def _connector(host: str, port: int, connect_timeout: Optional[float] = None) -> socket.socket:
        effective_timeout = connect_timeout if connect_timeout is not None else timeout
        lease = pool.acquire(timeout=effective_timeout)
        try:
            sock = lease.connector(host, port, effective_timeout)
        except (ProxyHandshakeError, ProxyTargetError) as exc:
            emit_event(
                "ERROR",
                "connector-error",
                f"Connector via proxy failed: {exc}",
                proxy=lease.label,
                host=host,
                port=port,
            )
            lease.close()
            raise
        except Exception as exc:  # pragma: no cover - unexpected
            emit_event(
                "ERROR",
                "connector-error",
                f"Unexpected connector error: {exc}",
                proxy=lease.label,
                host=host,
                port=port,
            )
            lease.close()
            raise

        close_lock = threading.Lock()
        released = False
        original_close = sock.close

        def _close_with_release() -> None:
            nonlocal released
            with close_lock:
                if released:
                    return
                released = True
            try:
                original_close()
            finally:
                lease.close()

        sock.close = _close_with_release  # type: ignore[assignment]
        weakref.finalize(sock, lease.close)
        return sock

    return _connector


if __name__ == "__main__":  # pragma: no cover - debug helper
    pool_path = Path(__file__).with_name("mullvadproxyips.txt")
    pool = ProxyPool.from_file(pool_path)
    try:
        pool.prepare_for_run()
        time.sleep(0.1)
        for stat in list(pool._stats):
            pool._ensure_health_probe(stat, force=True)
        time.sleep(2.5)
        snapshot = pool.snapshot_health()
        healthy = sum(1 for item in snapshot if item.get("health_ok"))
        total = len(snapshot)
        print(f"[SELF-CHECK] Healthy {healthy} / {total} proxies")
        for event in get_event_buffer().snapshot(limit=5):
            ts = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            print(f" {ts} [{event.level}] {event.type}: {event.message}")
    finally:
        pool.shutdown(wait=False)
