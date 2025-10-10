"""Mullvad VPN management helpers."""

from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

LogFn = Callable[[str, str], None]
CtlFn = Callable[[str], None]
UIFn = Callable[[Callable, tuple, dict], None]
StatusHook = Callable[[Dict[str, object]], None]


@dataclass
class MullvadStatus:
    cli_path: Optional[str] = None
    last_cycle: float = 0.0
    last_error: Optional[str] = None
    last_output: List[str] = field(default_factory=list)
    is_active: bool = False
    auto_enabled: bool = False
    connected: Optional[bool] = None
    connection_info: Dict[str, object] = field(default_factory=dict)
    last_status_poll: float = 0.0
    errors: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "cli_path": self.cli_path,
            "last_cycle": self.last_cycle,
            "last_error": self.last_error,
            "last_output": list(self.last_output),
            "is_active": self.is_active,
            "auto_enabled": self.auto_enabled,
            "connected": self.connected,
            "connection_info": dict(self.connection_info),
            "last_status_poll": self.last_status_poll,
            "errors": dict(self.errors),
        }


class MullvadManager:
    """Background helper that owns Mullvad CLI cycling logic."""

    def __init__(
        self,
        *,
        log_fn: LogFn,
        ctl_fn: CtlFn,
        ui_dispatch: UIFn,
        status_hook: Optional[StatusHook] = None,
        interval: int = 120,
    ) -> None:
        self.log_fn = log_fn
        self.ctl_fn = ctl_fn
        self.ui_dispatch = ui_dispatch
        self.status_hook = status_hook
        self.interval = max(10, int(interval))

        self._path = shutil.which("mullvad")
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._enabled = threading.Event()
        self._force = threading.Event()
        self._active = False

        self._lock = threading.RLock()
        self._status = MullvadStatus(cli_path=self._path)

    # ------------------------------------------------------------------ #
    # Properties / status
    # ------------------------------------------------------------------ #
    @property
    def cli_path(self) -> Optional[str]:
        return self._path

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def status(self) -> Dict[str, object]:
        return self._status.as_dict()

    def set_interval(self, seconds: int) -> None:
        self.interval = max(10, int(seconds))

    def refresh_cli_path(self) -> Optional[str]:
        with self._lock:
            path = shutil.which("mullvad")
            self._path = path
            self._status.cli_path = path
        return self._path

    def ensure_status(self, max_age: float = 30.0) -> Dict[str, object]:
        """Ensure the connection status is up to date and return it."""
        with self._lock:
            if time.time() - self._status.last_status_poll > max_age:
                self._collect_status(force=True)
            else:
                self._emit_status()
            return self._status.as_dict()

    def is_connected(self, max_age: float = 30.0) -> bool:
        """Check whether Mullvad appears connected."""
        status = self.ensure_status(max_age=max_age)
        return bool(status.get("connected"))

    # ------------------------------------------------------------------ #
    # Status collection helpers
    # ------------------------------------------------------------------ #
    def _collect_status(self, force: bool = False) -> None:
        info: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        connected: Optional[bool] = None

        # Mullvad public API
        try:
            from mullvad_api import MullvadAPI

            api_client = MullvadAPI()
            api_data = api_client.data or {}
            info["mullvad_api"] = api_data
            if connected is None:
                connected = bool(api_data.get("mullvad_exit_ip"))
        except Exception as exc:
            errors["mullvad_api"] = str(exc)

        # mullvad-python helper (Mullpy)
        try:
            from mullvad_python.api import Mullpy

            mp = Mullpy()
            info["mullvad_python"] = {
                "ip": getattr(mp, "ip", None),
                "city": getattr(mp, "city", None),
                "country": getattr(mp, "country", None),
                "exit_ip": getattr(mp, "exit_ip", None),
                "server_type": getattr(mp, "server_type", None),
                "organization": getattr(mp, "organization", None),
                "blacklisted": getattr(mp, "blacklisted", {}),
            }
            if connected is None:
                connected = bool(getattr(mp, "exit_ip", None))
        except Exception as exc:
            errors["mullvad_python"] = str(exc)

        # Mullvad CLI wrapper
        cli_info, cli_err = self._collect_cli_status()
        if cli_info:
            info["mullvad_cli"] = cli_info
            if connected is None:
                connected = bool(cli_info.get("connected"))
        elif cli_err:
            errors["mullvad_cli"] = cli_err

        if connected is None:
            connected = False

        self._status.connection_info = info
        self._status.connected = connected
        self._status.last_status_poll = time.time()
        self._status.errors = errors
        if errors and (connected is False or force):
            self._status.last_error = "; ".join(f"{k}: {v}" for k, v in errors.items())
        elif not errors:
            self._status.last_error = None
        self._emit_status()

    def _collect_cli_status(self) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        path = self.cli_path or shutil.which("mullvad")
        if not path:
            return None, "cli-missing"

        try:
            cli_module = importlib.import_module("mullvad.cli")
        except Exception:
            try:
                exceptions_mod = importlib.import_module("mullvad.exceptions")
                sys.modules.setdefault("exceptions", exceptions_mod)
                models_mod = importlib.import_module("mullvad.models")
                sys.modules.setdefault("models", models_mod)
                cli_module = importlib.import_module("mullvad.cli")
            except Exception as exc:
                return None, str(exc)

        try:
            MullvadCLI = getattr(cli_module, "MullvadCLI")
        except AttributeError as exc:
            return None, str(exc)

        try:
            cli = MullvadCLI(path=path)
            cli.status()
            status_text = getattr(cli, "status_str", "") or ""
            is_connected = getattr(cli, "is_connected", None)
            status_lines = [line.strip() for line in status_text.splitlines() if line.strip()]
            connection_line = next(
                (line for line in status_lines if "Connected" in line or "Disconnected" in line),
                status_lines[0] if status_lines else status_text.strip(),
            )
            server_hint = None
            for line in status_lines:
                if "Connected to" in line:
                    server_hint = line
                    break

            return (
                {
                    "status_raw": status_text.strip(),
                    "connected": bool(is_connected if is_connected is not None else ("connected" in status_text.lower())),
                    "connection_line": connection_line,
                    "server_hint": server_hint,
                },
                None,
            )
        except Exception as exc:
            return None, str(exc)

    # ------------------------------------------------------------------ #
    # Lifecycle control
    # ------------------------------------------------------------------ #
    def update_cycle_state(self, *, enabled: bool, scanning: bool) -> bool:
        """
        Sync the auto-cycle state with the GUI. Returns True if the manager is active.
        """
        if enabled and scanning:
            if not self.refresh_cli_path():
                self._log("[VPN] Mullvad CLI not found; auto-cycle disabled.", "red")
                self._enabled.clear()
                self._active = False
                self._status.auto_enabled = False
                self._status.last_error = "cli-missing"
                self._emit_status()
                return False
            self._enabled.set()
            self._status.auto_enabled = True
            self._ensure_thread()
            if not self._active:
                self._log(f"[VPN] Mullvad auto-cycle enabled ({self.interval}s).", "blue")
            self._active = True
            self._collect_status(force=True)
            return True

        self._enabled.clear()
        if self._active:
            self._log("[VPN] Mullvad auto-cycle paused.", "orange")
        self._active = False
        self._status.auto_enabled = False
        self._emit_status()
        return False

    def force_cycle(self) -> None:
        """Request an immediate cycle from the background thread."""
        self._force.set()
        self._enabled.set()
        self._ensure_thread()

    def run_cycle_now(self, asynchronous: bool = True) -> None:
        """Trigger a cycle immediately."""
        if asynchronous:
            self.force_cycle()
            return

        self._log("[VPN] Manual Mullvad cycle requested.", "blue")
        self._run_cycle()

    def stop(self) -> None:
        self._enabled.clear()
        self._active = False
        self._status.auto_enabled = False
        self._status.is_active = False
        self._emit_status()
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="mullvad-cycle", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        last_run = 0.0
        while not self._stop.is_set():
            if not self._enabled.is_set():
                if self._stop.wait(0.5):
                    break
                continue

            if self._force.is_set():
                self._force.clear()
                if self._run_cycle():
                    last_run = time.time()
                continue

            now = time.time()
            if last_run == 0.0 or now - last_run >= self.interval:
                if self._run_cycle():
                    last_run = now
                    continue

            remaining = self.interval - (time.time() - last_run)
            sleep_for = min(1.0, max(0.2, remaining))
            if self._stop.wait(max(0.1, sleep_for)):
                break

    def _run_cycle(self) -> bool:
        path = self.refresh_cli_path()
        if not path:
            self._status.last_error = "cli-missing"
            self._log("[VPN] Mullvad CLI unavailable; disabling auto-cycle.", "red")
            self._enabled.clear()
            self._active = False
            self._status.auto_enabled = False
            self._emit_status()
            return False

        commands = ([path, "disconnect"], [path, "connect"])
        for cmd in commands:
            label = cmd[1]
            msg_run = f"[VPN] Running mullvad {label}..."
            self._log(msg_run, "blue")
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
            except FileNotFoundError:
                self._status.last_error = "cli-missing"
                self._log("[VPN] Mullvad CLI unavailable; disabling auto-cycle.", "red")
                self._enabled.clear()
                self._active = False
                self._status.auto_enabled = False
                self._emit_status()
                return False
            except Exception as exc:
                self._status.last_error = str(exc)
                self._log(f"[VPN] mullvad {label} failed: {exc}", "red")
                self._emit_status()
                return False

            out_lines: List[str] = []
            if result.stdout:
                out_lines.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
            if result.stderr:
                out_lines.extend(line.strip() for line in result.stderr.splitlines() if line.strip())

            if result.returncode != 0:
                msg = out_lines[0] if out_lines else f"exit code {result.returncode}"
                self._status.last_error = msg
                self._log(f"[VPN] mullvad {label} error: {msg}", "red")
                self._emit_status()
                return False
            elif out_lines:
                detail = f"[VPN] {out_lines[0]}"
                self._log(detail, "blue")
                self._status.last_output = out_lines[-5:]

        self._status.last_cycle = time.time()
        self._status.last_error = None
        self._status.is_active = self._enabled.is_set()
        self._log("[VPN] Mullvad cycle completed.", "green")
        self._collect_status()
        return True

    def _log(self, message: str, tag: str) -> None:
        try:
            self.log_fn(message, tag)
        except Exception:
            pass
        try:
            self.ctl_fn(message)
        except Exception:
            pass

    def _emit_status(self) -> None:
        if self.status_hook:
            try:
                self.status_hook(self._status.as_dict())
            except Exception:
                pass
