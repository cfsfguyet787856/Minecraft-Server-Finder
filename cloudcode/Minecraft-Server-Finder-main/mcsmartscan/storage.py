"""Persistence helpers for the scanner."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from typing import Dict, Optional

from . import constants
from .utils import ensure_directory, get_desktop_path

DEFAULT_STATE: Dict[str, object] = {"servers": [], "maybe": [], "open_ports": []}


class StorageManager:
    """Centralise all file-system interactions for the scanner."""

    def __init__(
        self,
        base_dir: Optional[str] = None,
        output_filename: str = constants.OUTPUT_FILENAME,
        saved_filename: str = constants.SAVED_SERVERS_FILE,
        open_ports_filename: str = constants.OPEN_PORTS_FILENAME,
    ) -> None:
        self._lock = threading.RLock()
        self._output_filename = output_filename
        self._saved_filename = saved_filename
        self._open_ports_filename = open_ports_filename
        self._base_dir = None  # type: Optional[str]
        self._output_path = ""
        self._saved_path = ""
        self._open_ports_path = ""
        self.set_base_dir(base_dir or default_storage_directory())

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #
    @property
    def base_dir(self) -> str:
        return self._base_dir or ""

    @property
    def output_path(self) -> str:
        return self._output_path

    @property
    def saved_state_path(self) -> str:
        return self._saved_path

    @property
    def open_ports_path(self) -> str:
        return self._open_ports_path

    def set_base_dir(self, new_base: str) -> None:
        """Re-point storage to a new base directory."""
        path = os.path.abspath(new_base)
        ensure_directory(path)
        with self._lock:
            self._base_dir = path
            self._output_path = os.path.join(path, self._output_filename)
            self._saved_path = os.path.join(path, self._saved_filename)
            self._open_ports_path = os.path.join(path, self._open_ports_filename)
            self._ensure_files_locked()

    # ------------------------------------------------------------------ #
    # Loading / saving structured state
    # ------------------------------------------------------------------ #
    def load_state(self) -> Dict[str, object]:
        """Load saved state from disk, returning defaults on failure."""
        with self._lock:
            try:
                if os.path.exists(self._saved_path):
                    with open(self._saved_path, "r", encoding="utf-8") as handle:
                        data = json.load(handle)
                        if isinstance(data, dict):
                            return data
                        if isinstance(data, list):
                            return {"confirmed": data, "maybe": [], "open_ports": []}
            except Exception:
                pass
            return {**DEFAULT_STATE}

    def write_state(self, payload: Dict[str, object]) -> None:
        """Write the full state blob to disk."""
        with self._lock:
            try:
                ensure_directory(self.base_dir)
                with open(self._saved_path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
            except Exception:
                # Silent failure matches previous behaviour.
                pass

    # ------------------------------------------------------------------ #
    # Streaming append helpers
    # ------------------------------------------------------------------ #
    def append_confirmed_server(self, addr: str, version: str, players: str, confidence: str, motd: str) -> None:
        """Append a confirmed server entry to the human-readable text file."""
        timestamp = datetime.now().isoformat(timespec="seconds")
        line = f"{timestamp}\t{addr}\t{version}\t{players}\t{confidence}\t{motd}\n"
        self._append_line(self._output_path, line)

    def append_open_port(self, addr_port: str) -> None:
        """Append an open-port entry to the legacy text file."""
        self._append_line(self._open_ports_path, addr_port + "\n")

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _ensure_files_locked(self) -> None:
        ensure_directory(self.base_dir)
        try:
            if not os.path.exists(self._output_path):
                with open(self._output_path, "w", encoding="utf-8") as handle:
                    handle.write("ISO_Time\tAddress\tVersion\tPlayers\tConfidence\tMOTD\n")
        except Exception:
            pass
        try:
            if not os.path.exists(self._saved_path):
                with open(self._saved_path, "w", encoding="utf-8") as handle:
                    json.dump(DEFAULT_STATE, handle, ensure_ascii=False, indent=2)
        except Exception:
            pass
        try:
            if not os.path.exists(self._open_ports_path):
                with open(self._open_ports_path, "w", encoding="utf-8") as handle:
                    handle.write("Open ports (address:port)\n")
        except Exception:
            pass

    def _append_line(self, path: str, line: str) -> None:
        with self._lock:
            try:
                ensure_directory(os.path.dirname(path))
                with open(path, "a", encoding="utf-8", errors="replace") as handle:
                    handle.write(line)
            except Exception:
                pass


def default_storage_directory() -> str:
    """Determine the default directory for storing scanner artefacts."""
    try:
        desktop = get_desktop_path()
        if desktop and os.path.isdir(desktop):
            return desktop
    except Exception:
        pass
    return os.getcwd()

