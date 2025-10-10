# ============================== SECTION 1: IMPORTS / CONSTANTS / GLOBALS (START) ==============================
import os, sys, time, json, math, socket, threading, queue, subprocess, platform, re, hashlib, random, shutil
from datetime import datetime
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor
from collections import deque

from mcsmartscan.constants import (
    BEDROCK_MAGIC,
    DEFAULT_BEDROCK_PORT,
    DEFAULT_END_IP,
    DEFAULT_PORT,
    DEFAULT_START_IP,
    DEFAULT_TIMEOUT,
    DEFAULT_WORKERS,
    IS_WINDOWS,
    MAX_QUEUE,
    OUTSTANDING_FACTOR,
    OUTPUT_FILENAME,
    PROTOCOL_CANDIDATES,
    PROTOCOL_TO_VERSION_HINT,
    SAVED_SERVERS_FILE,
    ping_to_bars,
)
from mcsmartscan.storage import StorageManager
from mcsmartscan.utils import (
    ip_range_generator,
    ip_range_size,
    permuted_index_generator,
)
from mcsmartscan.vpn import MullvadManager

try:
    import psutil
except Exception:
    psutil = None

# optional graphs
_HAVE_MPL = False

# Preferred server checker (primary)
try:
    from mcstatus import JavaServer as _MC_JavaServer
    _mcstatus_available = True
except Exception:
    _mcstatus_available = False

try:
    import nmap
    _nmap_available = True
except Exception:
    _nmap_available = False

_gui_available = True
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
except Exception:
    _gui_available = False

_PING_TIME_RE = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_PING_TTL_RE = re.compile(r"\bttl[=\s:]\s*\d+", re.IGNORECASE)

# ============================== SECTION 1: IMPORTS / CONSTANTS / GLOBALS (END) ================================

# ============================== SECTION 2: PATHS / PERSISTENCE / UTILS (START) ================================
# (moved to mcsmartscan.utils and mcsmartscan.storage)
# ============================== SECTION 2: PATHS / PERSISTENCE / UTILS (END) ==================================

# ============================== SECTION 3: PROBES / PROTOCOL (START) ==========================================
def _nmap_probe(ip, port, timeout):
    if not _nmap_available:
        return False, None, None
    try:
        scanner = nmap.PortScanner()
        res = scanner.scan(ip, str(port), arguments=f"-Pn -T3 --max-retries 1 --host-timeout {int(timeout*1000)}ms")
        hostinfo = res.get("scan", {}).get(ip)
        if not hostinfo:
            return False, None, None
        tcpinfo = hostinfo.get("tcp", {}).get(port)
        if not tcpinfo:
            return False, None, None
        state = tcpinfo.get("state")
        product = tcpinfo.get("name", "")
        banner = tcpinfo.get("product", "") or tcpinfo.get("extrainfo", "")
        if state == "open" and "minecraft" in (product + banner).lower():
            return True, {"source": "nmap", "product": product, "banner": banner}, 0.0
        return False, None, None
    except Exception:
        return False, None, None


def ping_host(ip, timeout):
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), ip]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = r.stdout
        ok = bool(_PING_TTL_RE.search(out))
        rtt = None
        m = _PING_TIME_RE.search(out)
        if m:
            rtt = float(m.group(1))
        elif "time<1ms" in out.lower():
            rtt = 0.5
        return ok, rtt
    except Exception:
        return False, None


def check_port(ip, port, timeout):
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, port), timeout=timeout):
            rtt = (time.perf_counter() - t0) * 1000.0
            return True, rtt
    except Exception:
        return False, None


def _varint_encode(value: int) -> bytes:
    out = bytearray()
    value &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            break
    return bytes(out)


def _pack_string(s: str) -> bytes:
    data = s.encode("utf-8")
    return _varint_encode(len(data)) + data


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Socket closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def _varint_decode_sock(sock: socket.socket) -> int:
    num = 0
    num_read = 0
    while True:
        b = sock.recv(1)
        if not b:
            raise EOFError("Socket closed while reading VarInt")
        val = b[0]
        num |= (val & 0x7F) << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError("VarInt too big")
        if (val & 0x80) == 0:
            break
    return num


def _flatten_motd(desc):
    try:
        if desc is None:
            return ""
        if isinstance(desc, str):
            return desc
        if isinstance(desc, dict):
            parts = []
            if "text" in desc and isinstance(desc["text"], str):
                parts.append(desc["text"])
            if "extra" in desc and isinstance(desc["extra"], list):
                for item in desc["extra"]:
                    parts.append(_flatten_motd(item))
            if not parts and "translate" in desc:
                parts.append(str(desc.get("translate", "")))
            return "".join(parts)
        if isinstance(desc, list):
            return "".join(_flatten_motd(x) for x in desc)
        return str(desc)
    except Exception:
        return ""


def _modern_status_once(ip, port, timeout, proto_id=47, handshake_host=None, do_ping_pong=True):
    host_in_handshake = handshake_host if handshake_host else ip
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        pkt = (
            b"\x00"
            + _varint_encode(proto_id)
            + _pack_string(host_in_handshake)
            + port.to_bytes(2, "big")
            + _varint_encode(1)
        )
        s.sendall(_varint_encode(len(pkt)) + pkt)
        s.sendall(_varint_encode(1) + b"\x00")
        _ = _varint_decode_sock(s)
        pid = _varint_decode_sock(s)
        if pid != 0x00:
            return None
        json_len = _varint_decode_sock(s)
        data = _recv_exact(s, json_len)
        try:
            info = json.loads(data.decode("utf-8", errors="ignore"))
        except Exception:
            return None
        if not isinstance(info, dict):
            return None
        if do_ping_pong:
            payload = int(time.time_ns()) & ((1 << 63) - 1)
            payload_bytes = payload.to_bytes(8, "big", signed=False)
            pong_pkt = b"\x01" + payload_bytes
            s.sendall(_varint_encode(len(pong_pkt)) + pong_pkt)
            _ = _varint_decode_sock(s)
            pong_id = _varint_decode_sock(s)
            if pong_id != 0x01:
                return None
            returned = _recv_exact(s, 8)
            if returned != payload_bytes:
                return None
        desc = info.get("description")
        motd = _flatten_motd(desc)
        players = info.get("players") or {}
        version_obj = info.get("version") or {}
        version_name = version_obj.get("name")
        version_proto = version_obj.get("protocol")
        online = players.get("online")
        maxp = players.get("max")
        return {
            "flavor": "modern",
            "version": version_name or "-",
            "proto": version_proto if isinstance(version_proto, int) else None,
            "players": online if isinstance(online, int) else None,
            "max": maxp if isinstance(maxp, int) else None,
            "motd": motd,
            "raw": info,
        }


def _legacy_status(ip, port, timeout):
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"\xFE\x01")
        first = s.recv(1)
        if not first or first != b"\xFF":
            return None
        raw_len = _recv_exact(s, 2)
        strlen = int.from_bytes(raw_len, "big")
        raw = _recv_exact(s, strlen * 2)
        text = raw.decode("utf-16be", errors="ignore")
        parts = [p for p in text.replace("\x00", "\n").split("\n") if p]
        info = {"flavor": "legacy", "motd": "", "version": "-", "players": None, "max": None, "raw": text}
        if len(parts) >= 5:
            info["version"] = parts[2]
            info["motd"] = parts[3]
            try:
                info["players"] = int(parts[4])
                if len(parts) >= 6:
                    info["max"] = int(parts[5])
            except Exception:
                pass
        return info


def confirm_minecraft_by_protocol(ip, port, timeout, handshake_host=None):
    info_a = None
    hit_pid = None
    try:
        for pid in PROTOCOL_CANDIDATES:
            try:
                info_a = _modern_status_once(
                    ip, port, timeout, proto_id=pid, handshake_host=handshake_host, do_ping_pong=True
                )
                if info_a:
                    hit_pid = pid
                    break
            except Exception:
                continue
    except Exception:
        info_a = None
    info_b = None
    try:
        info_b = _legacy_status(ip, port, timeout)
    except Exception:
        info_b = None
    if not info_b:
        try:
            for pid in PROTOCOL_CANDIDATES:
                try:
                    info_b = _modern_status_once(
                        ip, port, timeout, proto_id=pid, handshake_host=handshake_host, do_ping_pong=False
                    )
                    if info_b and not hit_pid:
                        hit_pid = pid
                    if info_b:
                        break
                except Exception:
                    continue
        except Exception:
            info_b = None
    if not (info_a or info_b):
        return False, None, "none"
    base = info_a or info_b
    alt = info_b if info_a else None
    vname = base.get("version") or (alt.get("version") if alt else "-") or "-"
    vproto = base.get("proto") or (alt.get("proto") if alt else None)
    players = base.get("players") if base.get("players") is not None else (alt.get("players") if alt else None)
    maxp = base.get("max") if base.get("max") is not None else (alt.get("max") if alt else None)
    motd = base.get("motd") or (alt.get("motd") if alt else "")
    hint = None
    pid_for_hint = vproto if isinstance(vproto, int) else None
    if (not vname or vname == "-") and pid_for_hint is not None:
        hint = PROTOCOL_TO_VERSION_HINT.get(pid_for_hint)
    conf = "dual" if (info_a and info_b) else "single"
    return True, {
        "version": vname or "-",
        "players": players,
        "max": maxp,
        "motd": motd,
        "hint": hint,
        "protocol": vproto,
    }, conf


def bedrock_ping(ip, port, timeout):
    try:
        guid = random.getrandbits(64).to_bytes(8, "big")
        ts = int(time.time_ns() // 1_000_000).to_bytes(8, "big")
        pkt = b"\x01" + ts + BEDROCK_MAGIC + guid  # UNCONNECTED_PING
        t0 = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, port))
            data, _ = s.recvfrom(2048)
            rtt = (time.perf_counter() - t0) * 1000.0
        if not data or data[0] != 0x1C:  # UNCONNECTED_PONG
            return False, None, None
        idx = data.find(BEDROCK_MAGIC)
        server_id = ""
        if idx != -1 and len(data) > idx + len(BEDROCK_MAGIC) + 2:
            rest = data[idx + len(BEDROCK_MAGIC):]
            if len(rest) >= 2:
                strlen = int.from_bytes(rest[:2], "big", signed=False)
                sid_bytes = rest[2:2 + strlen]
                server_id = sid_bytes.decode("utf-8", errors="ignore")
            else:
                server_id = rest.decode("utf-8", errors="ignore")
        motd = "-"
        version = "-"
        players = None
        maxp = None
        if server_id:
            parts = server_id.split(";")
            if len(parts) >= 6 and parts[0].upper() in ("MCPE", "MCEE"):
                motd = parts[1] or "-"
                version = parts[3] or "-"
                try:
                    players = int(parts[4])
                except Exception:
                    players = None
                try:
                    maxp = int(parts[5])
                except Exception:
                    maxp = None
        info = {"version": version, "players": players, "max": maxp, "motd": motd, "hint": "Bedrock"}
        return True, info, rtt
    except Exception:
        return False, None, None


def _extra_fallback_probe(ip, timeout, handshake_host=None):
    """
    Probe a Java port using multiple strategies ordered by reliability:
    1) mcstatus
    2) direct protocol handshake
    3) nmap fingerprint
    """
    # 1) mcstatus primary
    if _mcstatus_available:
        try:
            srv = _MC_JavaServer.lookup(f"{ip}:{DEFAULT_PORT}")
            st = srv.status()
            version = getattr(getattr(st, "version", None), "name", None) or "-"
            players = getattr(getattr(st, "players", None), "online", None)
            maxp = getattr(getattr(st, "players", None), "max", None)
            motd = getattr(getattr(st, "motd", None), "clean", None)
            if isinstance(motd, list):
                motd = "".join(motd)
            info = {
                "version": version,
                "players": players if isinstance(players, int) else None,
                "max": maxp if isinstance(maxp, int) else None,
                "motd": (motd or "")[:220],
                "hint": "mcstatus",
            }
            return True, info, "Certain", {"mcstatus"}
        except Exception:
            pass

    custom_ok = False
    custom_info = None
    try:
        ok_custom, info_custom, _ = confirm_minecraft_by_protocol(
            ip, DEFAULT_PORT, timeout, handshake_host=handshake_host
        )
        if ok_custom:
            custom_ok = True
            custom_info = info_custom or {}
            if isinstance(custom_info, dict):
                custom_info.setdefault("hint", "protocol")
    except Exception:
        custom_ok = False
        custom_info = None

    nmap_ok = False
    nmap_info = None
    if _nmap_available:
        try:
            ok_nmap, info_nmap, _ = _nmap_probe(ip, DEFAULT_PORT, timeout)
            if ok_nmap:
                nmap_ok = True
                banner = info_nmap.get("banner") if isinstance(info_nmap, dict) else ""
                product = info_nmap.get("product") if isinstance(info_nmap, dict) else "-"
                nmap_info = {
                    "version": product or "-",
                    "players": None,
                    "max": None,
                    "motd": (banner or "")[:220],
                    "hint": "nmap",
                }
        except Exception:
            nmap_ok = False
            nmap_info = None

    if custom_ok:
        base = dict(custom_info or {})
        base.setdefault("version", base.get("version", "-"))
        base.setdefault("motd", base.get("motd", ""))
        if nmap_ok and nmap_info:
            merged = dict(base)
            merged.setdefault("version", nmap_info.get("version", merged.get("version", "-")))
            if merged.get("motd") in (None, "", "-") and nmap_info.get("motd"):
                merged["motd"] = nmap_info.get("motd")
            merged.setdefault("hint", "protocol+nmap")
            return True, merged, "Likely", {"custom", "nmap"}
        return True, base, "Possible", {"custom"}

    if nmap_ok and nmap_info:
        return True, nmap_info, "Unlikely", {"nmap"}

    return False, None, "Unlikely", set()
# ============================== SECTION 3: PROBES / PROTOCOL (END) ============================================

# ============================== SECTION 4: GUI CLASS - INIT + UI (START) ==============================
class ScannerAppGUI:
    def __init__(self, root):
        self.root = root
        root.title("Minecraft Scanner - Hybrid Backend")

        # --- Core state ---
        self._stop = threading.Event()
        self._pause = threading.Event(); self._pause.clear()
        self.executor = None
        self._uiq = queue.Queue(maxsize=MAX_QUEUE)
        self.start_time = None
        self.scanning = False

        # --- Storage ---
        self.storage = StorageManager()

        # --- Mullvad management ---
        self.vpn_manager = MullvadManager(
            log_fn=lambda msg, tag="info": self._uiq_put(("log", msg, tag)),
            ctl_fn=self._ctl_async,
            ui_dispatch=lambda fn, args=(), kwargs=None: self._run_on_ui(fn, *(args or ()), **(kwargs or {})),
            status_hook=self._handle_vpn_status_update,
            interval=120,
        )
        self._latest_vpn_status = self.vpn_manager.status
        self._vpn_connected = None
        self._vpn_last_cycle_time = 0.0
        self._vpn_cycle_lock = threading.Lock()
        self._scans_since_vpn_cycle = 0
        self._vpn_guard_last_check = 0.0
        self._vpn_guard_triggered = False

        # --- Persistence throttling ---
        self._save_lock = threading.Lock()
        self._save_pending = False
        self._last_save = 0.0
        self._maybe_lock = threading.Lock()

        # --- Stats and counters ---
        self.total_ips = 0
        self.processed = 0
        self.ping_attempts = 0
        self.ping_failures = 0
        self._ping_sum = 0.0
        self._ping_count = 0
        self._servers_saved = set()
        self.servers = []
        self.maybe_list = []
        self.open_ports = set()
        self.known_confirmed = set()
        self.known_maybe = set()
        self.last_checked = {}

        # --- Threading / auto-limit (no autotune/backoff/cooldowns) ---
        self.current_concurrency = DEFAULT_WORKERS
        self.max_concurrency = DEFAULT_WORKERS
        self.auto_limit_on = True
        self.failed_window = []
        self.auto_limit_threshold = 0.95
        self.auto_limit_cooldown = 20
        self._last_auto_change = 0
        self._concurrency_lock = threading.Lock()
        self._active_tasks = 0
        self._active_tasks_lock = threading.Lock()

        # --- Networking (no Mullvad / no global backoff) ---
        self._refresh_thread = None
        self._refresh_stop = threading.Event()
        self._refresh_tick = 10.0
        self._host_override_for_scan = None
        self._stable_ok_windows = 0

        # --- Tk variables (trimmed set only) ---
        self.var_start        = tk.StringVar(value=DEFAULT_START_IP)
        self.var_end          = tk.StringVar(value=DEFAULT_END_IP)
        self.var_threads      = tk.IntVar(value=DEFAULT_WORKERS)
        self.var_failthr      = tk.DoubleVar(value=self.auto_limit_threshold * 100.0)
        self.var_random       = tk.BooleanVar(value=True)
        self.var_require_ping = tk.BooleanVar(value=True)
        self.var_auto_limit   = tk.BooleanVar(value=True)
        self.var_timeout      = tk.DoubleVar(value=DEFAULT_TIMEOUT)
        self.var_mullvad_cycle = tk.BooleanVar(value=False)
        self.var_vpn_cycle_scans = tk.IntVar(value=0)

        # --- Performance strip StringVars ---
        self.s_elapsed  = tk.StringVar(value="Elapsed: 00:00")
        self.s_eta      = tk.StringVar(value="ETA: -")
        self.s_ips      = tk.StringVar(value="IPs/s: -")
        self.s_rps      = tk.StringVar(value="Replies/s: -")
        self.s_fpm      = tk.StringVar(value="Finds/min: -")
        self.s_avgping  = tk.StringVar(value="Avg ping: -")
        self.s_hit      = tk.StringVar(value="Hit rate: -")
        self.s_cpu      = tk.StringVar(value="CPU: -")
        self.s_ram      = tk.StringVar(value="RAM: -")

        # --- Quick stats vars ---
        self.var_icmp = tk.IntVar(value=0)
        self.var_port = tk.IntVar(value=0)
        self.var_mc   = tk.IntVar(value=0)
        self.var_total = tk.IntVar(value=0)
        self.var_failed_pct = tk.StringVar(value="0.00%")

        # --- Active threads var ---
        self.var_active_threads = tk.IntVar(value=0)
        self.var_dark_mode = tk.BooleanVar(value=True)

        self._theme_palettes = {}
        self._current_theme = "dark"
        self._tree_style = "Scanner.Treeview"
        self._primary_button_style = "Accent.TButton"
        self._muted_label_style = "Muted.TLabel"
        self._success_label_style = "Success.TLabel"
        self._warn_label_style = "Warn.TLabel"
        self._info_label_style = "Info.TLabel"
        self._danger_label_style = "Danger.TLabel"
        self._value_label_style = "Value.TLabel"
        self._style = None

        self._prepare_outfile()
        self._init_theme()
        self._build_ui()
        self._load_saved_servers()
        self._start_refresh_loop()
        self._schedule_analytics()

    # ----------------------------------------------------------------------

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=(8, 8, 8, 12))
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)

        self._threads_display = tk.StringVar(value=f"{self.current_concurrency} (active 0)")

        settings = ttk.LabelFrame(container, text="Scan Settings")
        settings.pack(fill="x", padx=4, pady=(0, 6))
        for col in (1, 3, 5, 7):
            settings.columnconfigure(col, weight=1)

        ttk.Label(settings, text="Start IP").grid(row=0, column=0, sticky="w", padx=(8, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_start).grid(row=0, column=1, sticky="ew", padx=(0, 12), pady=4)
        ttk.Label(settings, text="End IP").grid(row=0, column=2, sticky="w", padx=(0, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_end).grid(row=0, column=3, sticky="ew", padx=(0, 12), pady=4)
        ttk.Label(settings, text="Threads (max)").grid(row=0, column=4, sticky="w", padx=(0, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_threads, width=8).grid(row=0, column=5, sticky="ew", padx=(0, 12), pady=4)
        ttk.Label(settings, text="Timeout (s)").grid(row=0, column=6, sticky="w", padx=(0, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_timeout, width=8).grid(row=0, column=7, sticky="ew", padx=(0, 12), pady=4)

        ttk.Label(settings, text="Fail% threshold").grid(row=1, column=0, sticky="w", padx=(8, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_failthr, width=8).grid(row=1, column=1, sticky="w", padx=(0, 12), pady=4)

        options = ttk.LabelFrame(container, text="Scan Options")
        options.pack(fill="x", padx=4, pady=(0, 6))
        for idx in range(4):
            options.columnconfigure(idx, weight=1)

        ttk.Checkbutton(options, text="Randomize IP order", variable=self.var_random).grid(row=0, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Require ping response", variable=self.var_require_ping).grid(row=0, column=1, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Auto thread limit", variable=self.var_auto_limit).grid(row=0, column=2, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Dark mode", variable=self.var_dark_mode, command=self._toggle_theme).grid(row=0, column=3, sticky="w", padx=8, pady=2)

        tools = ttk.LabelFrame(container, text="Verification & Tools")
        tools.pack(fill="x", padx=4, pady=(0, 6))
        tools.columnconfigure(1, weight=1)
        tools.columnconfigure(3, weight=1)

        svc_text = f"Services: mcstatus {'ON' if _mcstatus_available else 'OFF'} | nmap {'ON' if _nmap_available else 'OFF'}"
        ttk.Label(tools, text=svc_text, style=self._muted_label_style).grid(row=0, column=0, columnspan=4, sticky="w", padx=8, pady=(6, 4))

        ttk.Label(tools, text="Host override").grid(row=1, column=0, sticky="w", padx=(8, 4), pady=4)
        self.var_host_override = tk.StringVar(value="")
        ttk.Entry(tools, textvariable=self.var_host_override).grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=4)

        ttk.Label(tools, text="Direct test host").grid(row=1, column=2, sticky="w", padx=(0, 4), pady=4)
        self.var_test_host = tk.StringVar(value="")
        ttk.Entry(tools, textvariable=self.var_test_host).grid(row=1, column=3, sticky="ew", padx=(0, 12), pady=4)
        ttk.Button(tools, text="Run Test", command=self.run_direct_test).grid(row=1, column=4, sticky="w", padx=(0, 8), pady=4)

        controls = ttk.Frame(container)
        controls.pack(fill="x", padx=4, pady=(0, 4))

        self.btn_start = ttk.Button(controls, text="Start", width=10, command=self.start_scan, style=self._primary_button_style)
        self.btn_pause = ttk.Button(controls, text="Pause", width=10, command=self.pause_scan, state="disabled")
        self.btn_resume = ttk.Button(controls, text="Resume", width=10, command=self.resume_scan, state="disabled")
        self.btn_stop = ttk.Button(controls, text="Stop", width=10, command=self.stop_scan, state="disabled")
        self.btn_start.pack(side="left")
        self.btn_pause.pack(side="left", padx=(6, 0))
        self.btn_resume.pack(side="left", padx=(6, 0))
        self.btn_stop.pack(side="left", padx=(6, 0))

        self.btn_clear_logs = ttk.Button(controls, text="Clear Logs", width=12, command=self.clear_logs)
        self.btn_open_folder = ttk.Button(controls, text="Open Output Folder", width=18, command=self.open_output_folder)
        self.btn_clear_logs.pack(side="right")
        self.btn_open_folder.pack(side="right", padx=(0, 6))

        vpn_frame = ttk.LabelFrame(container, text="VPN Control")
        vpn_frame.pack(fill="x", padx=4, pady=(0, 6))
        self.chk_mullvad = ttk.Checkbutton(
            vpn_frame,
            text="Cycle Mullvad every 120s during scans",
            variable=self.var_mullvad_cycle,
            command=self._on_mullvad_toggle
        )
        self.chk_mullvad.pack(side="left", padx=8, pady=4)
        self.btn_mullvad_now = ttk.Button(vpn_frame, text="Run Mullvad Cycle Now", width=22, command=self.run_mullvad_cycle_now)
        self.btn_mullvad_now.pack(side="left", padx=(6, 0), pady=4)
        ttk.Label(vpn_frame, text="Cycle after", style=self._muted_label_style).pack(side="left", padx=(8, 0), pady=4)
        self.ent_mullvad_cycle_scans = ttk.Entry(vpn_frame, width=7, textvariable=self.var_vpn_cycle_scans, justify="center")
        self.ent_mullvad_cycle_scans.pack(side="left", padx=(2, 0), pady=4)
        ttk.Label(vpn_frame, text="scans", style=self._muted_label_style).pack(side="left", padx=(2, 0), pady=4)
        mullvad_hint = "Mullvad CLI ready" if self.vpn_manager.cli_path else "Mullvad CLI missing"
        self.lbl_mullvad_status = ttk.Label(vpn_frame, text=mullvad_hint, style=self._muted_label_style)
        self.lbl_mullvad_status.pack(side="right", padx=8, pady=4)

        stats = ttk.LabelFrame(container, text="Quick Stats")
        stats.pack(fill="x", padx=4, pady=(0, 6))
        stat_items = [
            ("Replied", self.var_icmp, self._success_label_style),
            ("Port open", self.var_port, self._warn_label_style),
            ("Minecraft", self.var_mc, self._info_label_style),
            ("Total scanned", self.var_total, self._value_label_style),
            ("Failed %", self.var_failed_pct, self._value_label_style),
            ("Threads", self._threads_display, self._value_label_style),
        ]
        for idx, (title, var, style) in enumerate(stat_items):
            stats.columnconfigure(idx * 2 + 1, weight=1)
            ttk.Label(stats, text=f"{title}:").grid(row=0, column=idx * 2, sticky="w", padx=(8, 2), pady=4)
            ttk.Label(stats, textvariable=var, style=style).grid(row=0, column=idx * 2 + 1, sticky="w", padx=(0, 12), pady=4)

        perf = ttk.LabelFrame(container, text="Performance")
        perf.pack(fill="x", padx=4, pady=(0, 6))
        for col in range(3):
            perf.columnconfigure(col, weight=1)
        perf_vars = [self.s_elapsed, self.s_eta, self.s_ips, self.s_rps, self.s_fpm, self.s_avgping, self.s_hit, self.s_cpu, self.s_ram]
        for idx, var in enumerate(perf_vars):
            row, col = divmod(idx, 3)
            ttk.Label(perf, textvariable=var).grid(row=row, column=col, sticky="w", padx=8, pady=4)

        content = ttk.Frame(container)
        content.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)

        left = ttk.Frame(content)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(1, weight=1)
        left.rowconfigure(3, weight=1)

        ttk.Label(left, text="Log").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.log = scrolledtext.ScrolledText(left, state="disabled", height=14, font=("Consolas", 9), relief="flat", borderwidth=0)
        self.log.grid(row=1, column=0, sticky="nsew")

        ttk.Label(left, text="Control Log").grid(row=2, column=0, sticky="w", pady=(8, 4))
        self.ctl = scrolledtext.ScrolledText(left, state="disabled", height=6, font=("Consolas", 9), relief="flat", borderwidth=0)
        self.ctl.grid(row=3, column=0, sticky="nsew")

        right = ttk.Frame(content)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        columns = ("address", "version", "players", "confidence", "motd", "found", "ping", "bars", "hint")
        servers_frame = ttk.LabelFrame(right, text="Confirmed Minecraft Servers")
        servers_frame.grid(row=0, column=0, sticky="nsew")
        servers_frame.columnconfigure(0, weight=1)
        servers_frame.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(servers_frame, columns=columns, show="headings", selectmode="extended")
        for col, title, width, anc in [
            ("address", "Address", 170, "w"),
            ("version", "Version", 90, "center"),
            ("players", "Players", 90, "center"),
            ("confidence", "Confidence", 100, "center"),
            ("motd", "MOTD", 220, "w"),
            ("found", "Found At", 150, "center"),
            ("ping", "Ping", 90, "center"),
            ("bars", "Bars", 60, "center"),
            ("hint", "Version Hint", 120, "center"),
        ]:
            self.tree.heading(col, text=title, anchor=anc)
            self.tree.column(col, width=width, anchor=anc, stretch=False if col == "bars" else True)
        tree_scroll_y = ttk.Scrollbar(servers_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")

        mcols = ("address", "reason", "seen", "last_try")
        maybe_frame = ttk.LabelFrame(right, text="Maybe Servers & Open Ports")
        maybe_frame.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        maybe_frame.columnconfigure(0, weight=1)
        maybe_frame.rowconfigure(0, weight=1)
        self.maybe_tree = ttk.Treeview(maybe_frame, columns=mcols, show="headings", selectmode="extended", height=6)
        for col, title, width, anc in [
            ("address", "Address / IP", 200, "w"),
            ("reason", "Reason", 150, "center"),
            ("seen", "First Seen", 150, "center"),
            ("last_try", "Last Try", 150, "center"),
        ]:
            self.maybe_tree.heading(col, text=title, anchor=anc)
            self.maybe_tree.column(col, width=width, anchor=anc, stretch=True)
        maybe_scroll_y = ttk.Scrollbar(maybe_frame, orient="vertical", command=self.maybe_tree.yview)
        self.maybe_tree.configure(yscrollcommand=maybe_scroll_y.set)
        self.maybe_tree.grid(row=0, column=0, sticky="nsew")
        maybe_scroll_y.grid(row=0, column=1, sticky="ns")

        actions_right = ttk.Frame(right)
        actions_right.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.btn_copy_sel = ttk.Button(actions_right, text="Copy Selected", width=16, command=self.copy_selected)
        self.btn_del_sel = ttk.Button(actions_right, text="Delete Selected", width=16, command=self.delete_selected)
        self.btn_del_all = ttk.Button(actions_right, text="Delete All Maybe", width=16, command=self.delete_all_maybe)
        self.btn_copy_sel.pack(side="left")
        self.btn_del_sel.pack(side="left", padx=(6, 0))
        self.btn_del_all.pack(side="left", padx=(6, 0))

        self.save_hint = tk.StringVar(value=f"Saves to: {self.storage.output_path}")
        self.lbl_save_hint = ttk.Label(container, textvariable=self.save_hint, style=self._muted_label_style)
        self.lbl_save_hint.pack(anchor="w", padx=6, pady=(4, 0))

        self.status = tk.StringVar(value="Ready")
        self.lbl_status = ttk.Label(container, textvariable=self.status, style="Status.TLabel")
        self.lbl_status.pack(fill="x", padx=6, pady=(0, 6))

        self.btn_mullvad_now.config(state="normal" if self.vpn_manager.cli_path else "disabled")
        self._update_mullvad_label()
        self._apply_theme()

        self.root.after(120, self._pump_ui)
        self.root.after(500, self._tick)
        self.root.after(1000, self._update_threads_stat)

    def _init_theme(self):
        self._style = ttk.Style()
        try:
            self._style.theme_use("clam")
        except Exception:
            pass
        self._theme_palettes = {
            "dark": {
                "bg": "#1f1f24",
                "bg_alt": "#26262c",
                "fg": "#f2f2f7",
                "muted": "#b0b0bb",
                "accent": "#4da3ff",
                "border": "#2f2f35",
                "button_bg": "#33333a",
                "button_fg": "#f5f5f5",
                "button_active": "#5cafff",
                "entry_bg": "#2c2c33",
                "entry_fg": "#f5f5fa",
                "success": "#8bc34a",
                "warn": "#ffb74d",
                "info": "#4fc3f7",
                "danger": "#ef5350",
                "select_bg": "#4da3ff",
                "select_fg": "#111115",
            },
            "light": {
                "bg": "#f4f5f7",
                "bg_alt": "#ffffff",
                "fg": "#202130",
                "muted": "#6b6c7a",
                "accent": "#1976d2",
                "border": "#d0d2d9",
                "button_bg": "#e2e6ee",
                "button_fg": "#1f2430",
                "button_active": "#2a82dd",
                "entry_bg": "#ffffff",
                "entry_fg": "#1f2430",
                "success": "#388e3c",
                "warn": "#f57c00",
                "info": "#0288d1",
                "danger": "#d32f2f",
                "select_bg": "#1976d2",
                "select_fg": "#f9f9fb",
            },
        }
        self._current_theme = "dark" if self.var_dark_mode.get() else "light"

    def _toggle_theme(self):
        self._current_theme = "dark" if self.var_dark_mode.get() else "light"
        self._apply_theme()

    def _apply_theme(self):
        theme = "dark" if self.var_dark_mode.get() else "light"
        if theme not in self._theme_palettes:
            theme = "dark"
        self._current_theme = theme
        palette = self._theme_palettes[theme]

        try:
            self.root.configure(bg=palette["bg"])
        except Exception:
            pass

        if self._style is None:
            self._style = ttk.Style()
        style = self._style
        style.configure("TFrame", background=palette["bg"])
        style.configure("TLabelframe", background=palette["bg"], foreground=palette["accent"], bordercolor=palette["border"])
        style.configure("TLabelframe.Label", background=palette["bg"], foreground=palette["accent"])
        style.configure("TLabel", background=palette["bg"], foreground=palette["fg"])
        style.configure(self._muted_label_style, background=palette["bg"], foreground=palette["muted"])
        style.configure(self._success_label_style, background=palette["bg"], foreground=palette["success"])
        style.configure(self._warn_label_style, background=palette["bg"], foreground=palette["warn"])
        style.configure(self._info_label_style, background=palette["bg"], foreground=palette["info"])
        style.configure(self._danger_label_style, background=palette["bg"], foreground=palette["danger"])
        style.configure(self._value_label_style, background=palette["bg"], foreground=palette["fg"])
        style.configure("Status.TLabel", background=palette["bg"], foreground=palette["accent"])

        style.configure("TCheckbutton", background=palette["bg"], foreground=palette["fg"])
        style.map("TCheckbutton", background=[("active", palette["bg_alt"])])

        style.configure("TEntry", fieldbackground=palette["entry_bg"], foreground=palette["entry_fg"], bordercolor=palette["border"])
        style.map("TEntry", fieldbackground=[("disabled", palette["bg_alt"])], foreground=[("disabled", palette["muted"])])

        style.configure("TScrollbar", background=palette["bg_alt"], troughcolor=palette["bg"], bordercolor=palette["border"])

        style.configure("TButton", background=palette["button_bg"], foreground=palette["button_fg"], bordercolor=palette["border"])
        style.map("TButton",
                  background=[("active", palette["button_active"]), ("pressed", palette["accent"])],
                  foreground=[("active", palette["select_fg"]), ("pressed", palette["select_fg"])])
        style.configure(self._primary_button_style, background=palette["accent"], foreground=palette["select_fg"], bordercolor=palette["accent"])
        style.map(self._primary_button_style,
                  background=[("active", palette["button_active"]), ("pressed", palette["accent"])],
                  foreground=[("active", palette["select_fg"]), ("pressed", palette["select_fg"])])

        style.configure(self._tree_style,
                        background=palette["bg_alt"],
                        fieldbackground=palette["bg_alt"],
                        foreground=palette["fg"],
                        bordercolor=palette["border"],
                        rowheight=22)
        style.map(self._tree_style,
                  background=[("selected", palette["select_bg"])],
                  foreground=[("selected", palette["select_fg"])])
        style.configure(f"{self._tree_style}.Heading",
                        background=palette["bg_alt"],
                        foreground=palette["fg"],
                        bordercolor=palette["border"])
        style.map(f"{self._tree_style}.Heading",
                  background=[("active", palette["accent"])],
                  foreground=[("active", palette["select_fg"])])

        if hasattr(self, "tree"):
            try:
                self.tree.configure(style=self._tree_style)
            except Exception:
                pass
        if hasattr(self, "maybe_tree"):
            try:
                self.maybe_tree.configure(style=self._tree_style)
            except Exception:
                pass

        if hasattr(self, "log"):
            try:
                self.log.configure(bg=palette["bg_alt"], fg=palette["fg"], insertbackground=palette["fg"], highlightthickness=0, borderwidth=0)
                self.log.tag_config("green", foreground=palette["success"])
                self.log.tag_config("orange", foreground=palette["warn"])
                self.log.tag_config("blue", foreground=palette["info"])
                self.log.tag_config("red", foreground=palette["danger"])
                self.log.tag_config("info", foreground=palette["muted"])
            except Exception:
                pass
        if hasattr(self, "ctl"):
            try:
                self.ctl.configure(bg=palette["bg_alt"], fg=palette["fg"], insertbackground=palette["fg"], highlightthickness=0, borderwidth=0)
            except Exception:
                pass

        if hasattr(self, "lbl_status"):
            try:
                self.lbl_status.configure(style="Status.TLabel")
            except Exception:
                pass

        if hasattr(self, "lbl_save_hint"):
            try:
                self.lbl_save_hint.configure(style=self._muted_label_style)
            except Exception:
                pass

        self._update_mullvad_label()

    # small helper to refresh thread stat on screen
    def _update_threads_stat(self):
        try:
            current = getattr(self, "current_concurrency", self.var_threads.get())
            active = getattr(self, "_active_tasks", 0)
            self._threads_display.set(f"{current} (active {active})")
        except Exception:
            pass
        self.root.after(1000, self._update_threads_stat)

    def _run_on_ui(self, func, *args, **kwargs):
        try:
            if self.root:
                self.root.after(0, lambda: func(*args, **kwargs))
        except Exception:
            pass

    def _ctl_async(self, msg: str):
        if not msg:
            return
        self._run_on_ui(self._ctl_log, msg)

    def _update_mullvad_label(self):
        try:
            if hasattr(self, "lbl_mullvad_status"):
                status = getattr(self, "_latest_vpn_status", {}) or {}
                has_cli = bool(status.get("cli_path"))
                connected = bool(status.get("connected"))
                auto_enabled = bool(status.get("auto_enabled"))
                last_error = status.get("last_error")
                info = status.get("connection_info", {}) or {}
                palette = self._theme_palettes.get(self._current_theme, {})
                if last_error:
                    color = palette.get("danger")
                    text = f"Mullvad issue: {last_error}"
                elif connected:
                    color = palette.get("success")
                    city = (info.get("mullvad_python") or {}).get("city")
                    country = (info.get("mullvad_python") or {}).get("country")
                    server_hint = (info.get("mullvad_cli") or {}).get("server_hint")
                    if server_hint:
                        text = server_hint
                    elif city or country:
                        parts = [p for p in (city, country) if p]
                        text = "Mullvad connected • " + ", ".join(parts)
                    else:
                        text = "Mullvad connected"
                elif has_cli and auto_enabled:
                    color = palette.get("info") or palette.get("accent")
                    text = "Mullvad cycling"
                elif has_cli:
                    color = palette.get("warn") or palette.get("info")
                    text = "Mullvad CLI idle"
                else:
                    color = palette.get("danger")
                    text = "Mullvad CLI missing"

                kwargs = {"text": text}
                if color:
                    kwargs["foreground"] = color
                self.lbl_mullvad_status.configure(**kwargs)
            if hasattr(self, "btn_mullvad_now"):
                cli_ready = bool(getattr(self, "_latest_vpn_status", {}).get("cli_path"))
                state = "normal" if cli_ready else "disabled"
                self.btn_mullvad_now.config(state=state)
        except Exception:
            pass

    def _handle_vpn_status_update(self, status: dict):
        try:
            status = status or {}
        except Exception:
            status = {}
        self._latest_vpn_status = status

        connected = status.get("connected")
        connected_bool = None if connected is None else bool(connected)
        last_cycle = status.get("last_cycle") or 0.0
        if last_cycle and last_cycle != self._vpn_last_cycle_time:
            with self._vpn_cycle_lock:
                self._scans_since_vpn_cycle = 0
            self._vpn_last_cycle_time = last_cycle

        prev_connected = self._vpn_connected
        if connected_bool is not None and connected_bool != prev_connected:
            if connected_bool:
                info = status.get("connection_info", {}) or {}
                mp = info.get("mullvad_python") or {}
                cli_info = info.get("mullvad_cli") or {}
                city = mp.get("city")
                country = mp.get("country")
                server = cli_info.get("server_hint")
                detail_parts = [p for p in [server, ", ".join([x for x in (city, country) if x])] if p]
                detail = next((part for part in detail_parts if part), "unknown location")
                msg = f"[VPN] Connection secured via {detail}."
                self._vpn_guard_triggered = False
                tag = "green"
            else:
                msg = "[VPN] Connection lost; scan paused if running."
                tag = "red"
            self._uiq_put(("log", msg, tag))
            self._ctl_async(msg)
        if connected_bool is not None:
            self._vpn_connected = connected_bool

        self._run_on_ui(self._update_mullvad_label)

    @staticmethod
    def _normalize_confidence(value, default="Possible"):
        if value is None:
            return default
        mapping = {
            "single": "Possible",
            "dual": "Likely",
            "possible": "Possible",
            "likely": "Likely",
            "certain": "Certain",
            "certainly": "Certain",
            "uncertain": "Unlikely",
            "unlikely": "Unlikely",
            "nmap": "Unlikely",
        }
        val = str(value).strip()
        normalized = mapping.get(val.lower())
        if normalized:
            return normalized
        return default

    def _resolve_mullvad_path(self):
        path = self.vpn_manager.refresh_cli_path()
        self._latest_vpn_status = self.vpn_manager.status
        self._update_mullvad_label()
        return path

    def _on_mullvad_toggle(self):
        if self.var_mullvad_cycle.get() and not self._resolve_mullvad_path():
            try:
                messagebox.showwarning(
                    "Mullvad CLI",
                    "The Mullvad command-line tool is not available. Install it or adjust PATH before enabling the auto cycle.",
                )
            except Exception:
                pass
            self.var_mullvad_cycle.set(False)
            return
        self._sync_mullvad_cycle()

    def run_mullvad_cycle_now(self):
        if not self._resolve_mullvad_path():
            msg = "[VPN] Mullvad CLI not detected; cannot run cycle."
            self._uiq_put(("log", msg, "warn"))
            self._ctl_async(msg)
            return
        self.vpn_manager.force_cycle()
        msg = "[VPN] Manual Mullvad cycle requested."
        self._uiq_put(("log", msg, "info"))
        self._ctl_async(msg)

    def _sync_mullvad_cycle(self):
        enabled = bool(self.var_mullvad_cycle.get())
        active = self.vpn_manager.update_cycle_state(enabled=enabled, scanning=self.scanning)
        if enabled and self.scanning and not active:
            self._run_on_ui(self.var_mullvad_cycle.set, False)
        self._latest_vpn_status = self.vpn_manager.status
        self._update_mullvad_label()

    def _vpn_register_scan(self):
        try:
            threshold = int(self.var_vpn_cycle_scans.get() or 0)
        except Exception:
            threshold = 0
        if threshold <= 0:
            return
        with self._vpn_cycle_lock:
            self._scans_since_vpn_cycle += 1
            if self._scans_since_vpn_cycle >= threshold:
                self._scans_since_vpn_cycle = 0
                self.vpn_manager.force_cycle()
                msg = f"[VPN] Auto-cycle triggered after {threshold} scans."
                self._uiq_put(("log", msg, "blue"))
                self._ctl_async(msg)

# ============================== SECTION 4: GUI CLASS - INIT + UI (END) ==============================

# ============================== SECTION 5: PERSISTENCE / LOGS / HELPERS (START) ===============================
# (legacy helpers removed; see Section 9 for active implementations)
# ============================== SECTION 5: PERSISTENCE / LOGS / HELPERS (END) =================================
# ============================== SECTION 6: CONTROLS / SUBMITTER (START) =======================================
    def start_scan(self):
        if self.scanning:
            return
        if not self._resolve_mullvad_path():
            msg = "VPN (Mullvad CLI) not detected. Scanner is locked down until Mullvad is installed or available in PATH."
            self._ctl_async(f"[LOCKDOWN] {msg}")
            try:
                messagebox.showerror("VPN Required", msg)
            except Exception:
                pass
            self.status.set("Blocked: VPN required")
            return
        vpn_status = self.vpn_manager.ensure_status(max_age=5.0)
        if not vpn_status.get("connected"):
            msg = "[LOCKDOWN] Mullvad connection inactive. Scanning is blocked until the VPN is connected."
            self._ctl_async(msg)
            try:
                messagebox.showerror("VPN Disconnected", msg)
            except Exception:
                pass
            self.status.set("Blocked: VPN disconnected")
            return
        info = vpn_status.get("connection_info", {}) or {}
        primary_info = (info.get("mullvad_python") or info.get("mullvad_api") or {})
        ip = primary_info.get("ip") or primary_info.get("mullvad_exit_ip")
        city = primary_info.get("city")
        country = primary_info.get("country")
        server_hint = (info.get("mullvad_cli") or {}).get("server_hint")
        details = server_hint or ", ".join([p for p in (city, country) if p]) or "unknown location"
        msg = f"[VPN] Active exit IP {ip or '?'} via {details}."
        self._uiq_put(("log", msg, "info"))
        self._ctl_async(msg)
        self._stop.clear()
        self._pause.clear()
        with self._vpn_cycle_lock:
            self._scans_since_vpn_cycle = 0
        self._vpn_guard_triggered = False
        self.var_icmp.set(0); self.var_port.set(0); self.var_mc.set(0); self.var_total.set(0)
        self.ping_attempts = 0
        self.ping_failures = 0
        self.failed_window = []
        self._ping_sum = 0.0; self._ping_count = 0
        self.processed = 0
        self._stable_ok_windows = 0
        self.start_time = time.time()
        self.scanning = True
        self._host_override_for_scan = self.var_host_override.get().strip() or None

        # Allowed public vars only
        self.max_concurrency = max(1, int(self.var_threads.get()))
        self.current_concurrency = self.max_concurrency
        self.auto_limit_on = bool(self.var_auto_limit.get())
        try:
            self.auto_limit_threshold = max(0.50, min(0.999, float(self.var_failthr.get())/100.0))
        except Exception:
            self.auto_limit_threshold = 0.95

        self._clear_log()
        self._log(f"Scan start {self.var_start.get()}..{self.var_end.get()} threads={self.max_concurrency} timeout={self.var_timeout.get()} require_ping={self.var_require_ping.get()} svc=mcstatus | nmap={'on' if _nmap_available else 'off'}", "info")
        self._ctl_async(f"[SCAN] Started {self.var_start.get()} -> {self.var_end.get()} | threads={self.max_concurrency} timeout={self.var_timeout.get()}")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_pause.config(state="normal")
        self.btn_resume.config(state="disabled")
        try:
            self.total_ips = ip_range_size(self.var_start.get().strip(), self.var_end.get().strip())
        except Exception as e:
            messagebox.showerror("IP Range", f"Invalid range: {e}")
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")
            self.btn_pause.config(state="disabled")
            self.scanning = False
            self._sync_mullvad_cycle()
            self._ctl_async(f"[ERROR] Invalid IP range: {e}")
            return

        timeout = max(1e-3, float(self.var_timeout.get()))
        randomize = bool(self.var_random.get())
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrency)
        if randomize:
            seed = hashlib.sha256(str(time.time()).encode()).digest()
            ip_iter = permuted_index_generator(self.var_start.get().strip(), self.var_end.get().strip(), seed=seed, rounds=4)
        else:
            ip_iter = ip_range_generator(self.var_start.get().strip(), self.var_end.get().strip())
        self._feed_thread = threading.Thread(target=self._submitter, args=(ip_iter, timeout), daemon=True)
        self._feed_thread.start()
        self._sync_mullvad_cycle()

    def pause_scan(self):
        if not self.scanning:
            return
        self._pause.set()
        self.btn_pause.config(state="disabled")
        self.btn_resume.config(state="normal")
        self.status.set("Paused")
        self._ctl_async("[SCAN] Paused")

    def resume_scan(self):
        if not self.scanning:
            return
        self._pause.clear()
        self.btn_pause.config(state="normal")
        self.btn_resume.config(state="disabled")
        self.status.set("Scanning...")
        self._ctl_async("[SCAN] Resumed")

    def stop_scan(self):
        self._stop.set()
        self._pause.clear()
        self.scanning = False
        self._sync_mullvad_cycle()
        self.status.set("Stopping...")
        self._log("Stopped by user", "warn")
        try:
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        self.executor = None
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.btn_pause.config(state="disabled")
        self.btn_resume.config(state="disabled")
        self.status.set("Stopped")
        self._save_current_blob(immediate=True)
        self._ctl_async("[SCAN] Stopped")

    def _submitter(self, ip_iter, timeout):
        try:
            if not self.executor:
                return
            for ip in ip_iter:
                if self._stop.is_set():
                    break
                while self._pause.is_set() and not self._stop.is_set():
                    time.sleep(0.05)

                # (No per-IP cooldown anymore)

                with self._concurrency_lock:
                    allowed = self.current_concurrency
                with self._active_tasks_lock:
                    active = self._active_tasks
                if active >= allowed:
                    time.sleep(0.002)
                    continue
                try:
                    with self._active_tasks_lock:
                        self._active_tasks += 1
                    if self.executor:
                        self.executor.submit(self._worker_wrapper, ip, timeout)
                    else:
                        return
                except Exception:
                    with self._active_tasks_lock:
                        self._active_tasks = max(0, self._active_tasks - 1)
                    msg = f"{ip} - submit failed"
                    self._uiq_put(("log", msg, "warn"))
                    self._ctl_async(f"[ERROR] {msg}")
        finally:
            if self.executor:
                self.executor.shutdown(wait=True)
            self._uiq_put(("done",))
# ============================== SECTION 6: CONTROLS / SUBMITTER (END) =========================================

# ============================== SECTION 7: AUTO LIMIT / WORKER (START) ==============================
    def _adaptive_timeout(self, base_timeout):
        # Keep minimal: use average ping to slightly stretch timeout
        if self._ping_count:
            avg = self._ping_sum / max(1, self._ping_count)
            if avg > 0:
                return min(base_timeout * 2.0, max(base_timeout, (avg * 1.8) / 1000.0))
        return base_timeout

    def _auto_limit_evaluate(self):
        # Simple thread limiter only - no global backoff or bias
        try:
            self.auto_limit_threshold = max(0.50, min(0.999, float(self.var_failthr.get())/100.0))
        except Exception:
            pass
        if not self.auto_limit_on:
            return
        now = time.time()
        if now - self._last_auto_change < self.auto_limit_cooldown:
            return
        window = self.failed_window[-120:] if len(self.failed_window) >= 120 else self.failed_window[:]
        if len(window) < 60:
            return
        rate = sum(1 for x in window if x) / len(window)
        if rate >= self.auto_limit_threshold:
            with self._concurrency_lock:
                new_limit = max(8, int(self.current_concurrency * 0.7))
                if new_limit < self.current_concurrency:
                    self.current_concurrency = new_limit
                    self._last_auto_change = now
                    msg = f"[Auto] High ping failures {rate*100:.1f}% - threads={self.current_concurrency}"
                    self._uiq_put(("log", msg, "orange"))
                    self._ctl_async(msg)
        else:
            if self.current_concurrency < self.max_concurrency:
                self._stable_ok_windows += 1
                if self._stable_ok_windows >= 3:
                    with self._concurrency_lock:
                        self.current_concurrency = min(self.max_concurrency, self.current_concurrency + 2)
                        self._last_auto_change = now
                        msg = f"[Auto] Stable - threads={self.current_concurrency}"
                        self._uiq_put(("log", msg, "info"))
                        self._ctl_async(msg)
                    self._stable_ok_windows = 0
            else:
                self._stable_ok_windows = 0

    def _worker_wrapper(self, ip, timeout):
        try:
            self._worker(ip, timeout)
        finally:
            with self._active_tasks_lock:
                self._active_tasks = max(0, self._active_tasks - 1)

    def _worker(self, ip, timeout):
        try:
            if self._stop.is_set() or self._pause.is_set():
                return
            self.last_checked[ip] = time.time()

            self.var_total.set(self.var_total.get() + 1)
            self.processed += 1
            self._host_override_for_scan = self.var_host_override.get().strip() or None

            # Single ping attempt - track stats, but DO NOT log failures to main log
            try:
                base_t = float(self.var_timeout.get())
            except Exception:
                base_t = float(self.var_timeout)
            dyn_timeout = self._adaptive_timeout(max(1e-3, base_t))

            ok_ping, rtt = ping_host(ip, dyn_timeout)
            self.ping_attempts += 1
            if ok_ping:
                self.var_icmp.set(self.var_icmp.get() + 1)
                self._ping_count += 1
                if rtt is not None:
                    self._ping_sum += float(rtt)
                self.failed_window.append(False)
                # Only log responses
                self._uiq_put(("log", f"{ip} - ping received ({rtt:.1f} ms)" if rtt is not None else f"{ip} - ping received", "green"))
            else:
                self.ping_failures += 1
                self.failed_window.append(True)
                # No failed-ping line in main log
                if self.var_require_ping.get():
                    self._auto_limit_evaluate()
                    return

            # Ports (log concise open/closed only)
            open_java, _ = check_port(ip, DEFAULT_PORT, dyn_timeout)
            ok_bedrock, info_b, rtt_b = bedrock_ping(ip, DEFAULT_BEDROCK_PORT, dyn_timeout)

            if open_java and ok_bedrock:
                self._uiq_put(("log", f"{ip} - ports open: 25565 & 19132", "blue"))
                self._ctl_async(f"[PORT] {ip} open on 25565 & 19132")
            elif open_java:
                self._uiq_put(("log", f"{ip} - port 25565 open", "green"))
                self._ctl_async(f"[PORT] {ip}:25565 open")
            elif ok_bedrock:
                self._uiq_put(("log", f"{ip} - port 19132 open", "green"))
                self._ctl_async(f"[PORT] {ip}:19132 open")
            else:
                self._uiq_put(("log", f"{ip} - ports closed", "orange"))
                return

            # Java details via mcstatus primary (with fallbacks inside helper)
            if open_java:
                self.var_port.set(self.var_port.get() + 1)
                self.open_ports.add(ip)
                try:
                    self._append_open_port_to_file(f"{ip}:{DEFAULT_PORT}")
                except Exception:
                    pass
                self._save_current_blob()
                ok2, info2, conf2, sources2 = _extra_fallback_probe(ip, dyn_timeout, handshake_host=self._host_override_for_scan)
                if ok2:
                    conf_label = self._normalize_confidence(conf2, "Possible")
                    addr = f"{ip}:{DEFAULT_PORT}"
                    if addr not in self.known_confirmed:
                        players = info2.get("players") if isinstance(info2, dict) else None
                        maxp = info2.get("max") if isinstance(info2, dict) else None
                        version = (info2.get("version") if isinstance(info2, dict) else "-") or "-"
                        motd = ((info2.get("motd") if isinstance(info2, dict) else "") or "").replace("\n"," ")[:120]
                        hint = info2.get("hint") if isinstance(info2, dict) else None
                        pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                        bars = ping_to_bars(rtt if ok_ping else None)
                        rec = {"address": addr, "version": version, "players": pstr, "motd": motd, "confidence": conf_label,
                               "found_at": datetime.now().isoformat(timespec='seconds'), "ping": rtt if ok_ping else None, "bars": bars, "hint": hint}
                        self.servers.append(rec); self.known_confirmed.add(addr)
                        self.var_mc.set(self.var_mc.get() + 1)
                        self._append_server_to_file(addr, version, pstr, rec["confidence"], motd)
                        self._save_current_blob()
                        self.refresh_table(incremental=rec)
                        origin = ", ".join(sorted(sources2)) if sources2 else "unknown"
                        self._ctl_async(f"[MC] {addr} confirmed ({conf_label}) via {origin}")
                else:
                    self._ctl_async(f"[MC] {ip}:25565 open but no reliable Minecraft signature detected.")

            # Bedrock details
            if ok_bedrock and info_b:
                addr_b = f"{ip}:{DEFAULT_BEDROCK_PORT}"
                if addr_b not in self.known_confirmed:
                    conf_b = self._normalize_confidence("Possible", "Possible")
                    version = info_b.get("version","-") or "-"
                    players = info_b.get("players")
                    maxp = info_b.get("max")
                    pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                    motd = (info_b.get("motd") or "").replace("\n", " ")[:120]
                    bars = ping_to_bars(rtt_b)
                    rec = {"address": addr_b, "version": version, "players": pstr, "motd": motd, "confidence": conf_b,
                           "found_at": datetime.now().isoformat(timespec='seconds'), "ping": rtt_b, "bars": bars, "hint": "Bedrock"}
                    self.servers.append(rec); self.known_confirmed.add(addr_b)
                    self.var_mc.set(self.var_mc.get() + 1)
                    try:
                        self._append_open_port_to_file(addr_b)
                    except Exception:
                        pass
                    self._append_server_to_file(addr_b, version, pstr, conf_b, motd)
                    self._save_current_blob()
                    self.refresh_table(incremental=rec)
                    self._ctl_async(f"[MC] {addr_b} confirmed ({conf_b}) via bedrock ping")

            self._auto_limit_evaluate()
        except Exception as exc:
            self._uiq_put(("log", f"{ip} - worker error: {exc}", "red"))
            self._ctl_async(f"[ERROR] Worker failure on {ip}: {exc}")
        finally:
            self._vpn_register_scan()
            self._uiq_put(("processed", 1))
# ============================== SECTION 7: AUTO LIMIT / WORKER (END) ================================

# ============================== SECTION 8: GUI HELPERS / STATS / TICK (START) ==============================
    def _update_settings_display(self):
        # (Settings panel was removed; keep a no-op for compatibility)
        pass

    def run_direct_test(self):
        """Triggered by the 'Run Test' button in the GUI."""
        target = self.var_test_host.get().strip()
        if not target:
            self._log_info("[WARN] No test host provided.")
            return

        self._log_info(f"[TEST] Running quick probe for {target} ...")
        try:
            timeout = float(self.var_timeout.get())
        except Exception:
            timeout = float(self.var_timeout)
        try:
            ok, rtt = ping_host(target, timeout)
            if ok:
                self._log_info(f"[TEST] Ping to {target} succeeded" + (f" ({rtt:.1f} ms)" if rtt is not None else ""))
            else:
                self._log_info(f"[TEST] Ping to {target} failed")

            open_ok, rtt2 = check_port(target, 25565, timeout)
            if open_ok:
                self._log_info(f"[TEST] Port 25565 open" + (f" ({rtt2:.1f} ms)" if rtt2 is not None else ""))
                # mcstatus first
                tried_mcstatus = False
                if _mcstatus_available:
                    try:
                        srv = _MC_JavaServer.lookup(f"{target}:25565")
                        st = srv.status()
                        ver = getattr(getattr(st, "version", None), "name", None) or "?"
                        players = getattr(getattr(st, "players", None), "online", None) or 0
                        motd = getattr(getattr(st, "motd", None), "clean", None)
                        if isinstance(motd, list):
                            motd = "".join(motd)
                        self._log_info(f"[TEST] Minecraft server -> {ver} | {players} players | MOTD: {motd or ''}")
                        tried_mcstatus = True
                    except Exception:
                        pass
                if not tried_mcstatus:
                    okp, info, _ = confirm_minecraft_by_protocol(target, 25565, timeout)
                    if okp and info:
                        ver = info.get("version", "?")
                        players = info.get("players", 0)
                        motd = info.get("motd", "")
                        self._log_info(f"[TEST] Minecraft server -> {ver} | {players} players | MOTD: {motd}")
                    else:
                        self._log_info("[TEST] Port open but no valid MC protocol response.")
            else:
                self._log_info("[TEST] Port 25565 closed.")
        except Exception as e:
            self._log_info(f"[ERROR] Test failed: {e}")

    def _pump_ui(self):
        """
        Drain queued UI messages and refresh counters.
        Only log real log/events; ignore metric/progress messages.
        """
        try:
            drained = 0
            while not self._uiq.empty() and drained < 500:
                item = self._uiq.get_nowait()
                drained += 1

                msg, tag = None, "info"

                if isinstance(item, str):
                    msg = item
                elif isinstance(item, tuple):
                    if len(item) >= 2 and item[0] == "log":
                        msg = item[1]
                        if len(item) >= 3 and isinstance(item[2], str):
                            tag = item[2]
                    elif len(item) >= 1 and item[0] in ("proc", "progress", "metric", "processed", "done"):
                        continue
                    else:
                        continue
                elif isinstance(item, dict):
                    kind = item.get("type") or item.get("kind") or item.get("tag")
                    if kind in ("metric", "progress", "proc", "processed", "done"):
                        continue
                    if kind in ("log", "event", "info", "green", "red", "orange", "blue"):
                        msg = item.get("msg") or item.get("message") or item.get("text")
                        tag = item.get("tag") or item.get("level") or ("info" if kind in ("log", "event", "info") else kind)
                    else:
                        continue
                else:
                    continue

                if not msg or not isinstance(msg, str):
                    continue

                try:
                    self.log.configure(state="normal")
                    self.log.insert("end", msg + "\n", tag)
                    self.log.configure(state="disabled")
                    self.log.see("end")
                except Exception:
                    print(msg)
        except Exception:
            pass

        # Refresh simple counters (no logging)
        try:
            total = getattr(self, "processed", 0)
            self.var_total.set(total)
            fail_pct = (self.ping_failures / self.ping_attempts) * 100.0 if getattr(self, "ping_attempts", 0) else 0.0
            self.var_failed_pct.set(f"{fail_pct:.2f}%")
        except Exception:
            pass

        # Keep updating
        self.root.after(200, self._pump_ui)

    def _tick(self):
        """Periodic 1 s update loop for runtime statistics and progress."""
        # If start_time isn't set yet, schedule next tick and bail
        if not getattr(self, "start_time", None):
            self.root.after(1000, self._tick)
            return

        # --- Time & basic counters ---
        elapsed = max(0.0, time.time() - self.start_time)
        self.s_elapsed.set(f"Elapsed: {int(elapsed//60):02d}:{int(elapsed%60):02d}")

        if self.scanning:
            now = time.time()
            if now - self._vpn_guard_last_check >= 10.0:
                self._vpn_guard_last_check = now
                status = self.vpn_manager.ensure_status(max_age=10.0)
                if not status.get("connected") and not self._vpn_guard_triggered:
                    self._vpn_guard_triggered = True
                    if not self._pause.is_set():
                        self.pause_scan()
                    self.status.set("Paused (VPN lost)")
                    msg = "[LOCKDOWN] Mullvad connection lost; scan paused."
                    self._uiq_put(("log", msg, "red"))
                    self._ctl_async(msg)
        else:
            self._vpn_guard_triggered = False

        total = getattr(self, "processed", 0)
        total_pings = getattr(self, "ping_attempts", 0)
        failures = getattr(self, "ping_failures", 0)
        success = max(0, total_pings - failures)
        fail_pct = (failures / total_pings * 100.0) if total_pings else 0.0
        self.var_failed_pct.set(f"{fail_pct:.2f}%")

        # --- Throughput calculations ---
        ips_per_s = (total / elapsed) if elapsed > 0 else 0.0
        replies_per_s = (success / elapsed) if elapsed > 0 else 0.0
        finds_per_min = (len(self.servers) / (elapsed / 60.0)) if elapsed >= 60 else float(len(self.servers))

        self.s_ips.set(f"IPs/s: {ips_per_s:.1f}")
        self.s_rps.set(f"Replies/s: {replies_per_s:.1f}")
        self.s_fpm.set(f"Finds/min: {finds_per_min:.1f}")

        # --- Ping average & hit rate ---
        avg_ping = (self._ping_sum / max(1, self._ping_count)) if self._ping_count else None
        self.s_avgping.set(f"Avg ping: {avg_ping:.1f} ms" if avg_ping is not None else "Avg ping: -")

        if total_pings > 0:
            hit_rate = (success / total_pings) * 100.0
            self.s_hit.set(f"Hit rate: {hit_rate:.1f}%")
        else:
            self.s_hit.set("Hit rate: -")

        # --- ETA (based on total IPs estimated) ---
        if getattr(self, "total_ips", 0) > 0 and ips_per_s > 0:
            remaining = max(0, self.total_ips - total)
            eta_sec = remaining / ips_per_s
            self.s_eta.set(f"ETA: {int(eta_sec//60):02d}:{int(eta_sec%60):02d}")
        else:
            self.s_eta.set("ETA: -")

        # --- System usage stats (if psutil available) ---
        if psutil:
            try:
                cpu = psutil.cpu_percent(interval=None)
                ram = psutil.virtual_memory().percent
                self.s_cpu.set(f"CPU: {cpu:.0f}%")
                self.s_ram.set(f"RAM: {ram:.0f}%")
            except Exception:
                self.s_cpu.set("CPU: -")
                self.s_ram.set("RAM: -")
        else:
            self.s_cpu.set("CPU: -")
            self.s_ram.set("RAM: -")

        # --- Threads active ---
        try:
            with self._active_tasks_lock:
                active_threads = self._active_tasks
            self.var_active_threads.set(active_threads)
            self._threads_display.set(f"{self.current_concurrency} (active {active_threads})")
        except Exception:
            pass

        # --- Auto thread limit evaluation periodically ---
        try:
            self._auto_limit_evaluate()
        except Exception:
            pass

        # Reschedule
        self.root.after(1000, self._tick)

    def _start_refresh_loop(self):
        """Refresh GUI tables every 10 s."""
        try:
            if hasattr(self, "tree") and self.servers:
                # Touch to keep Treeview painting responsive
                for child in self.tree.get_children():
                    self.tree.item(child, tags=())
        except Exception:
            pass
        self.root.after(int(getattr(self, "_refresh_tick", 10.0) * 1000), self._start_refresh_loop)

    def _schedule_analytics(self):
        """Periodic analytics event emitter."""
        try:
            if hasattr(self, "_emit_analytics_point"):
                self._emit_analytics_point()
        except Exception:
            pass
        self.root.after(int(5.0 * 1000), self._schedule_analytics)

    def _emit_analytics_point(self):
        # Minimal placeholder; keep to avoid undefined refs.
        try:
            _ = len(self.servers)
            _ = len(self.maybe_list)
        except Exception:
            pass

    def _log_info(self, msg: str):
        try:
            self.log.configure(state="normal")
            self.log.insert("end", msg + "\n", "info")
            self.log.configure(state="disabled")
            self.log.see("end")
        except Exception:
            print(msg)
        self._ctl_async(msg)

    def _ctl_log(self, msg: str):
        try:
            self.ctl.configure(state="normal")
            self.ctl.insert("end", msg + "\n")
            self.ctl.configure(state="disabled")
            self.ctl.see("end")
        except Exception:
            print(msg)
# ============================== SECTION 8: GUI HELPERS / STATS / TICK (END) ==============================

# ============================== SECTION 9: FILES / LOGGING / TABLE HELPERS (START) ==============================
    # ------------------------------- FILE PREP --------------------------------
    def _prepare_outfile(self, base_dir=None):
        """Create/save locations and ensure files exist via the storage manager."""
        if base_dir:
            self.storage.set_base_dir(base_dir)
        else:
            # set_base_dir triggers ensure; reapply current directory to guarantee file existence
            self.storage.set_base_dir(self.storage.base_dir)

        self.out_path = self.storage.output_path
        self.saved_json = self.storage.saved_state_path
        self.open_ports_txt = self.storage.open_ports_path

    # ------------------------------ SAVE / LOAD -------------------------------
    def _append_server_to_file(self, addr, version, players, confidence, motd):
        """Append one confirmed server line to the human-readable TXT."""
        self.storage.append_confirmed_server(addr, version, players, confidence, motd)

    def _append_open_port_to_file(self, addr_port):
        """Append an open-port address to the Open_Ports.txt (de-dup at read time)."""
        self.storage.append_open_port(addr_port)

    def _save_current_blob(self, immediate=False):
        """Schedule or immediately persist current state to disk."""
        if immediate or not getattr(self, "root", None):
            with self._save_lock:
                self._last_save = time.time()
                self._save_pending = False
            self._write_current_blob()
            return

        def _schedule(delay_ms):
            try:
                self.root.after(delay_ms, self._flush_delayed_save)
            except Exception:
                with self._save_lock:
                    self._save_pending = False
                    self._last_save = time.time()
                self._write_current_blob()

        now = time.time()
        with self._save_lock:
            if self._save_pending:
                return
            elapsed = now - self._last_save
            if elapsed >= 2.0:
                delay = 0
            else:
                delay = int(max(0.0, (2.0 - elapsed) * 1000))
            self._save_pending = True
        _schedule(delay)

    def _flush_delayed_save(self):
        with self._save_lock:
            self._save_pending = False
        self._last_save = time.time()
    self._write_current_blob()

    def _write_current_blob(self):
        """Persist current state to saved_servers.json."""
        data = {
            "servers": self.servers,
            "maybe": self.maybe_list,
            "open_ports": sorted(list({*(self.open_ports or set())})),
        }
        self.storage.write_state(data)

    def _refresh_single_maybe_ui(self, rec):
        if not hasattr(self, "maybe_tree"):
            return
        address = rec.get("address", "-")
        values = (
            address,
            rec.get("reason", "-"),
            rec.get("seen", ""),
            rec.get("last_try", ""),
        )
        for iid in self.maybe_tree.get_children():
            vals = self.maybe_tree.item(iid, "values")
            if vals and vals[0] == address:
                self.maybe_tree.item(iid, values=values)
                break
        else:
            self.maybe_tree.insert("", "end", values=values)

    def _delete_maybe_row_ui(self, address):
        if not hasattr(self, "maybe_tree"):
            return
        for iid in self.maybe_tree.get_children():
            vals = self.maybe_tree.item(iid, "values")
            if vals and vals[0] == address:
                self.maybe_tree.delete(iid)
                break

    def _add_maybe_server(self, address, reason="uncertain", hint=None):
        if not address:
            return
        now = datetime.now().isoformat(timespec="seconds")
        with self._maybe_lock:
            existing = None
            for rec in self.maybe_list:
                if rec.get("address") == address:
                    existing = rec
                    break
            if existing:
                existing["last_try"] = now
                if reason:
                    existing["reason"] = reason
                if hint:
                    existing["hint"] = hint
                updated = dict(existing)
            else:
                rec = {
                    "address": address,
                    "reason": reason or "uncertain",
                    "seen": now,
                    "last_try": now,
                    "hint": hint or "",
                }
                self.maybe_list.append(rec)
                self.known_maybe.add(address)
                updated = dict(rec)
        self._run_on_ui(self._refresh_single_maybe_ui, updated)
        self._save_current_blob()

    def _remove_maybe_server(self, address):
        if not address:
            return
        removed = False
        with self._maybe_lock:
            if address in self.known_maybe:
                self.known_maybe.discard(address)
                self.maybe_list = [rec for rec in self.maybe_list if rec.get("address") != address]
                removed = True
        if removed:
            self._run_on_ui(self._delete_maybe_row_ui, address)
            self._save_current_blob()

    def _load_saved_servers(self):
        """Load saved state into memory and tables."""
        data = self.storage.load_state() or {}

        self.servers = list(data.get("servers", []))
        self.maybe_list = list(data.get("maybe", []))
        self.open_ports = set(data.get("open_ports", []))

        normalized_servers = []
        for rec in self.servers:
            if isinstance(rec, dict):
                rec["confidence"] = self._normalize_confidence(
                    rec.get("confidence", "Possible"), "Possible"
                )
                normalized_servers.append(rec)
        self.servers = normalized_servers

        # Restore known sets (for de-dup)
        self.known_confirmed = {rec.get("address") for rec in self.servers if rec.get("address")}
        self.known_maybe = {rec.get("address") for rec in self.maybe_list if rec.get("address")}

        # Populate GUI tables if they exist
        if hasattr(self, "tree"):
            for row in self.tree.get_children():
                self.tree.delete(row)
            for rec in self.servers:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        rec.get("address", "-"),
                        rec.get("version", "-"),
                        rec.get("players", "?"),
                        self._normalize_confidence(rec.get("confidence", "Possible"), "Possible"),
                        rec.get("motd", ""),
                        rec.get("found_at", ""),
                        f"{rec.get('ping', 0):.1f} ms" if isinstance(rec.get("ping"), (int, float)) else "-",
                        rec.get("bars", 0),
                        rec.get("hint", ""),
                    ),
                )
        if hasattr(self, "maybe_tree"):
            for row in self.maybe_tree.get_children():
                self.maybe_tree.delete(row)
            for rec in self.maybe_list:
                self.maybe_tree.insert(
                    "",
                    "end",
                    values=(
                        rec.get("address", "-"),
                        rec.get("reason", "open-port"),
                        rec.get("seen", ""),
                        rec.get("last_try", ""),
                    ),
                )

    # ------------------------------ TABLE REFRESH -----------------------------
    def refresh_table(self, incremental=None):
        """
        Fast path: insert just one new record if provided.
        Otherwise, rebuild table from self.servers.
        """
        try:
            if not hasattr(self, "tree"):
                return
            if incremental and isinstance(incremental, dict):
                rec = incremental
                self.tree.insert(
                    "", "end", values=(
                        rec.get("address","-"),
                        rec.get("version","-"),
                        rec.get("players","?"),
                        self._normalize_confidence(rec.get("confidence", "Possible"), "Possible"),
                        rec.get("motd",""),
                        rec.get("found_at",""),
                        f"{rec.get('ping',0):.1f} ms" if isinstance(rec.get("ping"), (int,float)) else "-",
                        rec.get("bars",0),
                        rec.get("hint","")
                    )
                )
            else:
                for row in self.tree.get_children():
                    self.tree.delete(row)
                for rec in self.servers:
                    self.tree.insert(
                        "", "end", values=(
                            rec.get("address","-"),
                            rec.get("version","-"),
                            rec.get("players","?"),
                            self._normalize_confidence(rec.get("confidence", "Possible"), "Possible"),
                            rec.get("motd",""),
                            rec.get("found_at",""),
                            f"{rec.get('ping',0):.1f} ms" if isinstance(rec.get("ping"), (int,float)) else "-",
                            rec.get("bars",0),
                            rec.get("hint","")
                        )
                    )
        except Exception:
            pass

    # ------------------------------ LOGGING -----------------------------------
    def _uiq_put(self, item):
        """Safe put into UI queue without blocking the workers."""
        try:
            self._uiq.put_nowait(item)
        except Exception:
            # Drop if full; keeps UI responsive
            pass

    def _clear_log(self):
        try:
            self.log.configure(state="normal")
            self.log.delete("1.0", "end")
            self.log.configure(state="disabled")
        except Exception:
            pass

    def _log(self, msg, tag="info"):
        """High-volume log to main log (thin)."""
        try:
            self.log.configure(state="normal")
            self.log.insert("end", str(msg) + "\n", tag)
            self.log.configure(state="disabled")
            self.log.see("end")
        except Exception:
            print(str(msg))

    def clear_logs(self):
        """Clear both main and control logs (button on top row)."""
        try:
            self._clear_log()
            self.ctl.configure(state="normal")
            self.ctl.delete("1.0", "end")
            self.ctl.configure(state="disabled")
            self._ctl_log("Logs cleared.")
        except Exception:
            pass

    def open_output_folder(self):
        """Open the directory where output files are written."""
        try:
            target = getattr(self, "out_path", self.storage.output_path)
            folder = os.path.dirname(target) or os.getcwd()
            if IS_WINDOWS:
                os.startfile(folder)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
            self._ctl_log(f"Opened folder: {folder}")
        except Exception as e:
            self._ctl_log(f"Open folder failed: {e}")

    # ------------------------------ COPY / DELETE ACTIONS ----------------------------
    def copy_selected(self):
        """Copy selected server rows to the clipboard."""
        try:
            lines = []
            if hasattr(self, "tree"):
                for iid in self.tree.selection():
                    vals = self.tree.item(iid, "values")
                    if vals:
                        addr, version, players, *_ = vals
                        lines.append(f"{addr} | {version} | {players}")
            if hasattr(self, "maybe_tree"):
                for iid in self.maybe_tree.selection():
                    vals = self.maybe_tree.item(iid, "values")
                    if vals:
                        addr, reason, *_ = vals
                        lines.append(f"{addr} ({reason})")
            if not lines:
                self._ctl_log("No entries selected to copy.")
                return
            text = "\n".join(lines)
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
            except Exception:
                self._ctl_log("Clipboard unavailable; writing copy buffer to log.")
                for line in lines:
                    self._ctl_log(line)
                return
            self._ctl_log(f"Copied {len(lines)} item(s) to clipboard.")
        except Exception as e:
            self._ctl_log(f"Copy failed: {e}")

    def delete_selected(self):
        """Delete selected entries from the right-side tables (both trees)."""
        try:
            # From Confirmed servers
            for iid in self.tree.selection():
                vals = self.tree.item(iid, "values")
                addr = vals[0] if vals and len(vals) > 0 else None
                if addr:
                    # remove from memory structs
                    self.servers = [r for r in self.servers if r.get("address") != addr]
                    self.known_confirmed.discard(addr)
                self.tree.delete(iid)

            # From Maybe/Open-ports
            for iid in self.maybe_tree.selection():
                vals = self.maybe_tree.item(iid, "values")
                addr = vals[0] if vals and len(vals) > 0 else None
                if addr:
                    self.maybe_list = [r for r in self.maybe_list if r.get("address") != addr]
                    self.known_maybe.discard(addr)
                self.maybe_tree.delete(iid)

            self._save_current_blob(immediate=True)
            self._ctl_log("Selected entries deleted.")
        except Exception as e:
            self._ctl_log(f"Delete failed: {e}")

    def delete_all_maybe(self):
        """Clear the entire Maybe/Open-ports table and memory list."""
        try:
            self.maybe_list = []
            self.known_maybe = set()
            if hasattr(self, "maybe_tree"):
                for iid in self.maybe_tree.get_children():
                    self.maybe_tree.delete(iid)
            self._save_current_blob(immediate=True)
            self._ctl_log("All Maybe/Open-ports entries deleted.")
        except Exception as e:
            self._ctl_log(f"Delete-all failed: {e}")
# ============================== SECTION 9: FILES / LOGGING / TABLE HELPERS (END) ===============================

# ============================== SECTION 10: APP LAUNCH / ENTRYPOINT (START) ===================================
def can_use_tk():
    try:
        import tkinter as _tk  # noqa: F401
        return True
    except Exception:
        return False


def _try_console_engine(app):
    """
    If you have a console scan loop defined elsewhere in this file,
    call it here. We try a few common entrypoint names.
    (Fixed: no 'return' inside a finally block.)
    """
    candidates = [
        "run_console_scan",
        "console_scan_loop",
        "main_console_loop",
        "scan_loop_console",
    ]
    g = globals()
    for name in candidates:
        fn = g.get(name)
        if callable(fn):
            app._log_info(f"[INFO] Starting console scan via {name}()")
            try:
                fn(app)
            except KeyboardInterrupt:
                app._log_info("[INFO] Interrupted.")
            except Exception as e:
                app._log_info(f"[ERROR] {name} crashed: {e}")
            return True
    return False


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--nogui", action="store_true", help="Force console mode")
    args = parser.parse_args()

    gui_ok = (not args.nogui) and can_use_tk()

    if gui_ok:
        import tkinter as tk
        try:
            root = tk.Tk()
            app = ScannerAppGUI(root)

            # Ensure loops run
            try: root.after(0, app._pump_ui)
            except Exception: pass
            try: root.after(0, app._tick)
            except Exception: pass
            try: root.after(int(5.0 * 1000), app._schedule_analytics)
            except Exception: pass

            root.mainloop()
            return
        except Exception as e:
            print(f"[WARN] GUI init failed, falling back to console: {e}")
            gui_ok = False

    # ------------------------------- CONSOLE MODE -------------------------------
    print("[INFO] Tkinter GUI not available. Running in console mode.")

    class _ConsoleShim:
        def __init__(self):
            self._stop = threading.Event()
            self._pause = threading.Event(); self._pause.clear()
            self.start_time = time.time()
            self.scanning = False

            self.total_ips = 0
            self.processed = 0
            self.ping_attempts = 0
            self.ping_failures = 0
            self._ping_sum = 0.0
            self._ping_count = 0
            self.failed_window = []

            self.known_confirmed = set()
            self.known_maybe = set()
            self.servers = []
            self.maybe_list = []
            self.open_ports = set()
            self.last_checked = {}

            self.current_concurrency = DEFAULT_WORKERS
            self.max_concurrency = DEFAULT_WORKERS

            self.auto_limit_threshold = 0.95
            self.timeout = float(DEFAULT_TIMEOUT)

            self.start_ip = DEFAULT_START_IP
            self.end_ip = DEFAULT_END_IP
            self.randomize = True
            self.require_ping = True

            self.storage = StorageManager()
            self.out_path = self.storage.output_path

        def _log_info(self, msg: str):
            try: print(msg, flush=True)
            except Exception: pass

        def _ctl_log(self, msg: str):
            try: print(msg, flush=True)
            except Exception: pass

    app = _ConsoleShim()

    started = _try_console_engine(app)
    if started:
        return

    print("[INFO] No console scan loop found.")
    print("[HINT] Define one of: run_console_scan(app), console_scan_loop(app), main_console_loop(app), scan_loop_console(app).")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[INFO] Exiting console mode.")

if __name__ == "__main__":
    main()
# ============================== SECTION 10: APP LAUNCH / ENTRYPOINT (END) =====================================
