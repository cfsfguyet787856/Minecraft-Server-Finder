# ============================== SECTION 1: IMPORTS / CONSTANTS / GLOBALS (START) ==============================
import os, sys, time, json, math, socket, threading, queue, subprocess, platform, re, hashlib, random, shutil
from datetime import datetime
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from pathlib import Path

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
from mcsmartscan.proxy import (
    ProxyAcquireTimeout,
    ProxyHandshakeError,
    ProxyPool,
    ProxyTargetError,
)

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
    from tkinter import ttk, messagebox, scrolledtext, filedialog
except Exception:
    _gui_available = False


def _resolve_resource_path(*relative_parts: str) -> Path:
    """Return an absolute path for bundled resources.

    When the application is packaged with PyInstaller the files are extracted
    to a temporary directory exposed via ``sys._MEIPASS``. During normal
    development ``__file__`` points at the repository root. This helper keeps
    both execution environments working without scattering conditional logic
    throughout the code base.
    """

    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*relative_parts)

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


def _direct_connector(ip: str, port: int, timeout: float) -> socket.socket:
    """Return a direct TCP socket connection to the target."""
    return socket.create_connection((ip, port), timeout=timeout)


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


def check_port(ip, port, timeout, connector=None):
    connector = connector or _direct_connector
    try:
        t0 = time.perf_counter()
        with connector(ip, port, timeout) as _:
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


def _modern_status_once(
    ip,
    port,
    timeout,
    proto_id=47,
    handshake_host=None,
    do_ping_pong=True,
    connector=None,
):
    connector = connector or _direct_connector
    host_in_handshake = handshake_host if handshake_host else ip
    with connector(ip, port, timeout) as s:
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


def _legacy_status(ip, port, timeout, connector=None):
    connector = connector or _direct_connector
    with connector(ip, port, timeout) as s:
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


def confirm_minecraft_by_protocol(ip, port, timeout, handshake_host=None, connector=None):
    connector = connector or _direct_connector
    info_a = None
    hit_pid = None
    try:
        for pid in PROTOCOL_CANDIDATES:
            try:
                info_a = _modern_status_once(
                    ip,
                    port,
                    timeout,
                    proto_id=pid,
                    handshake_host=handshake_host,
                    do_ping_pong=True,
                    connector=connector,
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
        info_b = _legacy_status(ip, port, timeout, connector=connector)
    except Exception:
        info_b = None
    if not info_b:
        try:
            for pid in PROTOCOL_CANDIDATES:
                try:
                    info_b = _modern_status_once(
                        ip,
                        port,
                        timeout,
                        proto_id=pid,
                        handshake_host=handshake_host,
                        do_ping_pong=False,
                        connector=connector,
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


def _extra_fallback_probe(ip, timeout, handshake_host=None, connector=None):
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
            ip,
            DEFAULT_PORT,
            timeout,
            handshake_host=handshake_host,
            connector=connector,
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
        self._ensure_full_cpu_affinity()

        # --- Core state ---
        self._stop = threading.Event()
        self._pause = threading.Event(); self._pause.clear()
        self.executor = None
        self._uiq = queue.Queue(maxsize=MAX_QUEUE)
        self.start_time = None
        self.scanning = False

        # --- Storage ---
        self.storage = StorageManager()

        # --- Proxy management ---
        self.proxy_pool = None
        self._proxy_enabled = False
        self._proxy_snapshot = []
        self._init_proxy_pool()

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
        self._base_scan_delay = 0.0
        self._max_scan_delay = 250.0
        self._adaptive_scan_delay = 0.0
        self._last_delay_adjust = 0.0
        self.adaptive_delay_enabled = False

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
        self.failed_window = deque(maxlen=240)
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
        self.var_scan_delay = tk.DoubleVar(value=0.0)
        self.var_scan_delay_max = tk.DoubleVar(value=250.0)
        self.var_adaptive_delay = tk.BooleanVar(value=False)
        self._update_scan_delay_settings()
        self._adaptive_scan_delay = self._base_scan_delay

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

        # --- Proxy monitoring vars ---
        default_proxy_text = (
            f"Proxies loaded: {self.proxy_pool.total} (ready)" if self._proxy_enabled else "Proxies disabled"
        )
        self.var_proxy_summary = tk.StringVar(value=default_proxy_text)
        self.var_proxy_health_hint = tk.StringVar(value="")

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
        self._section_frame_style = "Section.TFrame"
        self._section_header_style = "SectionHeader.TFrame"
        self._section_label_style = "SectionHeader.TLabel"
        self._style = None
        self._collapsible_sections = []

        self._prepare_outfile()
        self._init_theme()
        self._build_ui()
        self._load_saved_servers()
        self._start_refresh_loop()
        self._schedule_analytics()

    # ----------------------------------------------------------------------

    def _create_collapsible_section(self, parent, title: str, *, start_open: bool = True):
        """
        Create a section container with a static header and content frame.
        Returns the outer container and the inner content frame.
        """
        outer = ttk.Frame(parent, style=self._section_frame_style)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        header = ttk.Frame(outer, style=self._section_header_style, padding=(6, 4, 6, 4))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        label = ttk.Label(header, text=title, style=self._section_label_style)
        label.grid(row=0, column=0, sticky="w")

        body = ttk.Frame(outer, padding=(8, 6, 8, 10))
        body.grid(row=1, column=0, sticky="nsew")

        section = {
            "title": title,
            "outer": outer,
            "header": header,
            "body": body,
            "label": label,
        }
        self._collapsible_sections.append(section)
        return outer, body

    # ----------------------------------------------------------------------

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=(8, 8, 8, 12))
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)
        container.rowconfigure(1, weight=0)

        notebook = ttk.Notebook(container)
        notebook.grid(row=0, column=0, sticky="nsew")
        self.notebook = notebook

        scan_tab = ttk.Frame(notebook, padding=(8, 8, 8, 10))
        network_tab = ttk.Frame(notebook, padding=(8, 8, 8, 10))
        results_tab = ttk.Frame(notebook, padding=(8, 8, 8, 10))
        for tab in (scan_tab, network_tab, results_tab):
            tab.columnconfigure(0, weight=1)
        notebook.add(scan_tab, text="Scan")
        notebook.add(network_tab, text="Network")
        notebook.add(results_tab, text="Results")

        scan_body = ttk.Frame(scan_tab)
        scan_body.pack(fill="both", expand=True)
        scan_body.columnconfigure(0, weight=1)

        self._threads_display = tk.StringVar(value=f"{self.current_concurrency} (active 0)")

        controls = ttk.Frame(scan_body)
        controls.pack(fill="x", padx=4, pady=(0, 8))
        self.btn_start = ttk.Button(controls, text="Start", width=10, command=self.start_scan, style=self._primary_button_style)
        self.btn_pause = ttk.Button(controls, text="Pause", width=10, command=self.pause_scan, state="disabled")
        self.btn_resume = ttk.Button(controls, text="Resume", width=10, command=self.resume_scan, state="disabled")
        self.btn_stop = ttk.Button(controls, text="Stop", width=10, command=self.stop_scan, state="disabled")
        self.btn_start.pack(side="left")
        self.btn_pause.pack(side="left", padx=(6, 0))
        self.btn_resume.pack(side="left", padx=(6, 0))
        self.btn_stop.pack(side="left", padx=(6, 0))
        self.btn_open_folder = ttk.Button(controls, text="Open Output Folder", width=18, command=self.open_output_folder)
        self.btn_change_save = ttk.Button(controls, text="Change Save Folder", width=18, command=self.change_save_directory)
        self.btn_clear_logs = ttk.Button(controls, text="Clear Logs", width=12, command=self.clear_logs)
        self.btn_open_folder.pack(side="right", padx=(0, 6))
        self.btn_change_save.pack(side="right", padx=(0, 6))
        self.btn_clear_logs.pack(side="right")

        settings_grid = ttk.Frame(scan_body)
        settings_grid.pack(fill="x", padx=4, pady=(0, 6))
        settings_grid.columnconfigure(0, weight=1)
        settings_grid.columnconfigure(1, weight=1)

        settings_section, settings = self._create_collapsible_section(settings_grid, "Scan Settings")
        settings_section.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
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
        ttk.Label(settings, text="Base delay (ms)").grid(row=1, column=2, sticky="w", padx=(0, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_scan_delay, width=8).grid(row=1, column=3, sticky="w", padx=(0, 12), pady=4)
        ttk.Label(settings, text="Max delay (ms)").grid(row=1, column=4, sticky="w", padx=(0, 4), pady=4)
        ttk.Entry(settings, textvariable=self.var_scan_delay_max, width=8).grid(row=1, column=5, sticky="w", padx=(0, 12), pady=4)

        options_section, options = self._create_collapsible_section(settings_grid, "Scan Options")
        options_section.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        for idx in range(4):
            options.columnconfigure(idx, weight=1)
        ttk.Checkbutton(options, text="Randomize IP order", variable=self.var_random).grid(row=0, column=0, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Require ping response", variable=self.var_require_ping).grid(row=0, column=1, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Auto thread limit", variable=self.var_auto_limit).grid(row=0, column=2, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(options, text="Dark mode", variable=self.var_dark_mode, command=self._toggle_theme).grid(row=0, column=3, sticky="w", padx=8, pady=2)
        ttk.Checkbutton(
            options,
            text="Adaptive scan delay",
            variable=self.var_adaptive_delay,
            command=self._on_adaptive_delay_toggle,
        ).grid(row=1, column=0, sticky="w", padx=8, pady=2)

        tools_section, tools = self._create_collapsible_section(scan_body, "Verification & Tools")
        tools_section.pack(fill="x", padx=4, pady=(0, 6))
        tools.columnconfigure(1, weight=1)
        tools.columnconfigure(3, weight=1)
        svc_text = f"Services: mcstatus {'ON' if _mcstatus_available else 'OFF'} | nmap {'ON' if _nmap_available else 'OFF'}"
        ttk.Label(tools, text=svc_text, style=self._muted_label_style).grid(row=0, column=0, columnspan=4, sticky="w", padx=8, pady=(6, 4))
        ttk.Label(tools, text="Host override").grid(row=1, column=0, sticky="w", padx=(8, 4), pady=4)
        self.var_host_override = tk.StringVar(value="")
        self.var_host_override.trace_add("write", self._on_host_override_change)
        self._on_host_override_change()
        ttk.Entry(tools, textvariable=self.var_host_override).grid(row=1, column=1, sticky="ew", padx=(0, 12), pady=4)
        ttk.Label(tools, text="Direct test host").grid(row=1, column=2, sticky="w", padx=(0, 4), pady=4)
        self.var_test_host = tk.StringVar(value="")
        ttk.Entry(tools, textvariable=self.var_test_host).grid(row=1, column=3, sticky="ew", padx=(0, 12), pady=4)
        ttk.Button(tools, text="Run Test", command=self.run_direct_test).grid(row=1, column=4, sticky="w", padx=(0, 8), pady=4)

        quick_and_perf = ttk.Frame(scan_body)
        quick_and_perf.pack(fill="both", expand=True, padx=4, pady=(0, 6))
        quick_and_perf.columnconfigure(0, weight=1)
        quick_and_perf.columnconfigure(1, weight=1)
        quick_and_perf.rowconfigure(1, weight=1)

        stats_section, stats = self._create_collapsible_section(quick_and_perf, "Quick Stats")
        stats_section.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
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

        perf_section, perf = self._create_collapsible_section(quick_and_perf, "Performance")
        perf_section.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        for col in range(3):
            perf.columnconfigure(col, weight=1)
        perf_vars = [self.s_elapsed, self.s_eta, self.s_ips, self.s_rps, self.s_fpm, self.s_avgping, self.s_hit, self.s_cpu, self.s_ram]
        for idx, var in enumerate(perf_vars):
            row, col = divmod(idx, 3)
            ttk.Label(perf, textvariable=var).grid(row=row, column=col, sticky="w", padx=8, pady=4)

        quick_log_section, quick_log_frame = self._create_collapsible_section(quick_and_perf, "Live Log")
        quick_log_section.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        quick_log_frame.columnconfigure(0, weight=1)
        quick_log_frame.rowconfigure(0, weight=1)
        self.quick_log = scrolledtext.ScrolledText(
            quick_log_frame,
            state="disabled",
            height=8,
            font=("Consolas", 9),
            relief="flat",
            borderwidth=0,
        )
        self.quick_log.grid(row=0, column=0, sticky="nsew")

        network_body = ttk.Frame(network_tab)
        network_body.pack(fill="both", expand=True)
        network_body.columnconfigure(0, weight=1)

        proxy_section, proxy_frame = self._create_collapsible_section(network_body, "Proxy Pool")
        proxy_section.pack(fill="both", expand=True, padx=4, pady=(0, 6))
        proxy_frame.columnconfigure(0, weight=1)
        proxy_frame.columnconfigure(1, weight=0)
        proxy_frame.rowconfigure(1, weight=1)
        proxy_frame.rowconfigure(3, weight=1)
        proxy_header = ttk.Frame(proxy_frame)
        proxy_header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(6, 2))
        proxy_header.columnconfigure(0, weight=1)
        proxy_header.columnconfigure(1, weight=0)
        proxy_header.columnconfigure(2, weight=0)
        ttk.Label(proxy_header, textvariable=self.var_proxy_summary).grid(row=0, column=0, sticky="w")
        ttk.Label(proxy_header, textvariable=self.var_proxy_health_hint, style=self._muted_label_style).grid(row=0, column=1, sticky="e", padx=(0, 8))
        self.btn_toggle_proxy = ttk.Button(
            proxy_header,
            text="Disable Proxies" if self._proxy_enabled else "Enable Proxies",
            width=16,
            command=self.toggle_proxy_usage,
        )
        self.btn_toggle_proxy.grid(row=0, column=2, sticky="e")
        proxy_columns = ("proxy", "status", "latency", "ok", "pfail", "tfail")
        self.proxy_tree = ttk.Treeview(proxy_frame, columns=proxy_columns, show="headings", height=9)
        for col, title, width, anchor in [
            ("proxy", "Proxy", 160, "w"),
            ("status", "Status", 130, "w"),
            ("latency", "Latency (ms)", 110, "center"),
            ("ok", "OK", 70, "center"),
            ("pfail", "Proxy Fail", 100, "center"),
            ("tfail", "Target Fail", 100, "center"),
        ]:
            self.proxy_tree.heading(col, text=title, anchor=anchor)
            self.proxy_tree.column(
                col,
                width=width,
                anchor=anchor,
                stretch=False if col in {"latency", "ok", "pfail", "tfail"} else True,
            )
        proxy_scroll = ttk.Scrollbar(proxy_frame, orient="vertical", command=self.proxy_tree.yview)
        self.proxy_tree.configure(yscrollcommand=proxy_scroll.set)
        self.proxy_tree.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 4))
        proxy_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 4))
        ttk.Label(proxy_frame, text="Proxy Log").grid(row=2, column=0, sticky="w", padx=8, pady=(6, 2))
        self.proxy_log = scrolledtext.ScrolledText(
            proxy_frame,
            height=8,
            state="disabled",
            font=("Consolas", 9),
            relief="flat",
            borderwidth=0,
        )
        self.proxy_log.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 6))

        vpn_section, vpn_frame = self._create_collapsible_section(network_body, "VPN Control")
        vpn_section.pack(fill="x", padx=4, pady=(0, 6))
        vpn_controls = ttk.Frame(vpn_frame)
        vpn_controls.pack(fill="x", padx=8, pady=(4, 0))
        self.chk_mullvad = ttk.Checkbutton(
            vpn_controls,
            text="Cycle Mullvad every 120s during scans",
            variable=self.var_mullvad_cycle,
            command=self._on_mullvad_toggle,
        )
        self.chk_mullvad.pack(side="left", padx=0, pady=4)
        self.btn_mullvad_now = ttk.Button(vpn_controls, text="Run Mullvad Cycle Now", width=22, command=self.run_mullvad_cycle_now)
        self.btn_mullvad_now.pack(side="left", padx=(6, 0), pady=4)
        ttk.Label(vpn_controls, text="Cycle after", style=self._muted_label_style).pack(side="left", padx=(8, 0), pady=4)
        self.ent_mullvad_cycle_scans = ttk.Entry(vpn_controls, width=7, textvariable=self.var_vpn_cycle_scans, justify="center")
        self.ent_mullvad_cycle_scans.pack(side="left", padx=(2, 0), pady=4)
        ttk.Label(vpn_controls, text="scans", style=self._muted_label_style).pack(side="left", padx=(2, 0), pady=4)
        mullvad_hint = "Mullvad CLI ready" if self.vpn_manager.cli_path else "Mullvad CLI missing"
        self.lbl_mullvad_status = ttk.Label(vpn_controls, text=mullvad_hint, style=self._muted_label_style)
        self.lbl_mullvad_status.pack(side="right", padx=8, pady=4)

        results_body = ttk.Frame(results_tab)
        results_body.pack(fill="both", expand=True)
        results_body.columnconfigure(0, weight=1)

        results_section, results_frame = self._create_collapsible_section(results_body, "Results & Logs")
        results_section.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        results_paned = ttk.Panedwindow(results_frame, orient="horizontal")
        results_paned.grid(row=0, column=0, sticky="nsew")

        left = ttk.Frame(results_paned)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=2)
        left.rowconfigure(1, weight=1)
        right = ttk.Frame(results_paned)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.rowconfigure(2, weight=0)
        results_paned.add(left, weight=3)
        results_paned.add(right, weight=4)

        log_section, log_frame = self._create_collapsible_section(left, "Log")
        log_section.grid(row=0, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, state="disabled", height=14, font=("Consolas", 9), relief="flat", borderwidth=0)
        self.log.grid(row=0, column=0, sticky="nsew")

        ctl_section, ctl_frame = self._create_collapsible_section(left, "Control Log")
        ctl_section.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        ctl_frame.columnconfigure(0, weight=1)
        ctl_frame.rowconfigure(0, weight=1)
        self.ctl = scrolledtext.ScrolledText(ctl_frame, state="disabled", height=6, font=("Consolas", 9), relief="flat", borderwidth=0)
        self.ctl.grid(row=0, column=0, sticky="nsew")

        columns = ("address", "version", "players", "confidence", "motd", "found", "ping", "bars", "hint")
        servers_section, servers_frame = self._create_collapsible_section(right, "Confirmed Minecraft Servers")
        servers_section.grid(row=0, column=0, sticky="nsew")
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

        mcols = ("address", "reason", "hint", "seen", "last_try")
        maybe_section, maybe_frame = self._create_collapsible_section(right, "Potential Servers")
        maybe_section.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        maybe_frame.columnconfigure(0, weight=1)
        maybe_frame.rowconfigure(0, weight=1)
        self.maybe_tree = ttk.Treeview(maybe_frame, columns=mcols, show="headings", selectmode="extended", height=6)
        for col, title, width, anc in [
            ("address", "Address / IP", 200, "w"),
            ("reason", "Confidence", 130, "center"),
            ("hint", "Notes", 160, "w"),
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
        self.btn_copy_sel = ttk.Button(actions_right, text="Copy Selected", width=18, command=self.copy_selected)
        self.btn_recheck = ttk.Button(actions_right, text="Recheck Selected", width=18, command=self.recheck_selected_servers)
        self.btn_del_sel = ttk.Button(actions_right, text="Delete Selected", width=18, command=self.delete_selected)
        self.btn_del_all = ttk.Button(actions_right, text="Clear Potential", width=18, command=self.delete_all_maybe)
        self.btn_copy_sel.pack(side="left")
        self.btn_recheck.pack(side="left", padx=(6, 0))
        self.btn_del_sel.pack(side="left", padx=(6, 0))
        self.btn_del_all.pack(side="left", padx=(6, 0))

        footer = ttk.Frame(container, padding=(4, 4, 4, 0))
        footer.grid(row=1, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        footer.columnconfigure(1, weight=0)

        self.save_hint = tk.StringVar(value=f"Saves to: {self.storage.output_path}")
        self.lbl_save_hint = ttk.Label(footer, textvariable=self.save_hint, style=self._muted_label_style)
        self.lbl_save_hint.grid(row=0, column=0, sticky="w")

        self.status = tk.StringVar(value="Ready")
        self.lbl_status = ttk.Label(footer, textvariable=self.status, style="Status.TLabel")
        self.lbl_status.grid(row=0, column=1, sticky="e")

        self._refresh_proxy_health_ui()
        self._update_proxy_toggle_button()
        self.btn_mullvad_now.config(state="normal" if self.vpn_manager.cli_path else "disabled")
        self._update_mullvad_label()
        self._apply_theme()

        self.root.after(120, self._pump_ui)
        self.root.after(500, self._tick)
        self.root.after(1000, self._update_threads_stat)

    def _init_proxy_pool(self):
        """Load Mullvad proxy endpoints and attach health callback."""
        path = None
        try:
            path = _resolve_resource_path("mcsmartscan", "mullvadproxyips.txt")
        except Exception:
            path = None
        pool = None
        if path is not None and path.exists():
            pool = ProxyPool.from_file(path, default_port=1080, event_callback=self._handle_proxy_event)
            if pool.total <= 0:
                pool = None
        if pool:
            self.proxy_pool = pool
            self._proxy_enabled = True
            self._uiq_put(("log", f"[PROXY] Loaded {pool.total} Mullvad proxy endpoints.", "info"))
        else:
            self.proxy_pool = None
            self._proxy_enabled = False
            if path:
                if path.exists():
                    self._uiq_put(("log", f"[PROXY] No proxies found at {path}", "warn"))
                else:
                    self._uiq_put(("log", f"[PROXY] Proxy list missing at {path}", "warn"))
            else:
                self._uiq_put(("log", "[PROXY] Failed to resolve proxy list path.", "warn"))

    def toggle_proxy_usage(self):
        """Toggle proxy usage on or off from the UI."""
        if not self.proxy_pool:
            messagebox.showwarning(
                "Proxy Unavailable",
                "No proxy endpoints are loaded. Add proxies to enable this feature.",
            )
            self._proxy_enabled = False
            self._update_proxy_toggle_button()
            self._refresh_proxy_health_ui()
            return
        self._proxy_enabled = not self._proxy_enabled
        if self._proxy_enabled:
            self.proxy_pool.prepare_for_run()
            self._proxy_log("[PROXY] Proxy usage enabled.", "info")
            self.var_proxy_health_hint.set("Proxy usage enabled")
        else:
            self._proxy_log("[PROXY] Proxy usage disabled.", "info")
            self.var_proxy_health_hint.set("Proxy usage disabled")
        self._update_proxy_toggle_button()
        self._refresh_proxy_health_ui()

    def _update_proxy_toggle_button(self):
        """Ensure the proxy toggle button reflects availability and state."""
        if not hasattr(self, "btn_toggle_proxy"):
            return
        if not self.proxy_pool:
            self.btn_toggle_proxy.configure(text="Enable Proxies", state="disabled")
            return
        btn_text = "Disable Proxies" if self._proxy_enabled else "Enable Proxies"
        self.btn_toggle_proxy.configure(text=btn_text, state="normal")

    def _handle_proxy_event(self, event: dict) -> None:
        """Receive async events from the proxy pool."""
        if not isinstance(event, dict):
            return
        event = dict(event)
        event.setdefault("type", "info")
        self._uiq_put(("proxy-event", event))

    def _ensure_full_cpu_affinity(self):
        """Allow the process to run on all logical CPUs when possible."""
        if not psutil:
            return
        try:
            proc = psutil.Process()
            if hasattr(proc, "cpu_affinity"):
                logical = psutil.cpu_count(logical=True) or os.cpu_count() or 1
                desired = list(range(max(1, logical)))
                current = proc.cpu_affinity()
                if set(current) != set(desired):
                    proc.cpu_affinity(desired)
        except Exception:
            pass

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

    def _on_adaptive_delay_toggle(self, *args):
        enabled = bool(self.var_adaptive_delay.get())
        self.adaptive_delay_enabled = enabled
        if not enabled:
            self._adaptive_scan_delay = self._base_scan_delay
        else:
            if self._adaptive_scan_delay <= 0.0:
                self._adaptive_scan_delay = self._base_scan_delay
            self._adaptive_scan_delay = max(self._base_scan_delay, min(self._max_scan_delay, self._adaptive_scan_delay))
        self._last_delay_adjust = time.time()

    def _on_host_override_change(self, *args):
        value = self.var_host_override.get().strip()
        self._host_override_for_scan = value or None

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

        try:
            style.configure(self._section_frame_style,
                            background=palette["bg"],
                            borderwidth=1,
                            relief="solid",
                            bordercolor=palette["border"])
        except Exception:
            style.configure(self._section_frame_style, background=palette["bg"])
        style.configure(self._section_header_style, background=palette["bg_alt"])
        style.configure(self._section_label_style, background=palette["bg_alt"], foreground=palette["accent"])

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

        for section in getattr(self, "_collapsible_sections", []):
            header = section.get("header")
            outer = section.get("outer")
            label = section.get("label")
            try:
                if header:
                    header.configure(style=self._section_header_style)
            except Exception:
                pass
            try:
                if outer:
                    outer.configure(style=self._section_frame_style)
            except Exception:
                pass
            try:
                if label:
                    label.configure(style=self._section_label_style)
            except Exception:
                pass

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
        if hasattr(self, "proxy_tree"):
            try:
                self.proxy_tree.configure(style=self._tree_style)
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
                self.log.tag_config("muted", foreground=palette["muted"])
            except Exception:
                pass
        if hasattr(self, "quick_log"):
            try:
                self.quick_log.configure(bg=palette["bg_alt"], fg=palette["fg"], insertbackground=palette["fg"], highlightthickness=0, borderwidth=0)
                for tag, colour in [
                    ("green", palette["success"]),
                    ("orange", palette["warn"]),
                    ("blue", palette["info"]),
                    ("red", palette["danger"]),
                    ("info", palette["muted"]),
                    ("muted", palette["muted"]),
                ]:
                    self.quick_log.tag_config(tag, foreground=colour)
            except Exception:
                pass
        if hasattr(self, "proxy_log"):
            try:
                self.proxy_log.configure(
                    bg=palette["bg_alt"],
                    fg=palette["fg"],
                    insertbackground=palette["fg"],
                    highlightthickness=0,
                    borderwidth=0,
                )
                for tag, colour in [
                    ("info", palette["muted"]),
                    ("warn", palette["warn"]),
                    ("error", palette["danger"]),
                    ("success", palette["success"]),
                ]:
                    self.proxy_log.tag_config(tag, foreground=colour)
            except Exception:
                pass
        if hasattr(self, "ctl"):
            try:
                self.ctl.configure(bg=palette["bg_alt"], fg=palette["fg"], insertbackground=palette["fg"], highlightthickness=0, borderwidth=0)
                self.ctl.tag_config("info", foreground=palette["fg"])
                self.ctl.tag_config("warn", foreground=palette["warn"])
                self.ctl.tag_config("error", foreground=palette["danger"])
                self.ctl.tag_config("vpn", foreground=palette["info"])
                self.ctl.tag_config("threads", foreground=palette["accent"])
                self.ctl.tag_config("scan", foreground=palette["success"])
                self.ctl.tag_config("maybe", foreground=palette["warn"])
                self.ctl.tag_config("files", foreground=palette["accent"])
                self.ctl.tag_config("server", foreground=palette["success"])
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

    def _ctl_async(self, msg: str, tag: str = None):
        if not msg:
            return
        self._run_on_ui(self._ctl_log, msg, tag)

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
        self._ctl_async(msg, tag="vpn")
        self._stop.clear()
        self._pause.clear()
        with self._vpn_cycle_lock:
            self._scans_since_vpn_cycle = 0
        self._vpn_guard_triggered = False
        self._update_scan_delay_settings()
        self._adaptive_scan_delay = self._base_scan_delay
        self._on_adaptive_delay_toggle()
        self.var_icmp.set(0); self.var_port.set(0); self.var_mc.set(0); self.var_total.set(0)
        self.ping_attempts = 0
        self.ping_failures = 0
        self.failed_window.clear()
        self._ping_sum = 0.0; self._ping_count = 0
        self.processed = 0
        self._stable_ok_windows = 0
        self.start_time = time.time()
        self.scanning = True
        self._host_override_for_scan = self.var_host_override.get().strip() or None

        # Allowed public vars only
        self.max_concurrency = max(1, int(self.var_threads.get()))
        self.current_concurrency = self.max_concurrency
        if self.proxy_pool and self._proxy_enabled:
            self.proxy_pool.prepare_for_run()
            proxy_total = self.proxy_pool.total
            if proxy_total <= 0:
                self._proxy_enabled = False
                self.var_proxy_summary.set("Proxies unavailable")
            else:
                if self.max_concurrency > proxy_total:
                    self.max_concurrency = proxy_total
                    self._ctl_async(
                        f"[PROXY] Limiting concurrency to {proxy_total} to match proxy count.",
                        tag="threads",
                    )
                self.current_concurrency = self.max_concurrency
                self.var_proxy_summary.set(f"Proxies loaded: {proxy_total} (in use 0)")
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
                delay_ms = self._current_delay_ms()
                if delay_ms > 0:
                    jitter = random.uniform(0.0, min(delay_ms, 50.0))
                    actual_delay = min(self._max_scan_delay, delay_ms + jitter)
                    time.sleep(actual_delay / 1000.0)
                else:
                    # Add slight jitter to mimic organic traffic even when delay is zero
                    time.sleep(random.uniform(0.0, 0.003))
                try:
                    with self._active_tasks_lock:
                        self._active_tasks += 1
                    if self.executor:
                        lease = None
                        if self.proxy_pool and self._proxy_enabled:
                            try:
                                lease = self.proxy_pool.acquire(timeout=1.0)
                            except ProxyAcquireTimeout:
                                with self._active_tasks_lock:
                                    self._active_tasks = max(0, self._active_tasks - 1)
                                self._uiq_put(("proxy-log", f"[PROXY] No available proxy for {ip}", "warn"))
                                time.sleep(0.05)
                                continue
                        self.executor.submit(self._worker_wrapper, ip, timeout, lease)
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
    def _update_scan_delay_settings(self):
        """Refresh cached delay settings from UI variables."""
        try:
            base = max(0.0, float(self.var_scan_delay.get()))
        except Exception:
            base = 0.0
        try:
            max_delay = float(self.var_scan_delay_max.get())
        except Exception:
            max_delay = base
        if not math.isfinite(base):
            base = 0.0
        if not math.isfinite(max_delay):
            max_delay = base
        max_delay = max(base, max_delay)
        self._base_scan_delay = base
        self._max_scan_delay = max_delay
        return base, max_delay

    def _update_delay_from_rate(self, failure_rate: float):
        """Adjust adaptive delay based on recent failure rate."""
        base, max_delay = self._update_scan_delay_settings()
        if not self.adaptive_delay_enabled:
            self._adaptive_scan_delay = base
            self._last_delay_adjust = time.time()
            return self._adaptive_scan_delay
        rate = max(0.0, min(1.0, failure_rate))
        span = max(0.0, max_delay - base)
        target = base + span * rate
        if not math.isfinite(target):
            target = base
        if self._adaptive_scan_delay <= 0.0:
            blended = target
        else:
            blended = (self._adaptive_scan_delay * 0.6) + (target * 0.4)
        self._adaptive_scan_delay = max(base, min(max_delay, blended))
        self._last_delay_adjust = time.time()
        return self._adaptive_scan_delay

    def _current_delay_ms(self):
        """Return the current per-submit delay in milliseconds."""
        base, max_delay = self._base_scan_delay, self._max_scan_delay
        if not self.adaptive_delay_enabled:
            return max(0.0, base)
        if max_delay <= 0.0 and base <= 0.0:
            return 0.0
        return max(base, min(max_delay, self._adaptive_scan_delay))

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
        window = list(self.failed_window)
        if len(window) > 120:
            window = window[-120:]
        rate = (sum(window) / len(window)) if window else 0.0
        now = time.time()
        if not self.auto_limit_on:
            if self.adaptive_delay_enabled:
                self._update_delay_from_rate(0.0)
            else:
                self._adaptive_scan_delay = self._base_scan_delay
                self._last_delay_adjust = now
            return
        if self.adaptive_delay_enabled:
            self._update_delay_from_rate(rate)
        else:
            self._adaptive_scan_delay = self._base_scan_delay
            self._last_delay_adjust = now
        if now - self._last_auto_change < self.auto_limit_cooldown:
            return
        if len(window) < 60:
            return
        if rate >= self.auto_limit_threshold:
            with self._concurrency_lock:
                new_limit = max(8, int(self.current_concurrency * 0.7))
                if new_limit < self.current_concurrency:
                    self.current_concurrency = new_limit
                    self._last_auto_change = now
                    msg = f"[Auto] High ping failures {rate*100:.1f}% - threads={self.current_concurrency}"
                    self._uiq_put(("log", msg, "orange"))
                    self._ctl_async(msg, tag="threads")
            self._stable_ok_windows = 0
        else:
            if self.current_concurrency < self.max_concurrency:
                self._stable_ok_windows += 1
                if self._stable_ok_windows >= 3:
                    with self._concurrency_lock:
                        self.current_concurrency = min(self.max_concurrency, self.current_concurrency + 10)
                        self._last_auto_change = now
                        msg = f"[Auto] Stable - threads={self.current_concurrency}"
                        self._uiq_put(("log", msg, "info"))
                        self._ctl_async(msg, tag="threads")
                    self._stable_ok_windows = 0
            else:
                self._stable_ok_windows = 0

    def _worker_wrapper(self, ip, timeout, lease=None):
        try:
            self._worker(ip, timeout, lease)
        finally:
            if lease:
                try:
                    lease.close()
                except Exception:
                    pass
            with self._active_tasks_lock:
                self._active_tasks = max(0, self._active_tasks - 1)

    def _worker(self, ip, timeout, lease=None):
        try:
            if self._stop.is_set() or self._pause.is_set():
                return
            self.last_checked[ip] = time.time()

            self.var_total.set(self.var_total.get() + 1)
            self.processed += 1

            # Single ping attempt - track stats, but DO NOT log failures to main log
            try:
                base_t = float(self.var_timeout.get())
            except Exception:
                base_t = float(self.var_timeout)
            dyn_timeout = self._adaptive_timeout(max(1e-3, base_t))

            connector = lease.connector if lease else _direct_connector
            active_connector = connector

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
                self._uiq_put(("log", f"{ip} - ping failed", "muted"))
                if self.var_require_ping.get():
                    self._auto_limit_evaluate()
                    return

            # Ports (log concise open/closed only)
            open_java = False
            java_rtt = None
            attempts = 0
            while attempts < 3:
                try:
                    open_java, java_rtt = check_port(ip, DEFAULT_PORT, dyn_timeout, connector=active_connector)
                    break
                except ProxyTargetError as exc:
                    self._uiq_put(("proxy-log", f"[PROXY] Target refused via proxy for {ip}: {exc}", "warn"))
                    open_java = False
                    break
                except ProxyHandshakeError as exc:
                    attempts += 1
                    label = getattr(lease, "label", "direct")
                    self._uiq_put(("proxy-log", f"[PROXY] {label} handshake failed for {ip}: {exc}", "error"))
                    if active_connector is _direct_connector or not (self.proxy_pool and self._proxy_enabled):
                        self._uiq_put(("log", f"{ip} - proxy handshake failed, skipping", "orange"))
                        self._auto_limit_evaluate()
                        return
                    if lease:
                        try:
                            lease.close()
                        except Exception:
                            pass
                        lease = None
                    try:
                        lease = self.proxy_pool.acquire(timeout=1.5)
                        active_connector = lease.connector
                        self._uiq_put(("proxy-log", f"[PROXY] Swapped to {lease.label} after failure on {ip}", "info"))
                    except ProxyAcquireTimeout:
                        active_connector = _direct_connector
                        self._uiq_put(("proxy-log", f"[PROXY] Falling back to direct connection for {ip}", "warn"))
            else:
                open_java = False

            connector = active_connector
            if connector is _direct_connector and lease:
                try:
                    lease.close()
                except Exception:
                    pass
                lease = None

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
            if self._stop.is_set():
                return
            if open_java:
                self.var_port.set(self.var_port.get() + 1)
                self.open_ports.add(ip)
                try:
                    self._append_open_port_to_file(f"{ip}:{DEFAULT_PORT}")
                except Exception:
                    pass
                self._save_current_blob()
                ok2, info2, conf2, sources2 = _extra_fallback_probe(
                    ip,
                    dyn_timeout,
                    handshake_host=self._host_override_for_scan,
                    connector=connector,
                )
                addr = f"{ip}:{DEFAULT_PORT}"
                if ok2:
                    conf_label = self._normalize_confidence(conf2, "Possible")
                    confidence_lower = (conf_label or "").lower()
                    if confidence_lower in {"possible", "unlikely"}:
                        info = self._add_maybe_server(addr, reason=confidence_lower, hint="java")
                        if info["created"] or info["reason_changed"]:
                            self._ctl_async(f"[MAYBE] {addr} recorded ({conf_label})", tag="maybe")
                        self._uiq_put(("log", f"{addr} - possible Java server ({conf_label})", "orange"))
                    else:
                        players = info2.get("players") if isinstance(info2, dict) else None
                        maxp = info2.get("max") if isinstance(info2, dict) else None
                        version = (info2.get("version") if isinstance(info2, dict) else "-") or "-"
                        motd = ((info2.get("motd") if isinstance(info2, dict) else "") or "").replace("\n", " ")[:120]
                        hint = info2.get("hint") if isinstance(info2, dict) else None
                        pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                        rec = {
                            "address": addr,
                            "version": version,
                            "players": pstr,
                            "motd": motd,
                            "confidence": conf_label,
                            "found_at": datetime.now().isoformat(timespec="seconds"),
                            "ping": rtt if ok_ping else None,
                            "bars": ping_to_bars(rtt if ok_ping else None),
                            "hint": hint or (", ".join(sorted(sources2)) if sources2 else ""),
                        }
                        existing = next((s for s in self.servers if s.get("address") == addr), None)
                        if existing:
                            existing.update(rec)
                        else:
                            self.servers.append(rec)
                            self.known_confirmed.add(addr)
                            self.var_mc.set(self.var_mc.get() + 1)
                            self._append_server_to_file(addr, version, pstr, conf_label, motd)
                            self.refresh_table(incremental=rec)
                        self._remove_maybe_server(addr)
                        self._save_current_blob(immediate=True)
                        origin = ", ".join(sorted(sources2)) if sources2 else "unknown"
                        self._ctl_async(f"[MC] {addr} confirmed ({conf_label}) via {origin}", tag="server")
                        self._uiq_put(("log", f"{addr} confirmed ({conf_label}) via {origin}", "green"))
                else:
                    info = self._add_maybe_server(addr, reason="possible", hint="port-open")
                    if info["created"] or info["reason_changed"]:
                        self._ctl_async(f"[MAYBE] {addr} open but no protocol response", tag="maybe")
                    self._uiq_put(("log", f"{addr} open but no reliable Minecraft signature detected.", "orange"))

            if self._stop.is_set():
                return

            if ok_bedrock and info_b:
                addr_b = f"{ip}:{DEFAULT_BEDROCK_PORT}"
                conf_b = self._normalize_confidence("Possible", "Possible")
                conf_b_lower = conf_b.lower()
                if conf_b_lower in {"possible", "unlikely"}:
                    info = self._add_maybe_server(addr_b, reason=conf_b_lower, hint="bedrock")
                    if info["created"] or info["reason_changed"]:
                        self._ctl_async(f"[MAYBE] {addr_b} recorded ({conf_b})", tag="maybe")
                    self._uiq_put(("log", f"{addr_b} bedrock response ({conf_b})", "blue"))
                else:
                    version = info_b.get("version", "-") or "-"
                    players = info_b.get("players")
                    maxp = info_b.get("max")
                    pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                    motd = (info_b.get("motd") or "").replace("\n", " ")[:120]
                    rec = {
                        "address": addr_b,
                        "version": version,
                        "players": pstr,
                        "motd": motd,
                        "confidence": conf_b,
                        "found_at": datetime.now().isoformat(timespec="seconds"),
                        "ping": rtt_b,
                        "bars": ping_to_bars(rtt_b),
                        "hint": "Bedrock",
                    }
                    existing = next((s for s in self.servers if s.get("address") == addr_b), None)
                    if existing:
                        existing.update(rec)
                    else:
                        self.servers.append(rec)
                        self.known_confirmed.add(addr_b)
                        self.var_mc.set(self.var_mc.get() + 1)
                        try:
                            self._append_open_port_to_file(addr_b)
                        except Exception:
                            pass
                        self._append_server_to_file(addr_b, version, pstr, conf_b, motd)
                        self.refresh_table(incremental=rec)
                    self._remove_maybe_server(addr_b)
                    self._save_current_blob(immediate=True)
                    self._ctl_async(f"[MC] {addr_b} confirmed ({conf_b}) via bedrock ping", tag="server")
                    self._uiq_put(("log", f"{addr_b} confirmed via bedrock", "green"))
            elif ok_bedrock:
                addr_b = f"{ip}:{DEFAULT_BEDROCK_PORT}"
                info = self._add_maybe_server(addr_b, reason="possible", hint="bedrock-port")
                if info["created"] or info["reason_changed"]:
                    self._ctl_async(f"[MAYBE] {addr_b} recorded (bedrock port)", tag="maybe")

            if not self._stop.is_set():
                self._auto_limit_evaluate()
        except Exception as exc:
            self._uiq_put(("log", f"{ip} - worker error: {exc}", "red"))
            self._ctl_async(f"[ERROR] Worker failure on {ip}: {exc}")
        finally:
            self._vpn_register_scan()
            self._uiq_put(("processed", 1))
# ============================== SECTION 7: AUTO LIMIT / WORKER (END) ================================

# ============================== SECTION 8: GUI HELPERS / STATS / TICK (START) ==============================
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
        lease = None
        connector = _direct_connector
        if self.proxy_pool and self._proxy_enabled:
            try:
                lease = self.proxy_pool.acquire(timeout=2.0)
                connector = lease.connector
                self._proxy_log(f"[PROXY] Test using {lease.label}", "info")
            except ProxyAcquireTimeout:
                lease = None
                connector = _direct_connector
        try:
            ok, rtt = ping_host(target, timeout)
            if ok:
                self._log_info(f"[TEST] Ping to {target} succeeded" + (f" ({rtt:.1f} ms)" if rtt is not None else ""))
            else:
                self._log_info(f"[TEST] Ping to {target} failed")

            open_ok, rtt2 = check_port(target, 25565, timeout, connector=connector)
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
                    okp, info, _ = confirm_minecraft_by_protocol(target, 25565, timeout, connector=connector)
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
        finally:
            if lease:
                try:
                    lease.close()
                except Exception:
                    pass

    def _pump_ui(self):
        """
        Drain queued UI messages and refresh counters.
        Only log real log/events; ignore metric/progress messages.
        """
        try:
            drained = 0
            proxy_logs = []
            proxy_events = []
            while not self._uiq.empty() and drained < 500:
                item = self._uiq.get_nowait()
                drained += 1

                msg, tag = None, "info"

                if isinstance(item, str):
                    msg = item
                elif isinstance(item, tuple):
                    kind = item[0]
                    if len(item) >= 2 and kind == "log":
                        msg = item[1]
                        if len(item) >= 3 and isinstance(item[2], str):
                            tag = item[2]
                    elif len(item) >= 2 and kind == "proxy-log":
                        proxy_logs.append((item[1], item[2] if len(item) >= 3 else "info"))
                        continue
                    elif len(item) >= 2 and kind == "proxy-event":
                        proxy_events.append(item[1])
                        continue
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
                    if hasattr(self, "quick_log"):
                        self.quick_log.configure(state="normal")
                        self.quick_log.insert("end", msg + "\n", tag)
                        try:
                            line_count = int(self.quick_log.index("end-1c").split(".")[0])
                        except Exception:
                            line_count = 0
                        if line_count > 400:
                            start_line = max(1, line_count - 300)
                            try:
                                self.quick_log.delete("1.0", f"{start_line}.0")
                            except Exception:
                                pass
                        self.quick_log.configure(state="disabled")
                        self.quick_log.see("end")
                except Exception:
                    print(msg)
        except Exception:
            pass

        if proxy_events:
            for event in proxy_events:
                self._handle_proxy_event_ui(event)
            self._refresh_proxy_health_ui()

        if proxy_logs:
            for log_msg, log_tag in proxy_logs:
                self._proxy_log(log_msg, log_tag)

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
        self._ctl_async(msg, tag="info")

    def _resolve_ctl_tag(self, msg: str, explicit: str = None) -> str:
        if explicit:
            return explicit
        lower = (msg or "").lower()
        if "[vpn" in lower or "mullvad" in lower or "[lockdown" in lower:
            return "vpn"
        if "[auto]" in lower or "threads=" in lower:
            return "threads"
        if lower.startswith("[scan]"):
            return "scan"
        if lower.startswith("[recheck]") or "[mc]" in lower:
            return "server"
        if "[maybe]" in lower or "potential" in lower:
            return "maybe"
        if "[files]" in lower or "folder" in lower or "save" in lower:
            return "files"
        if lower.startswith("[warn]") or "warn" in lower:
            return "warn"
        if lower.startswith("[error]") or "error" in lower:
            return "error"
        return "info"

    def _ctl_log(self, msg: str, tag: str = None):
        resolved_tag = self._resolve_ctl_tag(msg, tag)
        try:
            if hasattr(self, "ctl"):
                self.ctl.configure(state="normal")
                self.ctl.insert("end", msg + "\n", resolved_tag)
                self.ctl.configure(state="disabled")
                self.ctl.see("end")
            else:
                print(msg)
        except Exception:
            print(msg)

    def _proxy_log(self, msg: str, tag: str = "info"):
        if not msg:
            return
        try:
            if hasattr(self, "proxy_log"):
                self.proxy_log.configure(state="normal")
                self.proxy_log.insert("end", str(msg) + "\n", tag)
                self.proxy_log.configure(state="disabled")
                self.proxy_log.see("end")
            else:
                print(msg)
        except Exception:
            print(msg)

    def _handle_proxy_event_ui(self, event: dict) -> None:
        if not isinstance(event, dict):
            return
        kind = event.get("type") or "info"
        label = event.get("proxy") or "?"
        if kind == "proxy-failure":
            stage = event.get("stage")
            error = event.get("error") or "proxy failure"
            detail = f"[PROXY] {label} failure: {error}"
            if stage:
                detail += f" ({stage})"
            self._proxy_log(detail, "error")
        elif kind == "target-failure":
            error = event.get("error") or "target failure"
            self._proxy_log(f"[PROXY] {label} target error: {error}", "warn")
        elif kind == "success":
            latency = event.get("latency_ms")
            if latency is not None:
                self.var_proxy_health_hint.set(f"{label} success {latency:.1f} ms")
        elif kind == "proxy-quarantine":
            duration = float(event.get("duration") or 0.0)
            consecutive = event.get("consecutive")
            extra = f" after {consecutive} failures" if consecutive is not None else ""
            self._proxy_log(f"[PROXY] {label} quarantined for {duration:.1f}s{extra}", "warn")
            self.var_proxy_health_hint.set(f"{label} quarantine {duration:.0f}s")
        elif kind == "proxy-disabled":
            duration = float(event.get("duration") or 0.0)
            reason = event.get("reason") or "cool-off"
            self._proxy_log(f"[PROXY] {label} disabled for {duration:.0f}s ({reason})", "error")
            self.var_proxy_health_hint.set(f"{label} disabled {duration:.0f}s")
        elif kind == "proxy-restored":
            self._proxy_log(f"[PROXY] {label} restored to pool", "success")
            self.var_proxy_health_hint.set(f"{label} restored")
        elif kind == "release":
            cooldown = float(event.get("cooldown") or 0.0)
            self.var_proxy_health_hint.set(f"{label} released ({cooldown:.1f}s cooldown)")
        elif kind == "acquire":
            self.var_proxy_health_hint.set(f"{label} in use")

    def _refresh_proxy_health_ui(self):
        if not hasattr(self, "proxy_tree"):
            return
        if not self.proxy_pool:
            self.proxy_tree.delete(*self.proxy_tree.get_children())
            self.var_proxy_summary.set("Proxies disabled")
            self.var_proxy_health_hint.set("")
            self._update_proxy_toggle_button()
            return
        snapshot = self.proxy_pool.health_snapshot()
        self._proxy_snapshot = snapshot
        total = len(snapshot)
        in_use = sum(1 for item in snapshot if item.get("in_use"))
        disabled_count = sum(1 for item in snapshot if (item.get("disabled") or 0) > 0.05)
        quarantine_count = sum(
            1
            for item in snapshot
            if (item.get("quarantine") or 0) > 0.05 and (item.get("disabled") or 0) <= 0.05
        )
        cooling = sum(
            1
            for item in snapshot
            if (
                not item.get("in_use")
                and (item.get("cooldown") or 0) > 0.05
                and (item.get("quarantine") or 0) <= 0.05
                and (item.get("disabled") or 0) <= 0.05
            )
        )
        idle = max(0, total - in_use - cooling - quarantine_count - disabled_count)
        summary_parts = [f"Proxies {total}", f"in use {in_use}"]
        if disabled_count:
            summary_parts.append(f"disabled {disabled_count}")
        if quarantine_count:
            summary_parts.append(f"quarantine {quarantine_count}")
        if cooling:
            summary_parts.append(f"cooling {cooling}")
        summary_parts.append(f"idle {idle}")
        summary = " | ".join(summary_parts)
        if not self._proxy_enabled:
            summary += " (disabled)"
        self.var_proxy_summary.set(summary)
        existing = set(self.proxy_tree.get_children())
        for item_id in existing:
            self.proxy_tree.delete(item_id)
        for entry in snapshot:
            label = entry.get("label", "?")
            cooldown = float(entry.get("cooldown") or 0.0)
            quarantine = float(entry.get("quarantine") or 0.0)
            disabled = float(entry.get("disabled") or 0.0)
            disabled_reason = entry.get("disabled_reason")
            in_use_flag = bool(entry.get("in_use"))
            if in_use_flag:
                status = "In use"
            elif disabled > 0.05:
                reason_hint = ""
                if disabled_reason:
                    hint = str(disabled_reason)
                    if len(hint) > 28:
                        hint = hint[:27] + "…"
                    reason_hint = f" ({hint})"
                status = f"Disabled {disabled:.0f}s{reason_hint}"
            elif quarantine > 0.05:
                status = f"Quarantine {quarantine:.1f}s"
            elif cooldown > 0.05:
                status = f"Cooling {cooldown:.1f}s"
            else:
                status = "Idle"
            last_stage = entry.get("last_stage")
            last_error = entry.get("last_error")
            if last_error and not in_use_flag:
                status = f"{status} ({last_stage or 'error'})"
            latency = entry.get("last_latency_ms")
            latency_str = f"{latency:.1f}" if latency is not None else "-"
            self.proxy_tree.insert(
                "",
                "end",
                values=(
                    label,
                    status,
                    latency_str,
                    entry.get("successes", 0),
                    entry.get("proxy_failures", 0),
                    entry.get("target_failures", 0),
                ),
            )
        self._update_proxy_toggle_button()
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
            rec.get("hint", ""),
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
            return {"created": False, "reason_changed": False, "record": None}
        now = datetime.now().isoformat(timespec="seconds")
        created = False
        reason_changed = False
        with self._maybe_lock:
            existing = None
            for rec in self.maybe_list:
                if rec.get("address") == address:
                    existing = rec
                    break
            if existing:
                prev_reason = existing.get("reason")
                prev_hint = existing.get("hint")
                existing["last_try"] = now
                if reason:
                    existing["reason"] = reason
                if hint:
                    existing["hint"] = hint
                reason_changed = bool(reason and reason != prev_reason)
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
                created = True
        self._run_on_ui(self._refresh_single_maybe_ui, updated)
        self._save_current_blob(immediate=True)
        return {"created": created, "reason_changed": reason_changed, "record": updated}

    def _remove_maybe_server(self, address):
        if not address:
            return False
        removed = False
        with self._maybe_lock:
            if address in self.known_maybe:
                self.known_maybe.discard(address)
                self.maybe_list = [rec for rec in self.maybe_list if rec.get("address") != address]
                removed = True
        if removed:
            self._run_on_ui(self._delete_maybe_row_ui, address)
            self._save_current_blob(immediate=True)
        return removed

    def _load_saved_servers(self):
        """Load saved state into memory and tables."""
        data = self.storage.load_state() or {}

        raw_servers = data.get("servers", [])
        normalized_servers = []
        for rec in raw_servers:
            if not isinstance(rec, dict):
                continue
            copy = dict(rec)
            copy["confidence"] = self._normalize_confidence(copy.get("confidence", "Possible"), "Possible")
            normalized_servers.append(copy)
        self.servers = normalized_servers

        raw_maybe = data.get("maybe", [])
        sanitized_maybe = []
        now_iso = datetime.now().isoformat(timespec="seconds")
        for rec in raw_maybe:
            if not isinstance(rec, dict):
                continue
            address = rec.get("address")
            if not address:
                continue
            sanitized_maybe.append(
                {
                    "address": address,
                    "reason": rec.get("reason", "possible"),
                    "hint": rec.get("hint", ""),
                    "seen": rec.get("seen") or now_iso,
                    "last_try": rec.get("last_try") or rec.get("seen") or now_iso,
                }
            )
        self.maybe_list = sanitized_maybe
        self.open_ports = set(data.get("open_ports", []))

        self.known_confirmed = {rec.get("address") for rec in self.servers if rec.get("address")}
        self.known_maybe = {rec.get("address") for rec in self.maybe_list if rec.get("address")}

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
                        rec.get("reason", "possible"),
                        rec.get("hint", ""),
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
                address = rec.get("address", "-")
                for iid in self.tree.get_children():
                    vals = self.tree.item(iid, "values")
                    if vals and vals[0] == address:
                        self.tree.delete(iid)
                        break
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
        if hasattr(self, "quick_log"):
            try:
                self.quick_log.configure(state="normal")
                self.quick_log.delete("1.0", "end")
                self.quick_log.configure(state="disabled")
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
            self._ctl_async("Logs cleared.", tag="info")
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
            self._ctl_async(f"[FILES] Opened folder: {folder}", tag="files")
        except Exception as e:
            self._ctl_async(f"[FILES] Open folder failed: {e}", tag="error")

    def change_save_directory(self):
        """Allow the user to pick a new directory for server persistence."""
        if not _gui_available:
            self._ctl_async("[FILES] Save directory change requires GUI mode.", tag="warn")
            return
        try:
            initial = self.storage.base_dir or os.getcwd()
            new_dir = filedialog.askdirectory(initialdir=initial, title="Select save directory")
        except Exception as exc:
            self._ctl_async(f"[FILES] Directory picker failed: {exc}", tag="error")
            return
        if not new_dir:
            return
        self._prepare_outfile(base_dir=new_dir)
        self.save_hint.set(f"Saves to: {self.storage.output_path}")
        self._save_current_blob(immediate=True)
        self._ctl_async(f"[FILES] Save directory set to {self.storage.base_dir}", tag="files")

    # ------------------------------ COPY / DELETE ACTIONS ----------------------------
    def copy_selected(self):
        """Copy selected server rows to the clipboard."""
        try:
            lines = []
            if hasattr(self, "tree"):
                for iid in self.tree.selection():
                    vals = self.tree.item(iid, "values")
                    if vals:
                        addr, version, players, confidence, *_ = vals
                        lines.append(f"{addr} | {version} | {players} | {confidence}")
            if hasattr(self, "maybe_tree"):
                for iid in self.maybe_tree.selection():
                    vals = self.maybe_tree.item(iid, "values")
                    if vals:
                        addr, reason, hint, *_ = vals
                        detail = f"{addr} ({reason})"
                        if hint:
                            detail += f" - {hint}"
                        lines.append(detail)
            if not lines:
                self._ctl_async("No entries selected to copy.", tag="warn")
                return
            text = "\n".join(lines)
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
            except Exception:
                self._ctl_async("Clipboard unavailable; writing copy buffer to log.", tag="warn")
                for line in lines:
                    self._ctl_async(line, tag="info")
                return
            self._ctl_async(f"Copied {len(lines)} item(s) to clipboard.", tag="info")
        except Exception as e:
            self._ctl_async(f"Copy failed: {e}", tag="error")

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

            # From Potential servers
            if hasattr(self, "maybe_tree"):
                for iid in self.maybe_tree.selection():
                    vals = self.maybe_tree.item(iid, "values")
                    addr = vals[0] if vals and len(vals) > 0 else None
                    if addr:
                        self._remove_maybe_server(addr)

            self._save_current_blob(immediate=True)
            self._ctl_async("Selected entries deleted.", tag="info")
        except Exception as e:
            self._ctl_async(f"Delete failed: {e}", tag="error")

    def delete_all_maybe(self):
        """Clear the entire Maybe/Open-ports table and memory list."""
        try:
            if hasattr(self, "maybe_tree"):
                for iid in list(self.maybe_tree.get_children()):
                    vals = self.maybe_tree.item(iid, "values")
                    addr = vals[0] if vals and len(vals) > 0 else None
                    if addr:
                        self._remove_maybe_server(addr)
            with self._maybe_lock:
                self.maybe_list = []
                self.known_maybe = set()
            self._save_current_blob(immediate=True)
            self._ctl_async("Cleared all potential server entries.", tag="maybe")
        except Exception as e:
            self._ctl_async(f"Delete-all failed: {e}", tag="error")

    def _remove_confirmed_row_ui(self, address):
        if not hasattr(self, "tree"):
            return
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if vals and vals[0] == address:
                self.tree.delete(iid)
                break

    def _remove_confirmed_server(self, address):
        if not address:
            return False
        removed = False
        for idx, rec in enumerate(list(self.servers)):
            if rec.get("address") == address:
                self.servers.pop(idx)
                removed = True
                break
        if removed:
            self.known_confirmed.discard(address)
            self._run_on_ui(self._remove_confirmed_row_ui, address)
        return removed

    def _parse_address_port(self, address: str):
        if not address:
            return None, DEFAULT_PORT
        if ":" in address:
            host, port_str = address.rsplit(":", 1)
            try:
                port = int(port_str)
            except Exception:
                port = DEFAULT_PORT
            return host.strip(), port
        return address.strip(), DEFAULT_PORT

    def recheck_selected_servers(self):
        """Trigger a verification pass for selected server entries."""
        selections = []
        if hasattr(self, "tree"):
            for iid in self.tree.selection():
                vals = self.tree.item(iid, "values")
                if vals:
                    selections.append(vals[0])
        if hasattr(self, "maybe_tree"):
            for iid in self.maybe_tree.selection():
                vals = self.maybe_tree.item(iid, "values")
                if vals:
                    selections.append(vals[0])
        addresses = list(dict.fromkeys(addr for addr in selections if addr))
        if not addresses:
            self._ctl_async("Select at least one server to recheck.", tag="warn")
            return
        self._ctl_async(f"[RECHECK] Checking {len(addresses)} server(s)...", tag="server")
        threading.Thread(target=self._run_recheck_batch, args=(addresses,), daemon=True).start()

    def _run_recheck_batch(self, addresses):
        refresh_confirmed = False
        for address in addresses:
            try:
                result = self._recheck_single_address(address)
                refresh_confirmed = refresh_confirmed or result.get("refresh_confirmed", False)
            except Exception as exc:
                self._uiq_put(("log", f"{address} - recheck error: {exc}", "red"))
                self._ctl_async(f"[RECHECK] {address} error: {exc}", tag="error")
        if refresh_confirmed:
            self._run_on_ui(self.refresh_table)
        self._save_current_blob(immediate=True)
        self._ctl_async("[RECHECK] Completed.", tag="server")

    def _recheck_single_address(self, address):
        result = {"refresh_confirmed": False}
        ip, port = self._parse_address_port(address)
        if not ip:
            return result
        try:
            base_timeout = max(1e-3, float(self.var_timeout.get()))
        except Exception:
            base_timeout = max(1e-3, float(self.var_timeout))
        dyn_timeout = self._adaptive_timeout(base_timeout)
        lease = None
        connector = _direct_connector
        if self.proxy_pool and self._proxy_enabled:
            try:
                lease = self.proxy_pool.acquire(timeout=2.0)
                connector = lease.connector
            except ProxyAcquireTimeout:
                lease = None
                connector = _direct_connector
        ok_ping, rtt = ping_host(ip, dyn_timeout)
        if not ok_ping:
            self._uiq_put(("log", f"{address} - recheck ping failed", "muted"))

        if port == DEFAULT_PORT:
            open_java, _ = check_port(ip, DEFAULT_PORT, dyn_timeout, connector=connector)
            if not open_java:
                if self._remove_confirmed_server(address):
                    result["refresh_confirmed"] = True
                info = self._add_maybe_server(address, reason="port-closed", hint="recheck")
                if info["created"] or info["reason_changed"]:
                    self._ctl_async(f"[RECHECK] {address} -> port closed", tag="maybe")
                self._uiq_put(("log", f"{address} recheck: port 25565 closed", "orange"))
                if lease:
                    try:
                        lease.close()
                    except Exception:
                        pass
                return result
            ok2, info2, conf2, sources2 = _extra_fallback_probe(
                ip,
                dyn_timeout,
                handshake_host=self._host_override_for_scan,
                connector=connector,
            )
            if ok2:
                conf_label = self._normalize_confidence(conf2, "Possible")
                conf_lower = (conf_label or "").lower()
                hint = (info2 or {}).get("hint") if isinstance(info2, dict) else None
                players = info2.get("players") if isinstance(info2, dict) else None
                maxp = info2.get("max") if isinstance(info2, dict) else None
                version = (info2.get("version") if isinstance(info2, dict) else "-") or "-"
                motd = ((info2.get("motd") if isinstance(info2, dict) else "") or "").replace("\n", " ")[:120]
                pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                rec = {
                    "address": address,
                    "version": version,
                    "players": pstr,
                    "confidence": conf_label,
                    "motd": motd,
                    "found_at": datetime.now().isoformat(timespec="seconds"),
                    "ping": rtt if ok_ping else None,
                    "bars": ping_to_bars(rtt if ok_ping else None),
                    "hint": hint or (", ".join(sorted(sources2)) if sources2 else ""),
                }
                if conf_lower in {"possible", "unlikely"}:
                    if self._remove_confirmed_server(address):
                        result["refresh_confirmed"] = True
                    info = self._add_maybe_server(address, reason=conf_lower, hint=rec["hint"] or "java")
                    if info["created"] or info["reason_changed"]:
                        self._ctl_async(f"[RECHECK] {address} -> {conf_label}", tag="maybe")
                    self._uiq_put(("log", f"{address} recheck: confidence {conf_label}", "orange"))
                else:
                    existing = next((s for s in self.servers if s.get("address") == address), None)
                    if existing:
                        existing.update(rec)
                    else:
                        self.servers.append(rec)
                        self.known_confirmed.add(address)
                    self._remove_maybe_server(address)
                    result["refresh_confirmed"] = True
                    self._ctl_async(f"[RECHECK] {address} confirmed ({conf_label})", tag="server")
                    self._uiq_put(("log", f"{address} recheck confirmed ({conf_label})", "green"))
            else:
                if self._remove_confirmed_server(address):
                    result["refresh_confirmed"] = True
                info = self._add_maybe_server(address, reason="no-response", hint="recheck")
                if info["created"] or info["reason_changed"]:
                    self._ctl_async(f"[RECHECK] {address} -> no protocol response", tag="maybe")
                self._uiq_put(("log", f"{address} recheck: no Java protocol response", "orange"))
            return result

        if port == DEFAULT_BEDROCK_PORT:
            ok_bedrock, info_b, rtt_b = bedrock_ping(ip, DEFAULT_BEDROCK_PORT, dyn_timeout)
            if ok_bedrock and info_b:
                conf_label = self._normalize_confidence("Possible", "Possible")
                conf_lower = conf_label.lower()
                players = info_b.get("players")
                maxp = info_b.get("max")
                pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                version = info_b.get("version", "-") or "-"
                motd = (info_b.get("motd") or "").replace("\n", " ")[:120]
                rec = {
                    "address": address,
                    "version": version,
                    "players": pstr,
                    "confidence": conf_label,
                    "motd": motd,
                    "found_at": datetime.now().isoformat(timespec="seconds"),
                    "ping": rtt_b,
                    "bars": ping_to_bars(rtt_b),
                    "hint": "Bedrock",
                }
                if conf_lower in {"possible", "unlikely"}:
                    if self._remove_confirmed_server(address):
                        result["refresh_confirmed"] = True
                    info = self._add_maybe_server(address, reason=conf_lower, hint="bedrock")
                    if info["created"] or info["reason_changed"]:
                        self._ctl_async(f"[RECHECK] {address} -> {conf_label}", tag="maybe")
                    self._uiq_put(("log", f"{address} recheck: bedrock response ({conf_label})", "blue"))
                else:
                    existing = next((s for s in self.servers if s.get("address") == address), None)
                    if existing:
                        existing.update(rec)
                    else:
                        self.servers.append(rec)
                        self.known_confirmed.add(address)
                    self._remove_maybe_server(address)
                    result["refresh_confirmed"] = True
                    self._ctl_async(f"[RECHECK] {address} confirmed via Bedrock", tag="server")
                    self._uiq_put(("log", f"{address} recheck confirmed via Bedrock", "green"))
            else:
                if self._remove_confirmed_server(address):
                    result["refresh_confirmed"] = True
                info = self._add_maybe_server(address, reason="no-response", hint="bedrock-recheck")
                if info["created"] or info["reason_changed"]:
                    self._ctl_async(f"[RECHECK] {address} -> bedrock response missing", tag="maybe")
                self._uiq_put(("log", f"{address} recheck: bedrock response missing", "orange"))
            if lease:
                try:
                    lease.close()
                except Exception:
                    pass
            return result

        open_generic, _ = check_port(ip, port, dyn_timeout, connector=connector)
        if not open_generic:
            if self._remove_confirmed_server(address):
                result["refresh_confirmed"] = True
            info = self._add_maybe_server(address, reason="port-closed", hint=f"port-{port}")
            if info["created"] or info["reason_changed"]:
                self._ctl_async(f"[RECHECK] {address} -> port {port} closed", tag="maybe")
            self._uiq_put(("log", f"{address} recheck: port {port} closed", "orange"))
        else:
            self._ctl_async(f"[RECHECK] {address} port {port} open (no parser available)", tag="info")
            self._uiq_put(("log", f"{address} recheck: port {port} open (no parser)", "blue"))
        if lease:
            try:
                lease.close()
            except Exception:
                pass
        return result
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
            self.failed_window = deque(maxlen=240)

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
