# ============================== SECTION 1: IMPORTS / CONSTANTS / GLOBALS (START) ==============================
import os, sys, time, json, math, socket, threading, queue, subprocess, platform, re, hashlib, random
from datetime import datetime
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor
from collections import deque

try:
    import psutil
except Exception:
    psutil = None

# optional graphs
_HAVE_MPL = False

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

IS_WINDOWS = platform.system().lower().startswith("win")
DEFAULT_START_IP = "40.0.0.0"
DEFAULT_END_IP = "255.255.255.255"

DEFAULT_PORT = 25565                 # Java
DEFAULT_BEDROCK_PORT = 19132         # Bedrock (UDP)

DEFAULT_TIMEOUT = 4.0
DEFAULT_WORKERS = 150
OUTSTANDING_FACTOR = 2
MAX_QUEUE = 20000
OUTPUT_FILENAME = "Minecraft_Servers.txt"
SAVED_SERVERS_FILE = "saved_servers.json"

PROTOCOL_CANDIDATES = [768, 767, 766, 765, 764, 763, 760, 759, 758, 757, 756, 755, 754, 498, 340, 316, 210, 110, 47]
_PING_TIME_RE = re.compile(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_PING_TTL_RE = re.compile(r"\bttl[=\s:]\s*\d+", re.IGNORECASE)
_ping_signal_bars = [(60,5),(100,4),(150,3),(250,2),(999999,1)]

PROTOCOL_TO_VERSION_HINT = {
    768:"1.21.x", 767:"1.21.x", 766:"1.21.x", 765:"1.21.x", 764:"1.20.6-1.21", 763:"1.20.5",
    760:"1.20.2-1.20.4", 759:"1.20.1", 758:"1.20", 757:"1.19.4", 756:"1.19.3", 755:"1.19-1.19.2",
    754:"1.16.5-1.17.1", 498:"1.14.4", 340:"1.12.2", 316:"1.11.2", 210:"1.10.2", 110:"1.9.4", 47:"1.8.x"
}

DEFAULT_RETRIES = 2
RETRY_BACKOFF_BASE = 0.2
TCP_FALLBACK_DEFAULT = False
PER_IP_COOLDOWN = 20.0
GLOBAL_BACKOFF_SECS = 12.0
PROBE_JITTER_MS = 25.0

# analytics + autotune
ANALYTICS_PUSH_EVERY = 5.0       # seconds between datapoints
AUTOTUNE_EVERY       = 15.0      # seconds between tuning decisions
ANALYTICS_WINDOW_SEC = 60 * 15   # keep last 15 minutes of datapoints
AUTOTUNE_LIMITS = {
    "timeout":        (1.0, 8.0),    # seconds
    "retries":        (0, 4),
    "backoff_base":   (0.05, 0.8),   # seconds
    "per_ip_cd":      (5.0, 120.0),  # seconds
    "global_backoff": (0.0, 30.0),   # seconds
}

BEDROCK_MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'  # RakNet magic
# ============================== SECTION 1: IMPORTS / CONSTANTS / GLOBALS (END) ================================

# ============================== SECTION 2: PATHS / PERSISTENCE / UTILS (START) ================================
def get_desktop_path():
    home = os.path.expanduser("~")
    system = platform.system().lower()
    candidates = [os.path.join(home, "Desktop")]
    if "windows" in system:
        candidates += [os.path.join(home, "OneDrive", "Desktop")]
    if "darwin" in system or "mac" in system:
        candidates += [os.path.join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "Desktop")]
    for p in candidates:
        if os.path.isdir(p):
            return p
    try:
        os.makedirs(os.path.join(home, "Desktop"), exist_ok=True)
        return os.path.join(home, "Desktop")
    except Exception:
        return home

DESKTOP_DIR = get_desktop_path()
OUT_PATH = os.path.join(DESKTOP_DIR, OUTPUT_FILENAME)
SAVED_PATH = os.path.join(DESKTOP_DIR, SAVED_SERVERS_FILE)

def safe_write_line(path, line):
    try:
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(line)
    except Exception:
        pass

def load_saved_blob():
    try:
        if os.path.exists(SAVED_PATH):
            with open(SAVED_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    return {"confirmed": data, "maybe": [], "open_ports": []}
    except Exception:
        pass
    return {"confirmed": [], "maybe": [], "open_ports": []}

def save_saved_blob(blob):
    try:
        with open(SAVED_PATH, "w", encoding="utf-8") as f:
            json.dump(blob, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def ip_range_size(a, b):
    sa = int(IPv4Address(a)); sb = int(IPv4Address(b))
    if sb < sa: sa, sb = sb, sa
    return (sb - sa) + 1

def ip_range_generator(a, b):
    sa = int(IPv4Address(a)); sb = int(IPv4Address(b))
    if sb < sa: sa, sb = sb, sa
    for i in range(sa, sb + 1):
        yield str(IPv4Address(i))

def permuted_index_generator(a, b, seed=None, rounds=4):
    sa = int(IPv4Address(a)); sb = int(IPv4Address(b))
    if sb < sa: sa, sb = sb, sa
    N = (sb - sa) + 1
    if N <= 0: return
    if seed is None:
        seed = hashlib.sha256(str(time.time()).encode()).digest()
    bits = max(1, math.ceil(math.log2(N)))
    domain = 1 << bits
    Lbits = bits // 2
    Rbits = bits - Lbits
    Lmask = (1 << Lbits) - 1
    Rmask = (1 << Rbits) - 1
    def feistel(x):
        L = (x >> Rbits) & Lmask
        R = x & Rmask
        for r in range(rounds):
            h = hashlib.sha256()
            h.update(seed); h.update(bytes([r & 0xFF])); h.update(R.to_bytes((Rbits+7)//8 or 1, "big"))
            F = int.from_bytes(h.digest(), "big") & Lmask
            L, R = R, (L ^ F) & Lmask
        return ((L << Rbits) | R) & (domain - 1)
    for i in range(domain):
        p = feistel(i)
        if p < N:
            yield str(IPv4Address(sa + p))

def ping_to_bars(ms):
    if ms is None:
        return 0
    for cutoff, bars in _ping_signal_bars:
        if ms < cutoff:
            return bars
    return 0
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
# ============================== SECTION 3: PROBES / PROTOCOL (END) ============================================

# ============================== SECTION 4: GUI CLASS — INIT + UI (START) ======================================
class ScannerAppGUI:
    def __init__(self, root):
        self.root = root
        root.title("Minecraft Scanner — Hybrid Backend")

        # --- Core state ---
        self._stop = threading.Event()
        self._pause = threading.Event(); self._pause.clear()
        self.executor = None
        self._uiq = queue.Queue(maxsize=MAX_QUEUE)
        self.start_time = None
        self.scanning = False

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

        # --- Threading / autotune ---
        self.current_concurrency = DEFAULT_WORKERS
        self.max_concurrency = DEFAULT_WORKERS
        self.auto_limit_on = True
        self.failed_window = []
        self.auto_limit_threshold = 0.95
        self.auto_limit_window = 120
        self.auto_limit_cooldown = 20
        self._last_auto_change = 0
        self._concurrency_lock = threading.Lock()
        self._active_tasks = 0
        self._active_tasks_lock = threading.Lock()

        # --- Networking / VPN ---
        self._refresh_thread = None
        self._refresh_stop = threading.Event()
        self._refresh_tick = 10.0
        self._host_override_for_scan = None
        self._stable_ok_windows = 0
        self._last_mullvad_reconnect = 0
        self.mullvad_cooldown = 120
        self._backoff_bias = 0.0

        # --- Tk variables ---
        self.var_start        = tk.StringVar(value=DEFAULT_START_IP)
        self.var_end          = tk.StringVar(value=DEFAULT_END_IP)
        self.var_threads      = tk.IntVar(value=DEFAULT_WORKERS)
        self.var_failthr      = tk.DoubleVar(value=self.auto_limit_threshold * 100.0)
        self.var_random       = tk.BooleanVar(value=True)
        self.var_require_ping = tk.BooleanVar(value=True)
        self.var_auto_limit   = tk.BooleanVar(value=True)

        self.var_timeout      = tk.DoubleVar(value=DEFAULT_TIMEOUT)
        self.var_retries      = tk.IntVar(value=DEFAULT_RETRIES)
        self.var_backoff_ms   = tk.DoubleVar(value=RETRY_BACKOFF_BASE * 1000.0)
        self.var_cooldown     = tk.DoubleVar(value=PER_IP_COOLDOWN)
        self.var_gbackoff     = tk.DoubleVar(value=GLOBAL_BACKOFF_SECS)
        self.var_jitter       = tk.DoubleVar(value=PROBE_JITTER_MS)
        self.var_tcp_fallback = tk.BooleanVar(value=TCP_FALLBACK_DEFAULT)

        # --- Non-Tk mirrors for logic paths ---
        self.retry_count = DEFAULT_RETRIES
        self.retry_backoff_base = RETRY_BACKOFF_BASE
        self.tcp_fallback = TCP_FALLBACK_DEFAULT
        self.per_ip_cooldown = PER_IP_COOLDOWN
        self.global_backoff_secs = GLOBAL_BACKOFF_SECS
        self._global_backoff_until = 0.0
        self.probe_jitter_ms = PROBE_JITTER_MS

        # --- Analytics / Autotune handles ---
        self._analytics_lock = threading.Lock()
        self.analytics = None
        self.autotune  = None

        self._prepare_outfile()
        self._build_ui()
        self._load_saved_servers()
        self._start_refresh_loop()
        self._schedule_analytics()
        self._schedule_autotune()

    # ----------------------------------------------------------------------

    def _build_ui(self):
        top = tk.Frame(self.root); top.pack(fill="x", padx=8, pady=6)

        tk.Label(top, text="Start IP:").grid(row=0, column=0, sticky="w")
        tk.Entry(top, textvariable=self.var_start, width=15).grid(row=0, column=1, sticky="w")

        tk.Label(top, text="End IP:").grid(row=0, column=2, sticky="w", padx=(8,0))
        tk.Entry(top, textvariable=self.var_end, width=15).grid(row=0, column=3, sticky="w")

        tk.Label(top, text="Threads (max):").grid(row=0, column=4, sticky="w", padx=(8,0))
        tk.Entry(top, textvariable=self.var_threads, width=6).grid(row=0, column=5, sticky="w")

        tk.Label(top, text="Fail% threshold").grid(row=0, column=6, sticky="w", padx=(8,0))
        tk.Entry(top, textvariable=self.var_failthr, width=6).grid(row=0, column=7, sticky="w")

        tk.Checkbutton(top, text="Randomize",     variable=self.var_random).grid(row=0, column=8,  padx=(8,0))
        tk.Checkbutton(top, text="Require ping",  variable=self.var_require_ping).grid(row=0, column=9,  padx=(8,0))
        tk.Checkbutton(top, text="Auto thread limit", variable=self.var_auto_limit).grid(row=0, column=10, padx=(8,0))

        # --- Host row ---
        hostrow = tk.Frame(self.root); hostrow.pack(fill="x", padx=8, pady=(2,4))
        tk.Label(hostrow, text=f"svc verify: inline | nmap: {'on' if _nmap_available else 'off'}").pack(side="left")
        tk.Label(hostrow, text="   Host override:").pack(side="left", padx=(12,0))
        self.var_host_override = tk.StringVar(value="")
        tk.Entry(hostrow, textvariable=self.var_host_override, width=28).pack(side="left", padx=(6,10))
        tk.Label(hostrow, text="Direct Test host:").pack(side="left")
        self.var_test_host = tk.StringVar(value="")
        tk.Entry(hostrow, textvariable=self.var_test_host, width=28).pack(side="left", padx=(6,6))
        tk.Button(hostrow, text="Run Test", command=self.run_direct_test).pack(side="left")

        # --- Buttons ---
        btn = tk.Frame(self.root); btn.pack(fill="x", padx=8, pady=(4,0))
        self.btn_start  = tk.Button(btn, text="Start",  width=10, command=self.start_scan);   self.btn_start.pack(side="left")
        self.btn_pause  = tk.Button(btn, text="Pause",  width=10, command=self.pause_scan,  state="disabled"); self.btn_pause.pack(side="left", padx=(6,0))
        self.btn_resume = tk.Button(btn, text="Resume", width=10, command=self.resume_scan, state="disabled"); self.btn_resume.pack(side="left", padx=(6,0))
        self.btn_stop   = tk.Button(btn, text="Stop",   width=10, command=self.stop_scan,   state="disabled"); self.btn_stop.pack(side="left", padx=(6,0))
        self.btn_del_sel  = tk.Button(btn, text="Delete Selected",   width=16, command=self.delete_selected);   self.btn_del_sel.pack(side="left", padx=(10,0))
        self.btn_del_all  = tk.Button(btn, text="Delete All Maybe",  width=16, command=self.delete_all_maybe);  self.btn_del_all.pack(side="left", padx=(6,0))
        self.btn_clear_logs = tk.Button(btn, text="Clear Logs", width=12, command=self.clear_logs); self.btn_clear_logs.pack(side="right")

        # --- Quick stats ---
        stats = tk.Frame(self.root); stats.pack(fill="x", padx=8)
        self.var_icmp = tk.IntVar(value=0)
        self.var_port = tk.IntVar(value=0)
        self.var_mc   = tk.IntVar(value=0)
        self.var_total = tk.IntVar(value=0)
        self.var_failed_pct = tk.StringVar(value="0.00%")

        tk.Label(stats, text="Replied:").pack(side="left");      tk.Label(stats, textvariable=self.var_icmp, fg="green").pack(side="left", padx=(4,12))
        tk.Label(stats, text="Port open:").pack(side="left");     tk.Label(stats, textvariable=self.var_port, fg="orange").pack(side="left", padx=(4,12))
        tk.Label(stats, text="Minecraft:").pack(side="left");     tk.Label(stats, textvariable=self.var_mc, fg="darkgreen").pack(side="left", padx=(4,12))
        tk.Label(stats, text="Total scanned:").pack(side="left"); tk.Label(stats, textvariable=self.var_total).pack(side="left", padx=(4,12))
        tk.Label(stats, text="Failed %:").pack(side="left");      tk.Label(stats, textvariable=self.var_failed_pct).pack(side="left", padx=(4,12))

        # --- Logs + tables ---
        mid = tk.Frame(self.root); mid.pack(fill="both", expand=True, padx=8, pady=(6,8))
        left = tk.Frame(mid); left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Log:").pack(anchor="w")
        self.log = scrolledtext.ScrolledText(left, state="disabled", height=16, font=("Consolas", 10))
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("green", foreground="#00c853")
        self.log.tag_config("orange", foreground="#ff9800")
        self.log.tag_config("blue", foreground="#1e88e5")
        self.log.tag_config("red", foreground="#e53935")
        self.log.tag_config("info", foreground="#444444")

        tk.Label(left, text="Control Log:").pack(anchor="w")
        self.ctl = scrolledtext.ScrolledText(left, state="disabled", height=8, font=("Consolas", 10))
        self.ctl.pack(fill="both", expand=True, pady=(4,0))

        right = tk.Frame(mid, width=500); right.pack(side="left", fill="both", expand=True, padx=(8,0))
        tk.Label(right, text="Confirmed Minecraft Servers:").pack(anchor="w")
        columns = ("address","version","players","confidence","motd","found","ping","bars","hint")
        self.tree = ttk.Treeview(right, columns=columns, show="headings", height=12)
        for col, title, width, anc in [
            ("address","Address",160,"w"),("version","Version",90,"center"),
            ("players","Players",80,"center"),("confidence","Confidence",85,"center"),
            ("motd","MOTD",220,"w"),("found","Found At",150,"center"),
            ("ping","Ping",80,"center"),("bars","Bars",60,"center"),("hint","Version Hint",110,"center")
        ]:
            self.tree.heading(col, text=title); self.tree.column(col, width=width, anchor=anc)
        tree_scroll_y = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set); tree_scroll_y.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # Maybe + open-ports
        tk.Label(right, text="Maybe Servers + Open Ports:").pack(anchor="w", pady=(6,0))
        mcols = ("address","reason","seen","last_try")
        self.maybe_tree = ttk.Treeview(right, columns=mcols, show="headings", height=6)
        for col, title, width, anc in [
            ("address","Address/IP",200,"w"),("reason","Reason",140,"center"),
            ("seen","First Seen",150,"center"),("last_try","Last Try",150,"center")
        ]:
            self.maybe_tree.heading(col, text=title); self.maybe_tree.column(col, width=width, anchor=anc)
        maybe_scroll_y = ttk.Scrollbar(right, orient="vertical", command=self.maybe_tree.yview)
        self.maybe_tree.configure(yscrollcommand=maybe_scroll_y.set); maybe_scroll_y.pack(side="right", fill="y")
        self.maybe_tree.pack(fill="both", expand=True)

        # --- New unified live settings panel ---
        self.settings_frame = tk.LabelFrame(self.root, text="Current Settings", padx=5, pady=5)
        self.settings_frame.pack(fill="x", padx=8, pady=(4,8))
        self.settings_text = tk.Label(self.settings_frame, text="Loading...", anchor="w", justify="left")
        self.settings_text.pack(fill="x")

        self.save_hint = tk.StringVar(value=f"Saves to: {OUT_PATH}")
        tk.Label(self.root, textvariable=self.save_hint, fg="gray").pack(anchor="w", padx=8)

        self.status = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(0,8))

        # --- Kick off periodic UI updates ---
        self.root.after(120, self._pump_ui)
        self.root.after(500, self._tick)
        self.root.after(1000, self._update_settings_display)
# ============================== SECTION 4: GUI CLASS — INIT + UI (END) ========================================

# ============================== SECTION 5: PERSISTENCE / LOGS / HELPERS (START) ===============================
    def _prepare_outfile(self):
        first = not os.path.exists(OUT_PATH)
        try:
            with open(OUT_PATH, "a", encoding="utf-8") as f:
                if first:
                    f.write("# Columns: ISO8601\tAddress\tVersion\tPlayers\tConfidence\tMOTD\n\n")
        except Exception:
            pass

    def _uiq_put(self, item):
        try:
            self._uiq.put_nowait(item)
        except queue.Full:
            pass

    def _append_server_to_file(self, addr, version, players, confidence, motd):
        key = f"{addr}|{version}|{players}|{confidence}|{motd}"
        if key in self._servers_saved:
            return
        safe_write_line(OUT_PATH, f"{datetime.now().isoformat(timespec='seconds')}\t{addr}\t{version}\t{players}\t{confidence}\t{motd}\n")
        self._servers_saved.add(key)

    def _ctl(self, text):
        self.ctl.config(state="normal")
        self.ctl.insert("end", text + "\n")
        self.ctl.see("end")
        self.ctl.config(state="disabled")

    def _log(self, text, level="info"):
        self.log.config(state="normal")
        color = {"ok":"green","no":"gray","port":"orange","found":"darkgreen","warn":"orange","info":"black"}.get(level,"black")
        self.log.insert("end", text + "\n", level)
        self.log.tag_config(level, foreground=color)
        self.log.see("end")
        self.log.config(state="disabled")

    def _clear_log(self):
        self.log.config(state="normal"); self.log.delete("1.0","end"); self.log.config(state="disabled")

    def _load_saved_servers(self):
        blob = load_saved_blob()
        now = datetime.now().isoformat(timespec="seconds")
        for item in blob.get("confirmed", []):
            addr = item.get("address")
            if not addr:
                continue
            self.known_confirmed.add(addr)
            rec = {
                "address": addr,
                "version": item.get("version","-"),
                "players": item.get("players","?"),
                "motd": item.get("motd",""),
                "confidence": item.get("confidence","single"),
                "found_at": item.get("found_at", now),
                "ping": item.get("ping", None),
                "bars": item.get("bars", 0),
                "hint": item.get("hint", None)
            }
            self.servers.append(rec)
        for entry in blob.get("maybe", []):
            addr = entry.get("address")
            if not addr:
                continue
            self.known_maybe.add(addr)
            self.maybe_list.append({
                "address": addr,
                "reason": entry.get("reason","open-port"),
                "seen": entry.get("seen", now),
                "last_try": entry.get("last_try", now)
            })
        for ip in blob.get("open_ports", []):
            self.open_ports.add(ip)
        self.refresh_table()
        self.refresh_maybe()

    def _save_current_blob(self):
        out_confirmed = []
        for r in self.servers:
            out_confirmed.append({
                "address": r["address"],
                "version": r.get("version","-"),
                "players": r.get("players","?"),
                "motd": r.get("motd",""),
                "confidence": r.get("confidence","single"),
                "found_at": r.get("found_at", datetime.now().isoformat(timespec="seconds")),
                "ping": r.get("ping", None),
                "bars": r.get("bars", 0),
                "hint": r.get("hint", None)
            })
        out_maybe = []
        for m in self.maybe_list:
            out_maybe.append({
                "address": m["address"],
                "reason": m.get("reason","open-port"),
                "seen": m.get("seen", datetime.now().isoformat(timespec="seconds")),
                "last_try": m.get("last_try", datetime.now().isoformat(timespec="seconds"))
            })
        save_saved_blob({"confirmed": out_confirmed, "maybe": out_maybe, "open_ports": sorted(list(self.open_ports))})
# ============================== SECTION 5: PERSISTENCE / LOGS / HELPERS (END) =================================

# ============================== SECTION 6: CONTROLS / SUBMITTER (START) =======================================
    def start_scan(self):
        if self.scanning:
            return
        self._stop.clear()
        self._pause.clear()
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
        self.max_concurrency = max(1, int(self.var_threads.get()))
        self.current_concurrency = self.max_concurrency
        self.auto_limit_on = bool(self.var_auto_limit.get())
        try:
            self.auto_limit_threshold = max(0.50, min(0.999, float(self.var_failthr.get())/100.0))
        except Exception:
            self.auto_limit_threshold = 0.95
        try:
            self.retry_count = max(0, int(self.var_retries.get()))
        except Exception:
            self.retry_count = DEFAULT_RETRIES
        try:
            self.retry_backoff_base = max(0.01, float(self.var_backoff_ms.get())/1000.0)
        except Exception:
            self.retry_backoff_base = RETRY_BACKOFF_BASE
        self.tcp_fallback = bool(self.var_tcp_fallback.get())
        try:
            self.per_ip_cooldown = max(0.0, float(self.var_cooldown.get()))
        except Exception:
            self.per_ip_cooldown = PER_IP_COOLDOWN
        try:
            self.global_backoff_secs = max(0.0, float(self.var_gbackoff.get()))
        except Exception:
            self.global_backoff_secs = GLOBAL_BACKOFF_SECS
        try:
            self.probe_jitter_ms = max(0.0, float(self.var_jitter.get()))
        except Exception:
            self.probe_jitter_ms = PROBE_JITTER_MS
        self._global_backoff_until = 0.0
        self._backoff_bias = 0.0
        self._clear_log()
        self._log(f"Scan start {self.var_start.get()}..{self.var_end.get()} threads={self.max_concurrency} timeout={self.var_timeout.get()} require_ping={self.var_require_ping.get()} svc=inline | nmap={'on' if _nmap_available else 'off'}", "info")
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

    def pause_scan(self):
        if not self.scanning:
            return
        self._pause.set()
        self.btn_pause.config(state="disabled")
        self.btn_resume.config(state="normal")
        self.status.set("Paused")

    def resume_scan(self):
        if not self.scanning:
            return
        self._pause.clear()
        self.btn_pause.config(state="normal")
        self.btn_resume.config(state="disabled")
        self.status.set("Scanning...")

    def stop_scan(self):
        self._stop.set()
        self._pause.clear()
        self.scanning = False
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
        self._save_current_blob()

    def _submitter(self, ip_iter, timeout):
        try:
            if not self.executor:
                return
            for ip in ip_iter:
                if self._stop.is_set():
                    break
                while self._pause.is_set() and not self._stop.is_set():
                    time.sleep(0.05)
                now = time.time()
                if now < self._global_backoff_until:
                    time.sleep(min(0.2, self._global_backoff_until - now))
                    continue
                last_t = self.last_checked.get(ip)
                if last_t is not None and (now - last_t) < self.per_ip_cooldown:
                    continue
                with self._concurrency_lock:
                    allowed = self.current_concurrency
                with self._active_tasks_lock:
                    active = self._active_tasks
                if active >= allowed:
                    time.sleep(0.002 + self._backoff_bias)
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
                    self._uiq_put(("log", f"{ip} - submit failed", "warn"))
        finally:
            if self.executor:
                self.executor.shutdown(wait=True)
            self._uiq_put(("done",))
# ============================== SECTION 6: CONTROLS / SUBMITTER (END) =========================================

# ============================== SECTION 7: AUTO LIMIT / MULLVAD / WORKER (START) ==============================
    def _adaptive_timeout(self, base_timeout):
        if self._ping_count:
            avg = self._ping_sum / max(1, self._ping_count)
            if avg > 0:
                return min(base_timeout * 2.0, max(base_timeout, (avg * 1.8) / 1000.0))
        return base_timeout

    def _ping_with_retries(self, ip, timeout):
        attempts = max(1, 1 + int(self.retry_count))
        base = max(0.01, float(self.retry_backoff_base))
        ok = False; rtt = None; tries = 0
        for i in range(attempts):
            tries = i + 1
            ok, rtt = ping_host(ip, timeout)
            if ok:
                break
            time.sleep(min(timeout, base * (2 ** i) * (1.0 + random.random() * 0.5)))
        return ok, rtt, tries

    def _auto_limit_evaluate(self):
        try:
            self.auto_limit_threshold = max(0.50, min(0.999, float(self.var_failthr.get())/100.0))
        except Exception:
            pass
        if not self.auto_limit_on:
            return
        now = time.time()
        if now - self._last_auto_change < self.auto_limit_cooldown:
            return
        window = self.failed_window[-self.auto_limit_window:] if len(self.failed_window) >= self.auto_limit_window else self.failed_window[:]
        if len(window) < max(50, int(self.auto_limit_window*0.6)):
            return
        rate = sum(1 for x in window if x) / len(window)
        if rate >= self.auto_limit_threshold:
            with self._concurrency_lock:
                new_limit = max(8, int(self.current_concurrency * 0.7))
                if new_limit < self.current_concurrency:
                    self.current_concurrency = new_limit
                    self._last_auto_change = now
                    self._backoff_bias = min(0.02, self._backoff_bias + 0.002)
                    self._uiq_put(("log", f"[Auto] High ping failures {rate:.0%}. Reducing threads to {self.current_concurrency}.", "orange"))
                    self._ctl(f"[Auto] Threads→{self.current_concurrency}")
            if self.global_backoff_secs > 0:
                self._global_backoff_until = max(self._global_backoff_until, now + float(self.global_backoff_secs))
                self._uiq_put(("log", f"[Auto] Global backoff for {int(self.global_backoff_secs)}s", "orange"))
                self._ctl(f"[Auto] GlobalBackoff→{int(self.global_backoff_secs)}s")
        else:
            if self.current_concurrency < self.max_concurrency:
                self._stable_ok_windows += 1
                if self._stable_ok_windows >= 3:
                    with self._concurrency_lock:
                        self.current_concurrency = min(self.max_concurrency, self.current_concurrency + 2)
                        self._last_auto_change = now
                        self._backoff_bias = max(0.0, self._backoff_bias - 0.002)
                        self._uiq_put(("log", f"[Auto] Stable. Increasing threads to {self.current_concurrency}.", "info"))
                        self._ctl(f"[Auto] Threads→{self.current_concurrency}")
                    self._stable_ok_windows = 0
            else:
                self._stable_ok_windows = 0

    def _maybe_mullvad_reconnect(self):
        now = time.time()
        if now - getattr(self, "_last_mullvad_reconnect", 0) < getattr(self, "mullvad_cooldown", 120):
            return
        self._last_mullvad_reconnect = now
        try:
            self._uiq_put(("log", "[Auto] Mullvad reconnecting...", "info"))
            self._ctl("Mullvad reconnect: disconnect")
            subprocess.run(["mullvad", "disconnect"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            time.sleep(1.0)
            self._ctl("Mullvad reconnect: connect")
            subprocess.run(["mullvad", "connect"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            self._uiq_put(("log", "[Auto] Mullvad reconnect done.", "info"))
            self._ctl("Mullvad reconnect: done")
        except Exception as e:
            self._uiq_put(("log", f"[Auto] Mullvad reconnect failed: {e}", "warn"))
            self._ctl(f"Mullvad reconnect error: {e}")

    def _extra_fallback_probe(self, ip, timeout, handshake_host=None):
        nmap_ok = False; nmap_info = None
        try:
            okn, info_n = self._nmap_probe(ip, DEFAULT_PORT, timeout)
            if okn:
                nmap_ok = True
                nmap_info = {"version": (info_n.get("product") or "-"), "players": None, "max": None, "motd": info_n.get("banner") or "", "hint": None}
        except Exception:
            pass
        try:
            ok1, info1, conf1 = confirm_minecraft_by_protocol(ip, DEFAULT_PORT, timeout, handshake_host=handshake_host)
            if ok1:
                if nmap_ok:
                    merged = dict(nmap_info)
                    if info1:
                        if not merged.get("version") or merged["version"] == "-":
                            merged["version"] = info1.get("version","-")
                        merged["players"] = info1.get("players") if merged.get("players") is None else merged["players"]
                        merged["max"] = info1.get("max") if merged.get("max") is None else merged["max"]
                        merged["motd"] = info1.get("motd") or merged.get("motd","")
                        merged["hint"] = info1.get("hint") or merged.get("hint")
                    return True, merged, "dual"
                return True, info1, conf1
            if nmap_ok:
                return True, nmap_info, "single"
            ok3, info3, conf3 = confirm_minecraft_by_protocol(ip, DEFAULT_PORT, timeout, handshake_host=handshake_host)
            return ok3, info3, conf3
        except Exception:
            return False, None, "none"

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
            time.sleep((self.probe_jitter_ms/1000.0) * random.random())
            time.sleep(self._backoff_bias * random.uniform(0.2, 1.5))

            self.var_total.set(self.var_total.get() + 1)
            self.processed += 1
            self._host_override_for_scan = self.var_host_override.get().strip() or None
            dyn_timeout = self._adaptive_timeout(max(1e-3, float(self.var_timeout.get())))

            ok_ping, rtt, tries = self._ping_with_retries(ip, dyn_timeout)
            self.ping_attempts += 1
            if ok_ping:
                self.var_icmp.set(self.var_icmp.get() + 1)
                self._ping_count += 1
                if rtt is not None:
                    self._ping_sum += float(rtt)
                self.failed_window.append(False)
                self._uiq_put(("log", f"{ip} - ping received ({rtt:.1f} ms)" if rtt is not None else f"{ip} - ping received", "green"))
            else:
                self.ping_failures += 1
                self.failed_window.append(True)
                self._uiq_put(("log", f"{ip} - ping failed", "red"))
                if self.var_require_ping.get():
                    self._auto_limit_evaluate()
                    if len(self.failed_window) >= self.auto_limit_window and sum(1 for x in self.failed_window[-self.auto_limit_window:] if x) / min(len(self.failed_window), self.auto_limit_window) >= self.auto_limit_threshold:
                        self._maybe_mullvad_reconnect()
                    return

            open_java, _ = check_port(ip, DEFAULT_PORT, dyn_timeout)
            ok_bedrock, info_b, rtt_b = bedrock_ping(ip, DEFAULT_BEDROCK_PORT, dyn_timeout)

            # category logging + analytics
            if open_java and ok_bedrock:
                self._uiq_put(("log", f"{ip} - both ports open", "blue"))
            elif open_java:
                self._uiq_put(("log", f"{ip} - port {DEFAULT_PORT} open", "green"))
            elif ok_bedrock:
                self._uiq_put(("log", f"{ip} - port {DEFAULT_BEDROCK_PORT} open", "green"))
            else:
                self._uiq_put(("log", f"{ip} - no ports open", "orange"))
                return

            # Java details
            if open_java:
                self.var_port.set(self.var_port.get() + 1)
                self.open_ports.add(ip)
                self._append_open_port_to_file(f"{ip}:{DEFAULT_PORT}")
                self._save_current_blob()
                ok2, info2, conf2 = self._extra_fallback_probe(ip, dyn_timeout, handshake_host=self._host_override_for_scan)
                if ok2:
                    addr = f"{ip}:{DEFAULT_PORT}"
                    if addr not in self.known_confirmed:
                        players = info2.get("players") if isinstance(info2, dict) else None
                        maxp = info2.get("max") if isinstance(info2, dict) else None
                        version = (info2.get("version") if isinstance(info2, dict) else "-") or "-"
                        motd = ((info2.get("motd") if isinstance(info2, dict) else "") or "").replace("\n"," ")[:120]
                        hint = info2.get("hint") if isinstance(info2, dict) else None
                        pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                        bars = ping_to_bars(rtt if ok_ping else None)
                        rec = {"address": addr, "version": version, "players": pstr, "motd": motd, "confidence": "dual" if conf2=="dual" else "single",
                               "found_at": datetime.now().isoformat(timespec='seconds'), "ping": rtt if ok_ping else None, "bars": bars, "hint": hint}
                        self.servers.append(rec); self.known_confirmed.add(addr)
                        self.var_mc.set(self.var_mc.get() + 1)
                        self._append_server_to_file(addr, version, pstr, rec["confidence"], motd)
                        self._save_current_blob()
                        self.refresh_table(incremental=rec)

            # Bedrock details
            if ok_bedrock:
                addr_b = f"{ip}:{DEFAULT_BEDROCK_PORT}"
                if addr_b not in self.known_confirmed:
                    players = info_b.get("players") if info_b else None
                    maxp = info_b.get("max") if info_b else None
                    version = info_b.get("version","-") if info_b else "-"
                    motd = (info_b.get("motd") or "-").replace("\n"," ")[:120] if info_b else "-"
                    pstr = f"{players}/{maxp}" if (players is not None and maxp is not None) else (str(players) if players is not None else "?")
                    bars = ping_to_bars(rtt_b)
                    rec = {"address": addr_b, "version": version, "players": pstr, "motd": motd, "confidence": "single",
                           "found_at": datetime.now().isoformat(timespec='seconds'), "ping": rtt_b, "bars": bars, "hint": "Bedrock"}
                    self.servers.append(rec); self.known_confirmed.add(addr_b)
                    self.var_mc.set(self.var_mc.get() + 1)
                    self._append_open_port_to_file(addr_b)
                    self._append_server_to_file(addr_b, version, pstr, "single", motd)
                    self._save_current_blob()
                    self.refresh_table(incremental=rec)

            self._auto_limit_evaluate()
            if len(self.failed_window) >= self.auto_limit_window and sum(1 for x in self.failed_window[-self.auto_limit_window:] if x) / min(len(self.failed_window), self.auto_limit_window) >= self.auto_limit_threshold:
                self._maybe_mullvad_reconnect()
        finally:
            self._uiq_put(("processed", 1))
# ============================== SECTION 7: AUTO LIMIT / MULLVAD / WORKER (END) ================================

# ============================== SECTION 8: GUI HELPERS — LIVE SETTINGS DISPLAY (START) ========================
    def _update_settings_display(self):
        """Refresh the live Current Settings panel once per second."""
        try:
            threads_limit = int(self.var_threads.get())
            current_threads = getattr(self, "current_concurrency", threads_limit)
            timeout_s   = float(self.var_timeout.get())
            retries     = int(self.var_retries.get())
            backoff_ms  = float(self.var_backoff_ms.get())
            cooldown_s  = float(self.var_cooldown.get())
            gbackoff_s  = float(self.var_gbackoff.get())
            jitter_ms   = float(self.var_jitter.get())
            require_ping = bool(self.var_require_ping.get())
            auto_limit   = bool(self.var_auto_limit.get())
            fail_thr_pct = float(self.var_failthr.get())
            tcp_fb       = bool(self.var_tcp_fallback.get())
            randomize    = bool(self.var_random.get())
            host_over    = self.var_host_override.get().strip() or "—"

            txt = (
                f"Threads (limit/current): {threads_limit}/{current_threads}\n"
                f"Timeout: {timeout_s:.2f}s | Retries: {retries} | Backoff base: {backoff_ms:.0f} ms\n"
                f"Per-IP cooldown: {cooldown_s:.1f}s | Global backoff: {gbackoff_s:.1f}s | Jitter: {jitter_ms:.0f} ms\n"
                f"Require ping: {require_ping} | Auto limit: {auto_limit} | Fail % thr: {fail_thr_pct:.0f}% | TCP fallback: {tcp_fb}\n"
                f"Randomize: {randomize} | Host override: {host_over}"
            )
            self.settings_text.config(text=txt)
        except Exception:
            pass
        self.root.after(1000, self._update_settings_display)

    # ----------------------------------------------------------------------

    def run_direct_test(self):
        """Triggered by the 'Run Test' button in the GUI."""
        target = self.var_test_host.get().strip()
        if not target:
            self._log_info("[WARN] No test host provided.")
            return

        self._log_info(f"[TEST] Running quick probe for {target} …")
        timeout = float(self.var_timeout.get())
        try:
            ok, rtt = ping_host(target, timeout)
            self._log_info(f"[TEST] Ping to {target} {'succeeded' if ok else 'failed'}"
                           + (f" ({rtt:.1f} ms)" if ok and rtt else ""))
            open_ok, rtt2 = check_port(target, 25565, timeout)
            if open_ok:
                self._log_info(f"[TEST] Port 25565 open ({rtt2:.1f} ms)")
                ok, info, _ = confirm_minecraft_by_protocol(target, 25565, timeout)
                if ok and info:
                    ver = info.get("version", "?")
                    motd = info.get("motd", "")
                    players = info.get("players", 0)
                    self._log_info(f"[TEST] Minecraft server → {ver} | {players} players | MOTD: {motd}")
                else:
                    self._log_info("[TEST] Port open but no valid MC protocol response.")
            else:
                self._log_info("[TEST] Port 25565 closed.")
        except Exception as e:
            self._log_info(f"[ERROR] Test failed: {e}")

    # ----------------------------------------------------------------------

    def _pump_ui(self):
        """Drain queued log messages and refresh live counters."""
        try:
            while not self._uiq.empty():
                msg, tag = self._uiq.get_nowait()
                self.log.configure(state="normal")
                self.log.insert("end", msg + "\n", tag)
                self.log.configure(state="disabled")
                self.log.see("end")
        except Exception:
            pass

        # Update failure %
        try:
            total = getattr(self, "processed", 0)
            self.var_total.set(total)
            fail_pct = (
                (self.ping_failures / self.ping_attempts) * 100.0
                if getattr(self, "ping_attempts", 0)
                else 0.0
            )
            self.var_failed_pct.set(f"{fail_pct:.2f}%")
        except Exception:
            pass

        self.root.after(200, self._pump_ui)

    # ----------------------------------------------------------------------

    def _start_refresh_loop(self):
        """Refresh GUI tables every 10 s."""
        try:
            if hasattr(self, "tree") and self.servers:
                for child in self.tree.get_children():
                    self.tree.item(child, tags=())
        except Exception:
            pass
        self.root.after(int(getattr(self, "_refresh_tick", 10.0) * 1000), self._start_refresh_loop)

    # ----------------------------------------------------------------------

    def _schedule_analytics(self):
        """Periodic analytics event emitter."""
        try:
            if hasattr(self, "_emit_analytics_point"):
                self._emit_analytics_point()
        except Exception:
            pass
        self.root.after(int(ANALYTICS_PUSH_EVERY * 1000), self._schedule_analytics)

    # ----------------------------------------------------------------------

    def _schedule_autotune(self):
        """Periodic autotune evaluator."""
        try:
            if hasattr(self, "_maybe_autotune"):
                self._maybe_autotune()
        except Exception:
            pass
        self.root.after(int(AUTOTUNE_EVERY * 1000), self._schedule_autotune)

    # ----------------------------------------------------------------------

    def _log_info(self, msg: str):
        """Safely log info text into GUI log (console fallback)."""
        try:
            self.log.configure(state="normal")
            self.log.insert("end", msg + "\n", "info")
            self.log.configure(state="disabled")
            self.log.see("end")
        except Exception:
            print(msg)
# ============================== SECTION 8: GUI HELPERS — LIVE SETTINGS DISPLAY (END) ==========================

# ============================== SECTION 9: UI HELPERS / LOGGING / TABLE REFRESH (START) =======================
    def _on_main_thread(self):
        return threading.current_thread() is threading.main_thread()

    def _uiq_put(self, item):
        try:
            self._uiq.put_nowait(item)
        except queue.Full:
            pass

    # --- color tags bootstrap (safe to call anytime) ---
    def _ensure_log_tags(self):
        if getattr(self, "_log_tags_ready", False):
            return
        try:
            self.log.tag_config("green", foreground="#00c853")
            self.log.tag_config("orange", foreground="#ff9800")
            self.log.tag_config("blue", foreground="#1e88e5")
            self.log.tag_config("red", foreground="#e53935")
            self.log.tag_config("info", foreground="#444444")
            self._log_tags_ready = True
        except Exception:
            self._log_tags_ready = False

    # --- main log with colored tags ---
    def _log(self, text, level="info"):
        tagmap = {
            "green": "green",
            "blue": "blue",
            "orange": "orange",
            "red": "red",
            "ok": "green",
            "found": "green",
            "port": "green",
            "warn": "orange",
            "info": "info",
            "no": "info",
        }
        tag = tagmap.get(level, "info")

        def _do():
            try:
                self._ensure_log_tags()
                self.log.config(state="normal")
                self.log.insert("end", text + "\n", (tag,))
                self.log.see("end")
            finally:
                self.log.config(state="disabled")

        if self._on_main_thread():
            _do()
        else:
            self.root.after(0, _do)

    # --- control log (plain) ---
    def _ctl(self, text):
        def _do():
            try:
                self.ctl.config(state="normal")
                self.ctl.insert("end", text + "\n")
                self.ctl.see("end")
            finally:
                self.ctl.config(state="disabled")
        if self._on_main_thread():
            _do()
        else:
            self.root.after(0, _do)

    # --- clear logs action for the toolbar button ---
    def clear_logs(self):
        def _do():
            try:
                self.log.config(state="normal")
                self.log.delete("1.0", "end")
                self.log.config(state="disabled")
            except Exception:
                pass
            try:
                self.ctl.config(state="normal")
                self.ctl.delete("1.0", "end")
                self.ctl.config(state="disabled")
            except Exception:
                pass
        if self._on_main_thread():
            _do()
        else:
            self.root.after(0, _do)
        self._uiq_put(("log", "Logs cleared", "info"))

    # --- list actions: delete from trees ---
    def delete_selected(self):
        sel_m = self.maybe_tree.selection()
        sel_c = self.tree.selection()
        changed = False
        if sel_m:
            for iid in sel_m:
                vals = self.maybe_tree.item(iid, "values")
                if vals:
                    addr = vals[0]
                    self.maybe_list = [m for m in self.maybe_list if m["address"] != addr]
                    self.known_maybe.discard(addr)
                    self._ctl(f"Delete Maybe: {addr}")
                    self._log(f"Maybe removed: {addr}", "info")
                    changed = True
        if sel_c:
            for iid in sel_c:
                vals = self.tree.item(iid, "values")
                if vals:
                    addr = vals[0]
                    self.servers = [r for r in self.servers if r["address"] != addr]
                    self.known_confirmed.discard(addr)
                    self._ctl(f"Delete Confirmed: {addr}")
                    self._log(f"Confirmed removed: {addr}", "info")
                    changed = True
        if changed:
            self.refresh_maybe()
            self.refresh_table()
            self._save_current_blob()

    def delete_all_maybe(self):
        cnt = len(self.maybe_list)
        self.maybe_list = []
        self.known_maybe = set()
        self.refresh_maybe()
        self._save_current_blob()
        self._ctl(f"Delete All Maybe: {cnt} entries")
        self._log(f"Cleared Maybe list ({cnt})", "info")

    # --- maybe/open-ports table rebuild ---
    def refresh_maybe(self):
        def _do():
            try:
                self.maybe_tree.delete(*self.maybe_tree.get_children(""))
                data = list(self.maybe_list) if isinstance(self.maybe_list, list) else []
                data.sort(key=lambda r: r.get("last_try",""), reverse=True)
                for rec in data:
                    self.maybe_tree.insert(
                        "",
                        "end",
                        values=(
                            rec.get("address",""),
                            rec.get("reason","open-port"),
                            rec.get("seen",""),
                            rec.get("last_try",""),
                        ),
                    )
            except Exception:
                pass
        if self._on_main_thread():
            _do()
        else:
            self.root.after(0, _do)

    # --- clipboard utility for open ports (if you expose a button) ---
    def show_open_ports(self):
        s = "\n".join(sorted(self.open_ports))
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(s)
            self._log("Open ports list copied to clipboard.", "info")
        except Exception:
            pass

    # --- stats helpers used by _tick ---
    def _format_hms(self, secs):
        secs = 0 if secs is None or secs < 0 else int(secs)
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
    
    # --- analytics event helper ---
    def _emit_analytics_point(self):
        """Collects analytics data and feeds it to the AnalyticsPanel (safe wrapper)."""
        try:
            ports_java = len([s for s in self.servers if "19132" not in s["address"]])
            ports_bedrock = len([s for s in self.servers if "19132" in s["address"]])
            ports_both = len([s for s in self.servers if s.get("both_ports", False)])
            if hasattr(self, "analytics"):
                self.analytics.log_stat(
                    responses=self.var_icmp.get(),
                    fails=self.ping_failures,
                    ports_java=ports_java,
                    ports_bedrock=ports_bedrock,
                    ports_both=ports_both,
                )
        except Exception:
            pass
    
        # --- automatic tuning helper ---
    def _maybe_autotune(self):
        """Runs the AutoTuner check every tick, adjusting retry/backoff settings dynamically."""
        try:
            if not hasattr(self, "autotuner"):
                # lazy init: create tuner on first call
                self.autotuner = AutoTuner(self)
            self.per_ip_cooldown, self.global_backoff_secs, self.var_timeout, self.retry_count = \
                self.autotuner.update(
                    responses=self.var_icmp.get(),
                    fails=self.ping_failures,
                    retries=self.retry_count,
                    cooldown=self.per_ip_cooldown,
                    gbackoff=self.global_backoff_secs,
                    timeout=self.var_timeout,
                )
        except Exception as e:
            # harmless if tuner not ready yet
            if "AutoTuner" not in str(e):
                self._ctl(f"[AutoTuner WARN] {e}")

    def _tick(self):
        now = time.time()
        elapsed = max(0.0, (now - self.start_time)) if self.start_time and (self.scanning or self._pause.is_set()) else 0.0
        self.s_elapsed.set(f"Elapsed: {self._format_hms(elapsed)}")

        ipsps = (self.var_total.get() / elapsed) if elapsed > 0 else 0.0
        rps = (self.var_icmp.get() / elapsed) if elapsed > 0 else 0.0
        fpm = (self.var_mc.get() / elapsed) * 60.0 if elapsed > 0 else 0.0
        self.s_ips.set(f"IPs/s: {ipsps:.2f}" if ipsps else "IPs/s: —")
        self.s_rps.set(f"Replies/s: {rps:.2f}" if rps else "Replies/s: —")
        self.s_fpm.set(f"Finds/min: {fpm:.2f}" if fpm else "Finds/min: —")

        if self._ping_count:
            self.s_avgping.set(f"Avg ping: {self._ping_sum / self._ping_count:.1f} ms")
        else:
            self.s_avgping.set("Avg ping: —")

        if self.var_total.get():
            self.s_hit.set(f"Hit rate: {(self.var_mc.get()/max(1,self.var_total.get()))*100.0:.2f}%")
            pct_fail = (self.ping_failures/max(1,self.ping_attempts))*100.0 if self.ping_attempts else 0.0
            self.var_failed_pct.set(f"{pct_fail:.2f}%")
        else:
            self.s_hit.set("Hit rate: —")
            self.var_failed_pct.set("0.00%")

        if self.scanning and self.total_ips and ipsps > 0:
            remain = max(0, self.total_ips - self.var_total.get())
            self.s_eta.set(f"ETA: {self._format_hms(int(remain / ipsps))}")
        elif self.scanning and self.total_ips and self.var_total.get() >= self.total_ips:
            self.s_eta.set("ETA: 00:00")
        else:
            self.s_eta.set("ETA: —")

        if psutil:
            try:
                self.s_cpu.set(f"CPU: {psutil.cpu_percent(interval=None):.0f}%")
                self.s_ram.set(f"RAM: {psutil.virtual_memory().percent:.0f}%")
            except Exception:
                self.s_cpu.set("CPU: —"); self.s_ram.set("RAM: —")
        else:
            self.s_cpu.set("CPU: —"); self.s_ram.set("RAM: —")

        with self._active_tasks_lock:
            self.var_active_threads.set(self._active_tasks)

        self.root.after(500, self._tick)

        def _update_settings_display(self):
            try:
                txt = (
                    f"Threads (limit/current): {int(self.var_threads.get())}/{int(self.current_concurrency)}\n"
                    f"Timeout: {float(self.var_timeout.get()):.2f}s | Retries: {int(self.var_retries.get())} | "
                    f"Backoff base: {float(self.var_backoff_ms.get()):.0f}ms\n"
                    f"Per-IP cooldown: {float(self.var_cooldown.get()):.1f}s | Global backoff: {float(self.var_gbackoff.get()):.1f}s | "
                    f"Jitter: {float(self.var_jitter.get()):.0f}ms\n"
                    f"Require ping: {bool(self.var_require_ping.get())} | Auto thread limit: {bool(self.var_auto_limit.get())} | "
                    f"Fail% threshold: {float(self.var_failthr.get()):.0f}% | TCP fallback: {bool(self.var_tcp_fallback.get())}\n"
                    f"Randomize: {bool(self.var_random.get())} | Host override: {self.var_host_override.get().strip() or '—'}"
                )
                self.settings_text.config(text=txt)
            except Exception:
                pass
            # refresh every second for real-time updates
            self.root.after(1000, self._update_settings_display)


    def _refresh_thread_suggestion(self):
        try:
            size = ip_range_size(self.var_start.get().strip(), self.var_end.get().strip())
        except Exception:
            size = None
        cores = os.cpu_count() or 4
        suggested = min(400, max(20, cores * 30))
        if size is not None and size < 256:
            suggested = max(20, min(suggested, 120))
        if psutil:
            try:
                freq = psutil.cpu_freq()
                ghz = f" @ {freq.current/1000:.2f}GHz" if freq else ""
            except Exception:
                ghz = ""
            self.lbl_suggest.set(f"Suggested threads: ~{suggested} (CPU cores: {cores})")
            self.lbl_sys.set(f"System OK{ghz} | svc: inline | nmap: {'on' if _nmap_available else 'off'}")
        else:
            self.lbl_suggest.set(f"Suggested threads: ~{suggested} (CPU cores: {cores})")
            self.lbl_sys.set(f"svc: inline | nmap: {'on' if _nmap_available else 'off'}")

    # --- confirmed table rebuild / incremental insert ---
    def _tree_find_row(self, tree, key_col, key_val):
        try:
            for iid in tree.get_children(""):
                vals = tree.item(iid, "values")
                if vals and len(vals) > key_col and vals[key_col] == key_val:
                    return iid
        except Exception:
            pass
        return None

    def _tree_upsert_confirmed(self, rec):
        addr = rec.get("address","")
        version = rec.get("version","-") or "-"
        players = rec.get("players","?") or "?"
        conf = rec.get("confidence","single")
        motd = (rec.get("motd") or "").replace("\n"," ")[:220]
        found = rec.get("found_at","")
        ping = ("%.1f ms" % rec["ping"]) if rec.get("ping") is not None else "—"
        bars = rec.get("bars", 0)
        hint = rec.get("hint") or "-"
        row = (addr, version, players, conf, motd, found, ping, bars, hint)

        iid = self._tree_find_row(self.tree, 0, addr)
        if iid:
            self.tree.item(iid, values=row)
        else:
            self.tree.insert("", "end", values=row)

    def refresh_table(self, incremental=None):
        mode = (self.var_sort.get() or "recent").lower() if hasattr(self, "var_sort") else "recent"

        if incremental is not None and isinstance(incremental, dict) and mode == "recent":
            # newest on top
            rec = incremental
            row = (
                rec.get("address",""),
                rec.get("version","-") or "-",
                rec.get("players","?") or "?",
                rec.get("confidence","single"),
                (rec.get("motd") or "").replace("\n"," ")[:220],
                rec.get("found_at",""),
                ("%.1f ms" % rec["ping"]) if rec.get("ping") is not None else "—",
                rec.get("bars", 0),
                rec.get("hint") or "-",
            )
            self.tree.insert("", 0, values=row)
            return

        # full rebuild
        try:
            self.tree.delete(*self.tree.get_children(""))
        except Exception:
            pass

        data = list(self.servers) if isinstance(self.servers, list) else []
        if mode == "version":
            data.sort(key=lambda r: (str(r.get("version","-")), r.get("found_at","")), reverse=False)
        else:
            data.sort(key=lambda r: r.get("found_at",""), reverse=True)

        for rec in data:
            self._tree_upsert_confirmed(rec)
# ============================== SECTION 9: UI HELPERS / LOGGING / TABLE REFRESH (END) =========================

# ============================== SECTION 10: AUTO-TUNER CLASS ==============================
class AutoTuner:
    def __init__(self, gui):
        self.gui = gui
        self.history = []
        self.best = {}
        self.last_update = time.time()
        self.interval = 30.0  # seconds between adjustments

    def update(self, responses, fails, retries, cooldown, gbackoff, timeout):
        now = time.time()
        if now - self.last_update < self.interval:
            return cooldown, gbackoff, timeout, retries

        total = responses + fails
        if total == 0:
            return cooldown, gbackoff, timeout, retries
        rate = responses / total
        self.history.append(rate)
        self.history = self.history[-20:]  # keep 20 points

        avg = sum(self.history) / len(self.history)
        delta = rate - avg
        tuned = False

        # adjust based on trends
        if delta < -0.05:
            retries = min(retries + 1, 5)
            cooldown = min(cooldown + 1, 30)
            gbackoff = min(gbackoff + 2, 60)
            timeout = min(timeout + 0.5, 8)
            tuned = True
        elif delta > 0.05:
            retries = max(1, retries - 1)
            cooldown = max(2, cooldown - 1)
            gbackoff = max(2, gbackoff - 1)
            timeout = max(2.5, timeout - 0.5)
            tuned = True

        self.last_update = now
        if tuned:
            self.gui._ctl(f"[AutoTuner] Adjusted — Retries={retries}, Cooldown={cooldown}s, GBackoff={gbackoff}s, Timeout={timeout}s")
        return cooldown, gbackoff, timeout, retries
# ============================== END SECTION 10: AUTO-TUNER CLASS ==========================

# ============================== SECTION 11 (MAIN ENTRYPOINT + CONSOLE SCANNER FALLBACK) ==============================
# --- fallback console scanner stub ---
class ConsoleScanner:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
    def run(self):
        print("[ConsoleScanner] Stub running (GUI mode available).")

def main():
    global run_console
    run_console = False
    try:
        if not _gui_available:
            raise RuntimeError("Tkinter GUI not available")
        import tkinter as tk
        root = tk.Tk()
        app = ScannerAppGUI(root)
        run_console = False
        root.mainloop()
    except Exception as e:
        print(f"[INFO] Tkinter GUI not available. Running in console mode.\n[DETAIL] {e}")
        run_console = True

    if run_console:
        out_path = os.path.join(os.getcwd(), OUTPUT_FILENAME)
        print(f"[INFO] Results will be saved to: {out_path}")
        start_ip = DEFAULT_START_IP
        end_ip = DEFAULT_END_IP
        total = int(IPv4Address(end_ip)) - int(IPv4Address(start_ip)) + 1
        print(f"[INFO] Scanning {start_ip}..{end_ip} ({total} IPs), threads={DEFAULT_WORKERS} timeout={DEFAULT_TIMEOUT}s, svc=inline | nmap={'on' if _nmap_available else 'off'}")

        app = ConsoleScanner(
            start_ip=start_ip,
            end_ip=end_ip,
            threads=DEFAULT_WORKERS,
            timeout=DEFAULT_TIMEOUT,
            retries=DEFAULT_RETRIES,
            backoff=RETRY_BACKOFF_BASE,
            require_ping=True,
            auto_limit=True,
            auto_limit_threshold=0.95,
            randomize=True,
            global_backoff_secs=GLOBAL_BACKOFF_SECS,
        )
        app.run()
        print("[INFO] Scan complete.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user, exiting.")
    except Exception as e:
        print(f"[CRITICAL] Unhandled exception in main: {e}")
# ============================== END SECTION 11 (MAIN ENTRYPOINT) ==========================