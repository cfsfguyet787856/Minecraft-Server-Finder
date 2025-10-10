"""Project-wide constants and lightweight helpers."""

from __future__ import annotations

import platform
from typing import Iterable, Tuple

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
OPEN_PORTS_FILENAME = "Open_Ports.txt"

PROTOCOL_CANDIDATES = [
    768, 767, 766, 765, 764, 763, 760, 759, 758, 757, 756, 755, 754,
    498, 340, 316, 210, 110, 47,
]

PROTOCOL_TO_VERSION_HINT = {
    768: "1.21.x",
    767: "1.21.x",
    766: "1.21.x",
    765: "1.21.x",
    764: "1.20.6-1.21",
    763: "1.20.5",
    760: "1.20.2-1.20.4",
    759: "1.20.1",
    758: "1.20",
    757: "1.19.4",
    756: "1.19.3",
    755: "1.19-1.19.2",
    754: "1.16.5-1.17.1",
    498: "1.14.4",
    340: "1.12.2",
    316: "1.11.2",
    210: "1.10.2",
    110: "1.9.4",
    47: "1.8.x",
}

PING_SIGNAL_BARS: Iterable[Tuple[int, int]] = (
    (60, 5),
    (100, 4),
    (150, 3),
    (250, 2),
    (999_999, 1),
)


def ping_to_bars(ms: float | None) -> int:
    """Translate a ping measurement into UI signal bars."""
    if ms is None:
        return 0
    for cutoff, bars in PING_SIGNAL_BARS:
        if ms < cutoff:
            return bars
    return 0


# Note: Removed autotune constants, retries/backoff/cooldown/jitter/TCP fallback/global backoff.
BEDROCK_MAGIC = b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"  # RakNet magic

