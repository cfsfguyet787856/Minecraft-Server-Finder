"""Generic utilities shared by the GUI and back-end scanners."""

from __future__ import annotations

import hashlib
import math
import os
import platform
import time
from ipaddress import IPv4Address
from typing import Generator, Iterable, Optional


def get_desktop_path() -> str:
    """Best-effort resolution of the user's Desktop directory."""
    home = os.path.expanduser("~")
    system = platform.system().lower()
    candidates = [os.path.join(home, "Desktop")]
    if "windows" in system:
        candidates += [os.path.join(home, "OneDrive", "Desktop")]
    if "darwin" in system or "mac" in system:
        candidates += [
            os.path.join(
                home,
                "Library",
                "Mobile Documents",
                "com~apple~CloudDocs",
                "Desktop",
            )
        ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    try:
        fallback = os.path.join(home, "Desktop")
        os.makedirs(fallback, exist_ok=True)
        return fallback
    except Exception:
        return home


def ip_range_size(start_ip: str, end_ip: str) -> int:
    """Return the number of IPv4 addresses between the start and end (inclusive)."""
    start = int(IPv4Address(start_ip))
    end = int(IPv4Address(end_ip))
    if end < start:
        start, end = end, start
    return (end - start) + 1


def ip_range_generator(start_ip: str, end_ip: str) -> Generator[str, None, None]:
    """Yield each IP in a range sequentially."""
    start = int(IPv4Address(start_ip))
    end = int(IPv4Address(end_ip))
    if end < start:
        start, end = end, start
    for value in range(start, end + 1):
        yield str(IPv4Address(value))


def permuted_index_generator(
    start_ip: str,
    end_ip: str,
    seed: Optional[bytes] = None,
    rounds: int = 4,
) -> Generator[str, None, None]:
    """Yield IPs in pseudorandom order using a Feistel permutation."""
    start = int(IPv4Address(start_ip))
    end = int(IPv4Address(end_ip))
    if end < start:
        start, end = end, start
    total = (end - start) + 1
    if total <= 0:
        return

    if seed is None:
        seed = hashlib.sha256(str(time.time()).encode("utf-8")).digest()

    bits = max(1, math.ceil(math.log2(total)))
    domain = 1 << bits
    left_bits = bits // 2
    right_bits = bits - left_bits
    left_mask = (1 << left_bits) - 1
    right_mask = (1 << right_bits) - 1

    def feistel(x: int) -> int:
        left = (x >> right_bits) & left_mask
        right = x & right_mask
        for round_index in range(rounds):
            h = hashlib.sha256()
            h.update(seed)
            h.update(bytes([round_index & 0xFF]))
            h.update(right.to_bytes((right_bits + 7) // 8 or 1, "big"))
            f = int.from_bytes(h.digest(), "big") & left_mask
            left, right = right, (left ^ f) & left_mask
        return ((left << right_bits) | right) & (domain - 1)

    for candidate in range(domain):
        permuted = feistel(candidate)
        if permuted < total:
            yield str(IPv4Address(start + permuted))


def ensure_directory(path: str) -> None:
    """Create a directory if it does not already exist."""
    os.makedirs(path, exist_ok=True)

