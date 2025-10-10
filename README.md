# Minecraft Server Finder

Minecraft Server Finder is a Python application for discovering publicly reachable
Minecraft servers. It can sweep through large IPv4 ranges, record open ports and
validate Minecraft-specific protocols so that you end up with a curated list of
servers to explore. The project includes both a Tkinter GUI and a console-first
scanning engine so you can run it interactively or unattended on a headless
machine.

## Highlights

- **Multi-threaded scanning engine** – efficiently probes thousands of hosts
  concurrently with configurable worker counts, timeouts and IP ranges.
- **Protocol aware detection** – performs full Minecraft status handshakes for
  modern and legacy protocol versions to confirm that an open port is really a
  Minecraft server.
- **Optional helper tools** – integrates with `mcstatus` for richer status
  queries, `python-nmap` for port verification, `psutil` for system monitoring,
  and Mullvad's CLI/SDKs for VPN cycling when scanning.
- **Persistent results** – writes confirmed servers, potential candidates and
  open-port findings to easily shareable text and JSON files, defaulting to the
  user's desktop for convenience.
- **Extensible design** – the `mcsmartscan` package breaks the monolithic
  scanner into focused modules (`constants`, `storage`, `utils`, `vpn`) to make
  maintenance and customisation easier.

## Repository Layout

```
.
├── app.py              # Main entry point with GUI + console launcher
├── mcsmartscan/        # Reusable package for the scanning engine
│   ├── __init__.py
│   ├── constants.py    # Defaults, protocol tables and helper enums
│   ├── storage.py      # Persistence helpers for scan results
│   ├── utils.py        # IP range iterators and misc helpers
│   └── vpn.py          # Mullvad VPN integration layer
├── MCSmartScan.py      # Original single-file script kept for reference
├── LICENSE
└── README.md
```

The `app.py` script is the recommended way to run the scanner. The legacy
`MCSmartScan.py` script mirrors much of the behaviour but is retained for
historical context and quick one-off modifications.

## Requirements

- Python 3.10 or later (earlier versions may work but are untested).
- Tkinter (bundled with most Python distributions) for the GUI mode.
- Optional libraries that unlock extra functionality:
  - [`mcstatus`](https://pypi.org/project/mcstatus/) – richer Java status
    queries.
  - [`python-nmap`](https://pypi.org/project/python-nmap/) – additional port
    probing via Nmap.
  - [`psutil`](https://pypi.org/project/psutil/) – display system resource
    usage in the UI.
  - [`mullvad-api`](https://pypi.org/project/mullvad-api/) and
    [`mullvad-python`](https://pypi.org/project/mullvad-python/) – enhance VPN
    state tracking for Mullvad users.

Install the core and optional dependencies with `pip`:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install --upgrade pip
pip install mcstatus python-nmap psutil mullvad-api mullvad-python
```

> The scanner gracefully degrades when optional packages are unavailable, so you
> can install only the libraries you need.

## Running the Scanner

### GUI mode (default)

```
python app.py
```

If Tkinter is available, the application launches a GUI where you can configure
IP ranges, concurrency, ping/handshake requirements, VPN cycling and review the
live logs. Results are written to `Minecraft_Servers.txt`, `Open_Ports.txt` and
`saved_servers.json` under the storage directory (Desktop by default).

### Console mode / headless use

```
python app.py --nogui
```

Passing `--nogui` forces console mode, which is also selected automatically when
Tkinter is missing. The console shim expects a custom scan loop function (see
`app.py` for entrypoint names) and keeps the process alive so you can integrate
it with your own orchestration scripts.

### Legacy script

```
python MCSmartScan.py
```

The legacy script mirrors the core features of the modern scanner but stays in a
single file for users who prefer the original layout.

## Output Files

By default the scanner stores artefacts in the user's desktop directory:

- `Minecraft_Servers.txt` – timestamped list of confirmed servers with version,
  player counts and MOTD.
- `Open_Ports.txt` – record of IP/port pairs that responded but could not be
  confirmed as full Minecraft servers yet.
- `saved_servers.json` – structured state used to repopulate the GUI tables on
  restart.

The destination directory can be overridden through the settings UI or by using
`StorageManager` directly in custom integrations.

## Development Tips

- The repository is pure Python, so standard tools such as `black`, `ruff` or
  `mypy` can be adopted easily.
- The modular `mcsmartscan` package can be imported into your own projects if
  you want to reuse the IP generators, storage layer or Mullvad integration.
- Contributions are welcome! Please open an issue or pull request describing the
  enhancement or bug fix you have in mind.

## License

Minecraft Server Finder is distributed under the terms of the MIT License. See
[`LICENSE`](./LICENSE) for details.
