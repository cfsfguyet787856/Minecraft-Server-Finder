# Minecraft Server Finder

Minecraft Server Finder is a Python application for discovering publicly reachable
Minecraft servers. It can sweep through large IPv4 ranges, record open ports and
validate Minecraft-specific protocols so that you end up with a curated list of
servers to explore. The project includes both a Tkinter GUI and a console-first
scanning engine so you can run it interactively or unattended on a headless
machine.

> ⚠️ **Important:** Only scan IP ranges that you own or have explicit permission to
> test. Unauthorised scanning may violate local laws, ISP terms of service or the
> acceptable use policies of hosting providers. The maintainers and contributors
> of this project accept no responsibility for misuse or for any legal or
> contractual issues that arise from how you choose to deploy the scanner. By
> using the tool you agree that you are solely accountable for complying with all
> applicable laws and agreements.

<img width="2880" height="1799" alt="image" src="https://github.com/user-attachments/assets/d2ebae98-4f35-42bd-a270-8e9bba4d09c1" />

## Highlights

- **Multi-threaded scanning engine** – efficiently probes thousands of hosts
  concurrently with configurable worker counts, timeouts and IP ranges.
- **Protocol aware detection** – performs full Minecraft status handshakes for
  modern and legacy protocol versions to confirm that an open port is really a
  Minecraft server.
- **SOCKS5 proxy rotation** – optionally routes probes through a managed pool
  of Mullvad (or custom) SOCKS endpoints with automatic health tracking and
  cooldowns to spread load across exit IPs.
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
├── .github/workflows/  # CI configuration
├── app.py              # Main entry point with GUI + console launcher
├── mcsmartscan/        # Reusable package for the scanning engine
│   ├── __init__.py
│   ├── constants.py    # Defaults, protocol tables and helper enums
│   ├── mullvadproxyips.txt  # Default SOCKS5 pool (host[:port] per line)
│   ├── proxy.py        # SOCKS5 proxy rotation + health tracking
│   ├── storage.py      # Persistence helpers for scan results
│   ├── utils.py        # IP range iterators and misc helpers
│   └── vpn.py          # Mullvad VPN integration layer
├── LICENSE
├── README.md
└── requirements.txt
```

The `app.py` script is the recommended way to run the scanner. The
`mcsmartscan` package exposes the reusable building blocks—storage, proxy
management, VPN helpers and utility functions—if you want to embed the engine
in your own tooling.

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

Install the recommended dependencies with the bundled `requirements.txt` file:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

> The scanner gracefully degrades when optional packages are unavailable, so you
> can install only the libraries you need. Feel free to edit
> `requirements.txt` to match the features you plan to use.

### Manual installation

If you prefer to install packages selectively, the key optional helpers are:

- [`mcstatus`](https://pypi.org/project/mcstatus/) – richer Java status
  queries.
- [`python-nmap`](https://pypi.org/project/python-nmap/) – additional port
  probing via Nmap.
- [`psutil`](https://pypi.org/project/psutil/) – display system resource
  usage in the UI.
- [`mullvad-api`](https://pypi.org/project/mullvad-api/) and
  [`mullvad-python`](https://pypi.org/project/mullvad-python/) – enhance VPN
  state tracking for Mullvad users.

## Running the Scanner

### GUI mode (default)

```
python app.py
```

If Tkinter is available, the application launches a GUI where you can configure
IP ranges, concurrency, ping/handshake requirements, VPN cycling and review the
live logs. Results are written to `Minecraft_Servers.txt`, `Open_Ports.txt` and
`saved_servers.json` under the storage directory (Desktop by default).

### Proxy-assisted scanning (optional)

When a SOCKS5 list is available, the GUI automatically enables a proxy pool so
that every outbound probe is tunnelled through an exit server:

1. Keep the bundled `mcsmartscan/mullvadproxyips.txt` file up to date with the
   Mullvad SOCKS IPs you want to use. Each line accepts `host` or `host:port`
   (defaults to `1080`) and ignores blank lines or those starting with `#`.
2. Connect the Mullvad app/CLI to a SOCKS-enabled location before starting a
   scan so that the endpoints are reachable.
3. Start a scan as usual. The **Proxy Pool** panel shows live health metrics,
   latency measurements, cooldowns and a rolling log of proxy failures.

The pool limits worker concurrency to the number of healthy proxies, retries
failed endpoints with exponential cooldowns and exposes the same connectors to
the **Run Test** tool. To disable proxying entirely, remove or empty the text
file (the scanner falls back to direct connections) or replace it with your own
SOCKS5 list for other providers.

### Quick-start workflow

1. Clone the repository and install the recommended dependencies.
2. Launch the GUI as shown above and enter the IPv4 ranges you want to inspect
   (e.g. `192.168.0.0/24`).
3. Adjust the worker/thread count to suit the bandwidth available on your
   network connection.
4. Click **Start Scan** to begin probing. Servers that respond successfully will
   appear in the results table in real time.
5. Export the findings directly from the GUI or open the generated files in your
   storage directory for use in other tooling.

### Console mode / headless use

```
python app.py --nogui
```

Passing `--nogui` forces console mode, which is also selected automatically when
Tkinter is missing. The console shim expects a custom scan loop function (see
`app.py` for entrypoint names) and keeps the process alive so you can integrate
it with your own orchestration scripts.

### Command-line arguments

The launcher currently accepts a small set of switches. Run `python app.py -h`
to see the full list or refer to the quick reference below:

| Flag | Description |
| ---- | ----------- |
| `--nogui` | Forces console mode even when Tkinter is available. Useful for running inside containers or servers without a display. |

Future releases will expand this list as additional automation hooks are
promoted from the GUI, so check back if you need more granular control over the
headless workflow.

## Troubleshooting

- **Tkinter errors on Linux** – Install the `python3-tk` (Debian/Ubuntu) or
  `tk` (Arch/Fedora) package that matches the Python version you are using.
- **Proxy pool never initialises** – Ensure the SOCKS5 endpoints listed in
  `mcsmartscan/mullvadproxyips.txt` are reachable and that your Mullvad client
  is connected to a SOCKS-enabled location before launching the scanner.
- **Permission denied writing results** – The storage folder defaults to the
  desktop of the user account running the scanner. Override the output path in
  the GUI, or run the program from an account with write access to that
  location.

## Contributing

Contributions are welcome! If you plan to submit a pull request:

1. Fork the repository and create a feature branch.
2. Ensure code adheres to the existing style and keep optional dependencies
   guarded so the core scanner remains lightweight.
3. Test both GUI and console flows where applicable.
4. Update the documentation (including this README) when behaviour changes.

Bug reports are just as valuable as code—if you hit an issue please open a
GitHub issue with reproduction steps, relevant logs and platform details so the
community can investigate.

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

## Configuration reference

Most of the options exposed in the GUI can also be supplied when using
`app.py --nogui` or by importing the underlying `mcsmartscan` components. The
most commonly tweaked parameters include:

- **IP ranges** – accept both CIDR blocks (e.g. `203.0.113.0/28`) and explicit
  start/end pairs. Multiple ranges can be supplied at once.
- **Port list** – defaults to the standard Java edition port `25565`, but any
  comma-separated list is accepted.
- **Worker threads** – increase this value to speed up scans on fast networks,
  or lower it to reduce bandwidth consumption and avoid overwhelming remote
  hosts.
- **Timeouts and retry counts** – tune how long the scanner waits before
  marking a host as unreachable and how often to reattempt connections.
- **VPN cycling** – enable Mullvad integration to rotate exit IPs on a schedule
  when running long scans.
- **Proxy pool** – edit `mcsmartscan/mullvadproxyips.txt` to point at the SOCKS5
  hosts you want to rotate through; the GUI automatically scales concurrency to
  the number of healthy proxies and exposes live health telemetry.

## Development Tips

- The repository is pure Python, so standard tools such as `black`, `ruff` or
  `mypy` can be adopted easily.
- The modular `mcsmartscan` package can be imported into your own projects if
  you want to reuse the IP generators, storage layer, SOCKS proxy pool or
  Mullvad integration.
- Contributions are welcome! Please open an issue or pull request describing the
  enhancement or bug fix you have in mind.

## License

Minecraft Server Finder is distributed under the terms of the MIT License. See
[`LICENSE`](./LICENSE) for details.
