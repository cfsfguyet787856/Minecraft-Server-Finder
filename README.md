<div align="center">
  <h1>🧭 Minecraft Server Finder</h1>
  <p>Discover publicly reachable Minecraft servers across IPv4. Multi-threaded, protocol-aware, proxy-friendly. Launch the polished Tkinter GUI or run fully headless.</p>
  <p>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg"></a>
    <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
    <img alt="OS" src="https://img.shields.io/badge/OS-Windows%20%7C%20macOS%20%7C%20Linux-2ea44f">
    <img alt="GUI" src="https://img.shields.io/badge/GUI-Tkinter-ff69b4">
    <img alt="Packaging" src="https://img.shields.io/badge/Packaging-PyInstaller-00ADD8">
    <img alt="Proxies" src="https://img.shields.io/badge/Proxies-SOCKS5-black">
    <a href=".github/workflows/python-app.yml"><img alt="CI" src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?logo=githubactions&logoColor=white"></a>
    <a href=".github/workflows/build-windows-release.yml"><img alt="Windows Release" src="https://img.shields.io/badge/Build-Windows%20Release-00A4EF?logo=windows&logoColor=white"></a>
    <a href="#quick-start"><img alt="Get Started" src="https://img.shields.io/badge/%F0%9F%9A%80-Quick%20Start-orange"></a>
  </p>
</div>

> [!WARNING]
> Only scan IP ranges that you own or have explicit permission to test. Unauthorised scanning may violate local laws, ISP terms of service or the acceptable‑use policies of hosting providers. By using this tool you accept full responsibility for complying with all applicable rules.

<details>
<summary><b>Table of contents</b></summary>

- [Highlights](#highlights)
- [Screenshot](#screenshot)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Running](#running)
  - [GUI Mode](#gui-mode)
  - [Console / Headless Mode](#console--headless-mode)
  - [CLI Flags](#cli-flags)
- [Proxy-Assisted Scanning](#proxy-assisted-scanning)
- [Windows Executable Builds](#windows-executable-builds)
- [Configuration](#configuration)
- [Output Files](#output-files)
- [Troubleshooting](#troubleshooting)
- [Repository Layout](#repository-layout)
- [FAQ](#faq)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Legal & Ethics](#legal--ethics)

</details>

## Highlights

- **High-throughput scanner** – Leverages `ThreadPoolExecutor`, bounded queues and adaptive worker limits to sweep massive IPv4 ranges without saturating your network links.
- **Protocol-aware verification** – Performs full Java status handshakes (with `mcstatus` support when installed) to surface version hints, MOTDs, player counts and latency measurements.
- **Deterministic IP randomisation** – The Feistel-based `permuted_index_generator` lets you reshuffle scan order while guaranteeing that every host is visited exactly once.
- **Battle-tested proxy rotation** – `ProxyPool` tracks SOCKS5 endpoint health, enforces exponential cooldowns and exposes live metrics so long-running sweeps stay reliable.
- **Mullvad automation ready** – `MullvadManager` integrates with the Mullvad CLI/SDK to rotate exit IPs and keep your proxy fleet fresh during multi-hour scans.
- **Persistent, shareable storage** – `StorageManager` writes confirmed hits, open-port leads and saved GUI state to text/JSON artefacts you can sync or process elsewhere.
- **Modular architecture** – All engine components live in the `mcsmartscan` package, making it easy to embed scanning, proxy or storage helpers in your own tooling.

## Screenshot

<div align="center">
  <img width="1919" height="980" alt="{825637BC-D15E-4AE2-A577-6E80CFBF947B}" src="https://github.com/user-attachments/assets/fbe25b54-8964-409f-be0d-681034763295" />

</div>

## Quick Start

1. Clone the repo and enter the project directory.
   ```bash
   git clone https://github.com/braydos-h/Minecraft-Server-Finder.git
   cd Minecraft-Server-Finder
   ```
2. Create and activate a virtual environment (recommended).
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   ```
3. Install dependencies and optional helpers.
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Run the GUI.
   ```bash
   python app.py
   ```

> [!TIP]
> Prefer clickable helpers? Use `install_system.bat` to install tooling system-wide on Windows, or run `pyinstaller.ps1` for a ready-to-ship executable without manually invoking PyInstaller.

## Installation

### Requirements
- Python 3.10 or newer
- Tkinter (bundled with most Python installs; optional if you only need headless mode)
- Optional integrations for richer telemetry:
  - [`mcstatus`](https://pypi.org/project/mcstatus/) – enhanced Java status queries
  - [`python-nmap`](https://pypi.org/project/python-nmap/) – cross-check suspicious ports
  - [`psutil`](https://pypi.org/project/psutil/) – UI system metrics
  - [`mullvad-api`](https://pypi.org/project/mullvad-api/) / [`mullvad-python`](https://pypi.org/project/mullvad-python/) – advanced VPN automation

### Setup Checklist
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

The scanner gracefully degrades when optional packages are missing—install only what you need.

## Running

### GUI Mode

- Launch with `python app.py`.
- Configure IP ranges, port lists, worker counts, proxy settings and Mullvad cycling directly in the UI.
- Real-time logs stream alongside the results table, which surfaces latency bars, MOTDs, protocol hints and timestamps.
- Results persist automatically to your Desktop (or a directory you choose).

### Console / Headless Mode

```bash
python app.py --nogui
```

- Ideal for servers, containers or remote automation where Tkinter is unavailable.
- Reuses the same scanning engine; you can plug in custom orchestration hooks defined in `app.py`.

### CLI Flags

| Flag | Description |
| ---- | ----------- |
| `--nogui` | Force console mode even if Tkinter is present. |
| `-h`, `--help` | Display the current list of supported switches. |

## Proxy-Assisted Scanning

- Maintain your SOCKS5 pool in `mcsmartscan/mullvadproxyips.txt` (`host` or `host:port`, one per line, comments allowed).
- The GUI’s **Proxy Pool** panel visualises healthy endpoints, latency, lease counts, failure streaks and cooldown timers.
- `ProxyPool` backs off misbehaving proxies, quarantines them after repeated failures and exposes event callbacks for custom dashboards.
- Pair with the Mullvad desktop app/CLI (or your own provider) to ensure endpoints are reachable before launching a scan.
- Remove or empty the proxy list to fall back to direct TCP connections.

## Windows Executable Builds

### Manual Build Steps

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --clean --noconfirm minecraft_server_finder.spec
```

The resulting `MinecraftServerFinder.exe` (in `dist/`) bundles the Mullvad proxy list plus all engine modules. Use `pyinstaller.ps1` for a scripted local build.

### Automated Releases

- Tag the repo with `v*` (e.g. `v1.2.0`) or trigger the **Build Windows Release** workflow from the Actions tab.
- GitHub Actions builds on `windows-latest`, uploads an artefact and publishes a GitHub release with the packaged executable attached.

## Configuration

| Setting | Default | Where to change | Notes |
| --- | --- | --- | --- |
| Start/End IP | `40.0.0.0` / `255.255.255.255` | GUI, CLI, or direct API usage | Accepts CIDR blocks and explicit start/end pairs. |
| Port list | `25565` | GUI or CLI | Add additional ports to probe Bedrock or modded servers. |
| Worker threads | `150` | GUI slider / CLI | Balance throughput against bandwidth and upstream rate limits. |
| Timeout | `4.0s` | GUI / CLI | Applies to TCP handshakes and proxy acquisition. |
| Proxy pool file | `mcsmartscan/mullvadproxyips.txt` | Filesystem | Whitespace/comments ignored; empty file disables proxying. |
| Output path | Desktop auto-detected | GUI settings / `StorageManager` | Point at shared folders to collaborate with teammates. |
| VPN cycling | Disabled | GUI toggle / `MullvadManager` | Rotate exit IPs on a schedule for long scans. |

## Output Files

Defaults live on the user’s Desktop (auto-detected per platform):

- `Minecraft_Servers.txt` – Confirmed servers with timestamps, version hints, player counts and MOTDs.
- `Open_Ports.txt` – IP:port pairs that responded but failed Minecraft-specific validation.
- `saved_servers.json` – Structured state used to repopulate the GUI tables on restart.

Override the destination path through the GUI or by instantiating `StorageManager` with a custom root inside your own integrations.

## Troubleshooting

- **Tkinter missing on Linux** – Install `python3-tk` (Debian/Ubuntu) or `tk` (Arch/Fedora) matching your Python version.
- **Proxy pool never becomes healthy** – Ensure the SOCKS endpoints are reachable and that your VPN is connected to a SOCKS-enabled location.
- **Permission denied while writing output** – Select a writable destination or run the process under an account with access to that folder.
- **False positives / empty MOTDs** – Add `mcstatus` for richer handshake parsing and `python-nmap` to corroborate suspicious open ports.

## Repository Layout

```text
Minecraft-Server-Finder/
├── app.py                       # GUI + console launcher and orchestration
├── mcsmartscan/                 # Reusable scanning engine modules
│   ├── constants.py             # Defaults, protocol tables, signal helpers
│   ├── proxy.py                 # SOCKS5 pool, cooldown/backoff logic
│   ├── storage.py               # Desktop-aware persistence helpers
│   ├── utils.py                 # IP generators and misc utilities
│   └── vpn.py                   # Mullvad integration layer
├── minecraft_server_finder.spec # PyInstaller recipe
├── tests/                       # pytest suites for storage and utilities
├── install_system.bat           # Windows helper for system installs
└── pyinstaller.ps1              # PowerShell helper for local packaging
```

## FAQ

- **Does the scanner support Bedrock servers?**  
  The default port list targets Java (`25565`), but you can add Bedrock ports (e.g. `19132`) to the GUI or CLI configuration. Bedrock-specific UDP validation is limited—use results as leads for further confirmation.

- **Can I pause and resume scans?**  
  The GUI supports stopping and restarting scans; results persist to disk via `StorageManager`, so you can resume later without losing confirmed servers.

- **Is there rate limiting?**  
  Worker counts, timeouts and proxy pool sizes provide coarse-grained control. Combine them with smaller IP ranges or custom orchestration for tighter rate limiting.

## Development

- Run the local test suite:
  ```bash
  pytest
  ```
- Keep the codebase lint-clean:
  ```bash
  flake8 .
  ```
- Adopt optional tooling (`black`, `ruff`, `mypy`) if you prefer stricter local enforcement—nothing in the repo prevents their use.
- Continuous Integration mirrors this workflow using the **Python application** action (`.github/workflows/python-app.yml`).

## Contributing

- Fork the repo, create a feature branch and keep optional dependencies gated so the lightweight core remains intact.
- Test both GUI and headless flows where your changes apply.
- Update documentation (including this README) when behaviour changes.
- Bug reports are hugely valuable—share reproduction steps, logs and platform details so the community can help quickly.

## License

Minecraft Server Finder is distributed under the terms of the [MIT License](LICENSE).

## Legal & Ethics

- Use responsibly: unauthorised scanning can breach laws, ISP contracts or hosting provider policies.
- Respect rate limits and terms of service for VPN or proxy providers.
- Share findings ethically—avoid disclosing sensitive information without consent.
- The maintainers accept no liability for misuse. By running the scanner you acknowledge that you alone are accountable for legal compliance.

