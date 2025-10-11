# install_system.ps1
# Installs all required Python packages system-wide

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Checking Python installation..."
python --version || (Write-Error "Python not found. Please install Python and ensure it's in PATH." ; exit 1)

Write-Host "Upgrading pip, setuptools, and wheel..."
python -m pip install --upgrade pip setuptools wheel

Write-Host "Installing packages system-wide..."
python -m pip install --upgrade `
    "mcstatus>=12.0.5" `
    "python-nmap>=0.7.1" `
    "psutil>=5.9.0" `
    "mullvad-api>=1.0.0" `
    "mullvad-python>=0.3.1"

Write-Host "`n✅ Installation complete. Packages installed system-wide."
