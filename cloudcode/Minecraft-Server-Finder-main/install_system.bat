@echo off
REM install_system.bat - system-wide installation

echo Checking Python installation...
python --version || (
    echo Python not found. Please install Python and ensure it's in PATH.
    pause
    exit /b 1
)

echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

echo Installing packages system-wide...
python -m pip install --upgrade ^
    "mcstatus>=12.0.5" ^
    "python-nmap>=0.7.1" ^
    "psutil>=5.9.0" ^
    "mullvad-api>=1.0.0" ^
    "mullvad-python>=0.3.1"

echo.
echo ✅ Installation complete. Packages installed system-wide.
pause
