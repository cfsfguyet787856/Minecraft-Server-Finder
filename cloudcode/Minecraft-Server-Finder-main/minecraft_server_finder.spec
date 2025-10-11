# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


def _resolve_project_root() -> Path:
    """Return the directory containing this spec file."""

    # When PyInstaller executes the spec file, the ``__file__`` global is not
    # guaranteed to be populated (for example when run via ``pyinstaller
    # path/to/spec`` on some platforms).  Fall back to the current working
    # directory so the build keeps functioning.
    spec_path = globals().get("__file__")
    if spec_path:
        return Path(spec_path).resolve().parent
    return Path.cwd()

block_cipher = None

PROJECT_ROOT = _resolve_project_root()


datas = [
    (str(PROJECT_ROOT / "mcsmartscan" / "mullvadproxyips.txt"), "mcsmartscan"),
]


a = Analysis(
    ['app.py'],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='MinecraftServerFinder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
