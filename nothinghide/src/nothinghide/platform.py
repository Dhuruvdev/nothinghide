"""Cross-platform utilities for Windows PowerShell and Linux/macOS compatibility."""

import os
import sys
import platform
from pathlib import Path
from typing import Optional

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

def get_config_dir() -> Path:
    """Get the user configuration directory (cross-platform)."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return Path(base) / "nothinghide"
    else:
        xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        return Path(xdg_config) / "nothinghide"


def get_data_dir() -> Path:
    """Get the user data directory (cross-platform)."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", os.path.expanduser("~")))
        return Path(base) / "nothinghide"
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        return Path(xdg_data) / "nothinghide"


def get_cache_dir() -> Path:
    """Get the user cache directory (cross-platform)."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", os.path.expanduser("~")))
        return Path(base) / "nothinghide" / "cache"
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
        return Path(xdg_cache) / "nothinghide"


def clear_screen() -> None:
    """Clear the terminal screen (cross-platform).
    
    Uses ANSI escape codes which work on:
    - Linux/macOS terminals
    - Windows Terminal
    - Windows PowerShell (with VT support)
    - Windows CMD (Windows 10+)
    
    Falls back to system command for older Windows.
    """
    if IS_WINDOWS:
        if sys.stdout.isatty():
            try:
                print("\033[2J\033[H", end="", flush=True)
            except Exception:
                os.system("cls")
        else:
            pass
    else:
        print("\033[2J\033[H", end="", flush=True)


def enable_windows_ansi() -> None:
    """Enable ANSI escape code support on Windows."""
    if not IS_WINDOWS:
        return
    
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def get_shell_type() -> str:
    """Detect the current shell type."""
    shell = os.environ.get("SHELL", "")
    comspec = os.environ.get("COMSPEC", "")
    psmodulepath = os.environ.get("PSModulePath", "")
    
    if psmodulepath:
        return "powershell"
    elif "bash" in shell:
        return "bash"
    elif "zsh" in shell:
        return "zsh"
    elif "fish" in shell:
        return "fish"
    elif comspec and "cmd" in comspec.lower():
        return "cmd"
    else:
        return "unknown"


def supports_unicode() -> bool:
    """Check if the terminal supports Unicode characters."""
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.kernel32.GetConsoleOutputCP() == 65001  # type: ignore[attr-defined]
        except Exception:
            return False
    return True


def get_terminal_width() -> int:
    """Get terminal width (cross-platform)."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except Exception:
        return 80
