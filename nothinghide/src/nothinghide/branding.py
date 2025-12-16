"""Branding and visual presentation module.

This module provides consistent branding, ASCII art, and styled output
for the NothingHide CLI tool with clean, simple aesthetics.
"""

import os
import subprocess
from pathlib import Path
from rich.console import Console
from rich.text import Text
from rich.align import Align

from . import __version__
from .config import VERSION

WHITE = "#FFFFFF"
GRAY = "#6B7280"
GREEN = "#22C55E"
YELLOW = "#FBBF24"
RED = "#FF3B3B"
CYAN = "#00F5FF"
PURPLE = "#A855F7"

ASSETS_DIR = Path(__file__).parent.parent.parent / "assets"


def get_terminal_size(console: Console) -> tuple[int, int]:
    return console.width, console.height


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')


def run_fastfetch(console: Console) -> None:
    """Run fastfetch with NothingHide ASCII art logo."""
    logo_path = ASSETS_DIR / "logo.txt"
    config_path = ASSETS_DIR / "fastfetch.jsonc"
    
    try:
        cmd = ["fastfetch"]
        if logo_path.exists():
            cmd.extend(["--logo", str(logo_path), "--logo-type", "file"])
        if config_path.exists():
            cmd.extend(["--config", str(config_path)])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(ASSETS_DIR.parent)
        )
        if result.returncode == 0:
            console.print(result.stdout, style=WHITE)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        console.print("""
 _   _       _   _     _             _   _ _     _      
| \\ | | ___ | |_| |__ (_)_ __   __ _| | | (_) __| | ___ 
|  \\| |/ _ \\| __| '_ \\| | '_ \\ / _` | |_| | |/ _` |/ _ \\
| |\\  | (_) | |_| | | | | | | | (_| |  _  | | (_| |  __/
|_| \\_|\\___/ \\__|_| |_|_|_| |_|\\__, |_| |_|_|\\__,_|\\___|
                               |___/                    
""", style=WHITE)


def render_banner(console: Console) -> None:
    """Render the main NothingHide banner using fastfetch."""
    clear_screen()
    console.print()
    run_fastfetch(console)
    console.print(f"v{VERSION}", style=GRAY, justify="center")
    console.print()


def render_welcome(console: Console, show_tagline: bool = True) -> None:
    """Render the full welcome screen."""
    render_banner(console)
    
    if show_tagline:
        console.print("Check emails and passwords against breach databases", style=GRAY, justify="center")
        console.print("100% lawful sources - No data stored", style=GRAY, justify="center")
    
    console.print()


def render_status(console: Console, status: str, status_type: str = "info") -> None:
    """Render a status message."""
    icons = {
        "info": "->",
        "success": "[ok]",
        "warning": "[!]",
        "error": "[x]",
    }
    
    icon = icons.get(status_type, "->")
    console.print(f"  {icon} {status}", style=WHITE)


def render_menu(console: Console) -> None:
    """Render the main menu."""
    console.print()
    
    menu_items = [
        ("1", "Email Breach Check", "scan breach databases"),
        ("2", "Password Check", "k-anonymity lookup"),
        ("3", "Full Scan", "complete identity check"),
        ("4", "Help", "documentation"),
        ("5", "Exit", "quit"),
    ]
    
    for num, title, desc in menu_items:
        console.print(f"    [{num}] {title:<20}  {desc}", style=WHITE)
    
    console.print()


def render_input_prompt(console: Console) -> str:
    """Render input prompt and get user choice."""
    console.print("  >> ", style=WHITE, end="")
    
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return "5"


def render_keyboard_shortcuts(console: Console) -> None:
    """Render keyboard shortcuts."""
    console.print("  [Ctrl+C] exit  [?] help", style=GRAY)


def render_section_header(console: Console, title: str, icon: str = "") -> None:
    """Render a section header."""
    console.print()
    console.print(f"  {title.upper()}", style=f"bold {WHITE}")
    console.print(f"  {'-' * len(title)}", style=GRAY)
    console.print()


def render_command_header(console: Console, command_name: str, description: str = "") -> None:
    """Render a command header with clear screen."""
    clear_screen()
    console.print()
    console.print("""
 _   _       _   _     _             _   _ _     _      
| \\ | | ___ | |_| |__ (_)_ __   __ _| | | (_) __| | ___ 
|  \\| |/ _ \\| __| '_ \\| | '_ \\ / _` | |_| | |/ _` |/ _ \\
| |\\  | (_) | |_| | | | | | | | (_| |  _  | | (_| |  __/
|_| \\_|\\___/ \\__|_| |_|_|_| |_|\\__, |_| |_|_|\\__,_|\\___|
                               |___/                    
""", style=WHITE)
    console.print(command_name.upper(), style=f"bold {WHITE}", justify="center")
    
    if description:
        console.print(description, style=GRAY, justify="center")
    
    console.print()


def render_footer(console: Console, data_source: str = "") -> None:
    """Render footer with data source."""
    console.print()
    
    if data_source:
        console.print(f"  source: {data_source}", style=GRAY)
    
    console.print()
    console.print("  NothingHide - Secure Exposure Intelligence", style=WHITE)
    console.print()


def render_privacy_notice(console: Console) -> None:
    """Render privacy notice."""
    console.print()
    console.print("  [ok] PRIVACY: Your data is never stored or transmitted", style=WHITE)
    console.print("       Password uses k-anonymity - only partial hash sent", style=GRAY)
    console.print()


def render_exposed_status(console: Console) -> None:
    """Render EXPOSED status with impact."""
    console.print()
    console.print("  STATUS: EXPOSED", style=f"bold {WHITE}")
    console.print()


def render_clear_status(console: Console) -> None:
    """Render CLEAR status."""
    console.print()
    console.print("  STATUS: CLEAR", style=f"bold {WHITE}")
    console.print()


def render_not_found_status(console: Console) -> None:
    """Render NOT FOUND status."""
    console.print()
    console.print("  STATUS: NOT FOUND", style=f"bold {WHITE}")
    console.print()


def render_success_banner(console: Console, message: str) -> None:
    """Render success message."""
    console.print()
    console.print(f"  [ok] {message}", style=WHITE)
    console.print()


def render_error_banner(console: Console, message: str) -> None:
    """Render error message."""
    console.print()
    console.print(f"  [x] {message}", style=WHITE)
    console.print()


def render_warning_banner(console: Console, message: str) -> None:
    """Render warning message."""
    console.print()
    console.print(f"  [!] {message}", style=WHITE)
    console.print()
