"""Branding and visual presentation module.

This module provides consistent branding, ASCII art, and styled output
for the NothingHide CLI tool with clean, uncensored aesthetics.
"""

from rich.console import Console
from rich.text import Text
from rich.align import Align

from . import __version__
from .config import VERSION

CYAN = "#00F5FF"
CYAN_DARK = "#00B4D8"
PURPLE = "#A855F7"
MAGENTA = "#F472B6"
GREEN = "#22C55E"
YELLOW = "#FBBF24"
RED = "#FF3B3B"
GRAY = "#6B7280"
WHITE = "#FFFFFF"

BANNER = """[bold #00F5FF]
 _   _       _   _     _             _   _ _     _      
| \\ | | ___ | |_| |__ (_)_ __   __ _| | | (_) __| | ___ 
|  \\| |/ _ \\| __| '_ \\| | '_ \\ / _` | |_| | |/ _` |/ _ \\
| |\\  | (_) | |_| | | | | | | | (_| |  _  | | (_| |  __/
|_| \\_|\\___/ \\__|_| |_|_|_| |_|\\__, |_| |_|_|\\__,_|\\___|
                               |___/                    
[/bold #00F5FF]"""

TAGLINE = "[bold #A855F7]▓▓▓[/] [bold #FFFFFF]CYBERSECURITY CLI[/] [bold #A855F7]▓▓▓[/]"

SKULL = """[bold #FF3B3B]
    ░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░▄▄▄▄▄▄░░░░░░░░░░░
    ░░░░░░░▄█████████▄░░░░░░░░
    ░░░░░▄███████████▄░░░░░░░░
    ░░░░░█████▀░░▀████░░░░░░░░
    ░░░░░████░░░░░░████░░░░░░░
    ░░░░░▀▀▀░░░░░░░▀▀▀░░░░░░░░
[/bold #FF3B3B]"""


def get_terminal_size(console: Console) -> tuple[int, int]:
    return console.width, console.height


def render_banner(console: Console) -> None:
    """Render the main NothingHide banner."""
    console.print(BANNER, justify="center")
    console.print(TAGLINE, justify="center")
    console.print()


def render_welcome(console: Console, show_tagline: bool = True) -> None:
    """Render the full welcome screen."""
    console.print()
    render_banner(console)
    
    version = Text()
    version.append("v", style=GRAY)
    version.append(VERSION, style=f"bold {CYAN}")
    console.print(Align.center(version))
    
    if show_tagline:
        console.print()
        console.print(f"[{GRAY}]Check emails & passwords against breach databases[/{GRAY}]", justify="center")
        console.print(f"[{GRAY}]100% lawful sources • No data stored[/{GRAY}]", justify="center")
    
    console.print()


def render_status(console: Console, status: str, status_type: str = "info") -> None:
    """Render a status message."""
    icons = {
        "info": ("▸", CYAN),
        "success": ("✓", GREEN),
        "warning": ("!", YELLOW),
        "error": ("✗", RED),
    }
    
    icon, color = icons.get(status_type, ("▸", CYAN))
    
    text = Text()
    text.append(f"  {icon} ", style=f"bold {color}")
    text.append(status, style=WHITE)
    console.print(text)


def render_menu(console: Console) -> None:
    """Render the main menu."""
    console.print()
    console.print(f"[bold {PURPLE}]═══════════════════════════════════════════════════[/]", justify="center")
    console.print()
    
    menu_items = [
        ("1", "Email Breach Check", "scan breach databases"),
        ("2", "Password Check", "k-anonymity lookup"),
        ("3", "Full Scan", "complete identity check"),
        ("4", "Help", "documentation"),
        ("5", "Exit", "quit"),
    ]
    
    for num, title, desc in menu_items:
        line = Text()
        line.append(f"    [{num}] ", style=f"bold {CYAN}")
        line.append(f"{title:<20}", style=f"bold {WHITE}")
        line.append(f"  {desc}", style=GRAY)
        console.print(line)
    
    console.print()
    console.print(f"[bold {PURPLE}]═══════════════════════════════════════════════════[/]", justify="center")
    console.print()


def render_input_prompt(console: Console) -> str:
    """Render input prompt and get user choice."""
    prompt = Text()
    prompt.append("  >> ", style=f"bold {CYAN}")
    console.print(prompt, end="")
    
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return "5"


def render_keyboard_shortcuts(console: Console) -> None:
    """Render keyboard shortcuts."""
    shortcuts = Text()
    shortcuts.append("  [", style=GRAY)
    shortcuts.append("Ctrl+C", style=f"bold {WHITE}")
    shortcuts.append("] exit  ", style=GRAY)
    shortcuts.append("[", style=GRAY)
    shortcuts.append("?", style=f"bold {WHITE}")
    shortcuts.append("] help", style=GRAY)
    console.print(shortcuts)


def render_section_header(console: Console, title: str, icon: str = "▓") -> None:
    """Render a section header."""
    console.print()
    header = Text()
    header.append(f"  {icon} ", style=f"bold {PURPLE}")
    header.append(title.upper(), style=f"bold {WHITE}")
    header.append(f" {icon}", style=f"bold {PURPLE}")
    console.print(header)
    console.print(f"  [bold {PURPLE}]{'─' * (len(title) + 6)}[/]")
    console.print()


def render_command_header(console: Console, command_name: str, description: str = "") -> None:
    """Render a command header."""
    render_banner(console)
    
    header = Text()
    header.append("▓ ", style=f"bold {PURPLE}")
    header.append(command_name.upper(), style=f"bold {WHITE}")
    header.append(" ▓", style=f"bold {PURPLE}")
    console.print(Align.center(header))
    
    if description:
        console.print(f"[{GRAY}]{description}[/{GRAY}]", justify="center")
    
    console.print()


def render_footer(console: Console, data_source: str = "") -> None:
    """Render footer with data source."""
    console.print()
    
    if data_source:
        console.print(f"  [{GRAY}]source: {data_source}[/{GRAY}]")
    
    console.print()
    footer = Text()
    footer.append("  ▓▓▓ ", style=f"bold {PURPLE}")
    footer.append("NOTHINGHIDE", style=f"bold {CYAN}")
    footer.append(" | ", style=GRAY)
    footer.append("Secure Exposure Intelligence", style=GRAY)
    footer.append(" ▓▓▓", style=f"bold {PURPLE}")
    console.print(footer)
    console.print()


def render_privacy_notice(console: Console) -> None:
    """Render privacy notice."""
    console.print()
    console.print(f"  [{GREEN}]🔒 PRIVACY: Your data is never stored or transmitted[/{GREEN}]")
    console.print(f"  [{GRAY}]   Password uses k-anonymity - only partial hash sent[/{GRAY}]")
    console.print()


def render_exposed_status(console: Console) -> None:
    """Render EXPOSED status with impact."""
    console.print()
    exposed = Text()
    exposed.append("  ▓▓▓ ", style=f"bold {RED}")
    exposed.append("STATUS: ", style=f"bold {WHITE}")
    exposed.append("EXPOSED", style=f"bold {RED}")
    exposed.append(" ▓▓▓", style=f"bold {RED}")
    console.print(exposed)
    console.print()


def render_clear_status(console: Console) -> None:
    """Render CLEAR status."""
    console.print()
    clear = Text()
    clear.append("  ▓▓▓ ", style=f"bold {GREEN}")
    clear.append("STATUS: ", style=f"bold {WHITE}")
    clear.append("CLEAR", style=f"bold {GREEN}")
    clear.append(" ▓▓▓", style=f"bold {GREEN}")
    console.print(clear)
    console.print()


def render_not_found_status(console: Console) -> None:
    """Render NOT FOUND status."""
    console.print()
    notfound = Text()
    notfound.append("  ▓▓▓ ", style=f"bold {GREEN}")
    notfound.append("STATUS: ", style=f"bold {WHITE}")
    notfound.append("NOT FOUND", style=f"bold {GREEN}")
    notfound.append(" ▓▓▓", style=f"bold {GREEN}")
    console.print(notfound)
    console.print()


def render_success_banner(console: Console, message: str) -> None:
    """Render success message."""
    console.print()
    msg = Text()
    msg.append("  ✓ ", style=f"bold {GREEN}")
    msg.append(message, style=f"bold {WHITE}")
    console.print(msg)
    console.print()


def render_error_banner(console: Console, message: str) -> None:
    """Render error message."""
    console.print()
    msg = Text()
    msg.append("  ✗ ", style=f"bold {RED}")
    msg.append(message, style=f"bold {WHITE}")
    console.print(msg)
    console.print()


def render_warning_banner(console: Console, message: str) -> None:
    """Render warning message."""
    console.print()
    msg = Text()
    msg.append("  ! ", style=f"bold {YELLOW}")
    msg.append(message, style=f"bold {WHITE}")
    console.print(msg)
    console.print()
