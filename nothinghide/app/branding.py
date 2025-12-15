"""Branding and visual presentation module.

This module provides consistent branding, ASCII art, and styled output
for the NothingHide CLI tool.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.style import Style
from rich.table import Table

from . import __version__
from .config import VERSION

CYAN_PRIMARY = "#00C2FF"
CYAN_DARK = "#0099CC"
GREEN_SUCCESS = "#1FDB7D"
AMBER_WARNING = "#F9A825"
RED_ERROR = "#FF5252"
GRAY_DIM = "#6B7280"
WHITE = "#FFFFFF"
MAGENTA_ACCENT = "#FF69B4"

WELCOME_TEXT = "[white]Welcome to[/white]"

BANNER_FULL = """[cyan]███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗███╗   ██╗ ██████╗ ██╗  ██╗██╗██████╗ ███████╗[/cyan]
[cyan]████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝ ██║  ██║██║██╔══██╗██╔════╝[/cyan]
[cyan]██╔██╗ ██║██║   ██║   ██║   ███████║██║██╔██╗ ██║██║  ███╗███████║██║██║  ██║█████╗  [/cyan]
[cyan]██║╚██╗██║██║   ██║   ██║   ██╔══██║██║██║╚██╗██║██║   ██║██╔══██║██║██║  ██║██╔══╝  [/cyan]
[cyan]██║ ╚████║╚██████╔╝   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝██║  ██║██║██████╔╝███████╗[/cyan]
[cyan]╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝[/cyan]"""

BANNER_MEDIUM = """[cyan]╔╗╔╔═╗╔╦╗╦ ╦╦╔╗╔╔═╗╦ ╦╦╔╦╗╔═╗[/cyan]
[cyan]║║║║ ║ ║ ╠═╣║║║║║ ╦╠═╣║ ║║║╣ [/cyan]
[cyan]╝╚╝╚═╝ ╩ ╩ ╩╩╝╚╝╚═╝╩ ╩╩═╩╝╚═╝[/cyan]"""

BANNER_COMPACT = "[cyan]NOTHINGHIDE[/cyan]"

MASCOT_ART = """[cyan]    ██████████    [/cyan]
[cyan]  ██[/cyan][green]░░░░░░░░[/green][cyan]██  [/cyan]
[cyan]██[/cyan][green]░░[/green][bright_magenta]████[/bright_magenta][green]░░░░[/green][cyan]██[/cyan]
[cyan]██[/cyan][green]░░[/green][bright_magenta]████[/bright_magenta][green]░░░░[/green][cyan]██[/cyan]
[cyan]██[/cyan][green]░░░░░░░░░░[/green][cyan]██[/cyan]
[cyan]  ██[/cyan][green]░░[/green][white]██[/white][green]░░[/green][cyan]██  [/cyan]
[cyan]    ██████████    [/cyan]"""

MASCOT_COMPACT = "[cyan]◆[/cyan]"


def get_terminal_size(console: Console) -> tuple[int, int]:
    """Get terminal width and height.
    
    Args:
        console: Rich console instance.
        
    Returns:
        Tuple of (width, height).
    """
    return console.width, console.height


def render_banner(console: Console) -> None:
    """Render the NothingHide ASCII art banner with mascot.
    
    Adapts to terminal width for responsive display.
    
    Args:
        console: Rich console instance.
    """
    width = console.width
    
    console.print()
    
    if width >= 100:
        console.print(WELCOME_TEXT, justify="center")
        console.print()
        banner_lines = BANNER_FULL.strip().split('\n')
        mascot_lines = MASCOT_ART.strip().split('\n')
        
        max_mascot_lines = len(mascot_lines)
        max_banner_lines = len(banner_lines)
        
        for i in range(max(max_banner_lines, max_mascot_lines)):
            banner_line = banner_lines[i] if i < max_banner_lines else " " * 80
            mascot_line = mascot_lines[i] if i < max_mascot_lines else " " * 18
            console.print(f"  {banner_line}  {mascot_line}")
    elif width >= 50:
        console.print(WELCOME_TEXT, justify="center")
        console.print()
        console.print(BANNER_MEDIUM, justify="center")
    else:
        console.print(WELCOME_TEXT, justify="center")
        console.print(BANNER_COMPACT, justify="center")
    
    console.print()


def render_welcome(console: Console, show_tagline: bool = True) -> None:
    """Render the welcome message with version info.
    
    Args:
        console: Rich console instance.
        show_tagline: Whether to show the tagline.
    """
    width = console.width
    
    render_banner(console)
    
    version_text = Text()
    version_text.append("CLI Version ", style=GRAY_DIM)
    version_text.append(VERSION, style=f"bold {CYAN_PRIMARY}")
    console.print(Align.center(version_text))
    
    if show_tagline and width >= 50:
        console.print()
        tagline = Text()
        tagline.append("NothingHide can check email breaches and password exposure right from your terminal.", style=WHITE)
        console.print(Align.center(tagline))
        
        help_text = Text()
        help_text.append("Select an option to get started or enter ", style=WHITE)
        help_text.append("?", style=f"bold {CYAN_PRIMARY}")
        help_text.append(" for help. Uses only lawful public sources.", style=WHITE)
        console.print(Align.center(help_text))
    
    console.print()


def render_status(console: Console, status: str, status_type: str = "info") -> None:
    """Render a status indicator.
    
    Args:
        console: Rich console instance.
        status: Status message to display.
        status_type: Type of status (info, success, warning, error).
    """
    colors = {
        "info": CYAN_PRIMARY,
        "success": GREEN_SUCCESS,
        "warning": AMBER_WARNING,
        "error": RED_ERROR,
    }
    
    symbols = {
        "info": "●",
        "success": "●",
        "warning": "●",
        "error": "●",
    }
    
    color = colors.get(status_type, CYAN_PRIMARY)
    symbol = symbols.get(status_type, "●")
    
    text = Text()
    text.append(f"  {symbol} ", style=color)
    text.append(status, style="white")
    console.print(text)


def render_menu(console: Console) -> None:
    """Render the main menu with numbered options.
    
    Args:
        console: Rich console instance.
    """
    console.print()
    
    menu_items = [
        ("1", "Email Check", "Check if your email appears in data breaches"),
        ("2", "Password Check", "Check if your password has been exposed"),
        ("3", "Full Scan", "Complete identity scan (email + password)"),
        ("4", "Help", "Show detailed help information"),
        ("5", "Exit", "Exit NothingHide"),
    ]
    
    for num, title, desc in menu_items:
        line = Text()
        line.append(f"  [{CYAN_PRIMARY}]{num}[/{CYAN_PRIMARY}]  ", style=CYAN_PRIMARY)
        line.append(f"{title}", style=f"bold {WHITE}")
        line.append(f"  - {desc}", style=GRAY_DIM)
        console.print(line)
    
    console.print()


def render_input_prompt(console: Console) -> str:
    """Render the input prompt and get user choice.
    
    Args:
        console: Rich console instance.
        
    Returns:
        User's choice as string.
    """
    prompt_text = Text()
    prompt_text.append("> ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return "5"


def render_keyboard_shortcuts(console: Console) -> None:
    """Render keyboard shortcuts footer.
    
    Args:
        console: Rich console instance.
    """
    console.print()
    shortcuts = Text()
    shortcuts.append("Ctrl+c", style=f"bold {WHITE}")
    shortcuts.append(" Exit", style=GRAY_DIM)
    shortcuts.append("  ·  ", style=GRAY_DIM)
    shortcuts.append("?", style=f"bold {WHITE}")
    shortcuts.append(" Help", style=GRAY_DIM)
    console.print(shortcuts)


def render_section_header(console: Console, title: str) -> None:
    """Render a section header.
    
    Args:
        console: Rich console instance.
        title: Section title.
    """
    width = console.width
    
    if width >= 60:
        console.print()
        console.print(Panel(
            Text(title, style=f"bold {WHITE}", justify="center"),
            border_style=CYAN_PRIMARY,
            padding=(0, 2),
        ))
    else:
        console.print()
        console.print(f"[bold {CYAN_PRIMARY}]--- {title} ---[/bold {CYAN_PRIMARY}]", justify="center")
    
    console.print()


def render_result_box(
    console: Console,
    title: str,
    content: str,
    result_type: str = "info"
) -> None:
    """Render a result in a styled box.
    
    Args:
        console: Rich console instance.
        title: Box title.
        content: Box content.
        result_type: Type of result (info, success, warning, error).
    """
    colors = {
        "info": CYAN_PRIMARY,
        "success": GREEN_SUCCESS,
        "warning": AMBER_WARNING,
        "error": RED_ERROR,
    }
    
    color = colors.get(result_type, CYAN_PRIMARY)
    width = console.width
    
    if width >= 50:
        console.print(Panel(
            content,
            title=f"[bold]{title}[/bold]",
            border_style=color,
            padding=(0, 2),
        ))
    else:
        console.print(f"[bold {color}]{title}[/bold {color}]")
        console.print(content)


def render_command_header(console: Console, command_name: str, description: str = "") -> None:
    """Render a command header with consistent styling.
    
    Args:
        console: Rich console instance.
        command_name: Name of the command.
        description: Optional description.
    """
    width = console.width
    
    render_banner(console)
    
    if width >= 60:
        header_text = Text()
        header_text.append(command_name.upper(), style=f"bold {CYAN_PRIMARY}")
        if description:
            header_text.append(f" - {description}", style=GRAY_DIM)
        console.print(Align.center(header_text))
    else:
        console.print(f"[bold {CYAN_PRIMARY}]{command_name.upper()}[/bold {CYAN_PRIMARY}]", justify="center")
    
    version_text = Text()
    version_text.append("v", style=GRAY_DIM)
    version_text.append(VERSION, style=GRAY_DIM)
    console.print(Align.center(version_text))
    console.print()


def render_footer(console: Console, data_source: str = "") -> None:
    """Render a footer with data source attribution.
    
    Args:
        console: Rich console instance.
        data_source: Data source to attribute.
    """
    console.print()
    
    if data_source:
        footer = Text()
        footer.append("Data source: ", style=GRAY_DIM)
        footer.append(data_source, style=GRAY_DIM)
        console.print(footer)
    
    footer_line = Text()
    footer_line.append("NothingHide", style=f"bold {CYAN_PRIMARY}")
    footer_line.append(" - Secure Exposure Intelligence", style=GRAY_DIM)
    console.print(footer_line)
    console.print()


def render_privacy_notice(console: Console) -> None:
    """Render a privacy notice.
    
    Args:
        console: Rich console instance.
    """
    width = console.width
    
    notice = "Your data is never stored or logged. Passwords use k-anonymity."
    
    if width >= 70:
        console.print(Panel(
            Text(notice, style=GRAY_DIM, justify="center"),
            border_style=GRAY_DIM,
            padding=(0, 1),
        ))
    else:
        console.print(f"[{GRAY_DIM}]{notice}[/{GRAY_DIM}]")
