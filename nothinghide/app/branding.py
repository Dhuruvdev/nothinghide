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

BANNER_FULL = """
[cyan]███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗███╗   ██╗ ██████╗ [/cyan][bright_white]██╗  ██╗██╗██████╗ ███████╗[/bright_white]
[cyan]████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝ [/cyan][bright_white]██║  ██║██║██╔══██╗██╔════╝[/bright_white]
[cyan]██╔██╗ ██║██║   ██║   ██║   ███████║██║██╔██╗ ██║██║  ███╗[/cyan][bright_white]███████║██║██║  ██║█████╗  [/bright_white]
[cyan]██║╚██╗██║██║   ██║   ██║   ██╔══██║██║██║╚██╗██║██║   ██║[/cyan][bright_white]██╔══██║██║██║  ██║██╔══╝  [/bright_white]
[cyan]██║ ╚████║╚██████╔╝   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝[/cyan][bright_white]██║  ██║██║██████╔╝███████╗[/bright_white]
[cyan]╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ [/cyan][bright_white]╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝[/bright_white]
"""

BANNER_MEDIUM = """
[cyan]╔╗╔╔═╗╔╦╗╦ ╦╦╔╗╔╔═╗[/cyan][bright_white]╦ ╦╦╔╦╗╔═╗[/bright_white]
[cyan]║║║║ ║ ║ ╠═╣║║║║║ ╦[/cyan][bright_white]╠═╣║ ║║║╣ [/bright_white]
[cyan]╝╚╝╚═╝ ╩ ╩ ╩╩╝╚╝╚═╝[/cyan][bright_white]╩ ╩╩═╩╝╚═╝[/bright_white]
"""

BANNER_COMPACT = "[cyan]NOTHING[/cyan][bright_white]HIDE[/bright_white]"

SHIELD_ART = """
[cyan]    ╔═══════╗    [/cyan]
[cyan]   ╔╝ ░░░░░ ╚╗   [/cyan]
[cyan]   ║ ░░███░░ ║   [/cyan]
[cyan]   ║ ░█████░ ║   [/cyan]
[cyan]   ║ ░░███░░ ║   [/cyan]
[cyan]   ╚╗ ░░░░░ ╔╝   [/cyan]
[cyan]    ╚═══════╝    [/cyan]
"""

SHIELD_COMPACT = "[cyan]◆[/cyan]"


def get_terminal_size(console: Console) -> tuple[int, int]:
    """Get terminal width and height.
    
    Args:
        console: Rich console instance.
        
    Returns:
        Tuple of (width, height).
    """
    return console.width, console.height


def render_banner(console: Console) -> None:
    """Render the NothingHide ASCII art banner.
    
    Adapts to terminal width for responsive display.
    
    Args:
        console: Rich console instance.
    """
    width = console.width
    
    console.print()
    
    if width >= 90:
        console.print(BANNER_FULL, justify="center")
    elif width >= 40:
        console.print(BANNER_MEDIUM, justify="center")
    else:
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
        tagline = Text()
        tagline.append("Secure Exposure Intelligence", style=f"italic {GRAY_DIM}")
        console.print(Align.center(tagline))
    
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
