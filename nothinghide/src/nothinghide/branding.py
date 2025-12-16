"""Branding and visual presentation module.

This module provides consistent branding, ASCII art, and styled output
for the NothingHide CLI tool with professional aesthetics.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.style import Style
from rich.table import Table
from rich import box

from . import __version__
from .config import VERSION

CYAN_PRIMARY = "#00D4FF"
CYAN_GLOW = "#00F5FF"
CYAN_DARK = "#0099CC"
PURPLE_ACCENT = "#A855F7"
PURPLE_GLOW = "#C084FC"
MAGENTA_ACCENT = "#F472B6"
GREEN_SUCCESS = "#22C55E"
GREEN_GLOW = "#4ADE80"
AMBER_WARNING = "#FBBF24"
AMBER_GLOW = "#FCD34D"
RED_ERROR = "#EF4444"
RED_GLOW = "#F87171"
GRAY_DIM = "#6B7280"
GRAY_LIGHT = "#9CA3AF"
WHITE = "#F9FAFB"
DARK_BG = "#1F2937"

BANNER_FULL = """
[bold #00D4FF]╔═══════════════════════════════════════════════════════════════════════════════════════╗[/]
[bold #00D4FF]║[/]                                                                                       [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00F5FF]███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗███╗   ██╗ ██████╗ ██╗  ██╗██╗██████╗ ███████╗[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00E5FF]████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝ ██║  ██║██║██╔══██╗██╔════╝[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00D4FF]██╔██╗ ██║██║   ██║   ██║   ███████║██║██╔██╗ ██║██║  ███╗███████║██║██║  ██║█████╗[/]    [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00C4FF]██║╚██╗██║██║   ██║   ██║   ██╔══██║██║██║╚██╗██║██║   ██║██╔══██║██║██║  ██║██╔══╝[/]    [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00B4FF]██║ ╚████║╚██████╔╝   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝██║  ██║██║██████╔╝███████╗[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00A4FF]╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]                                                                                       [bold #00D4FF]║[/]
[bold #00D4FF]╚═══════════════════════════════════════════════════════════════════════════════════════╝[/]"""

BANNER_MEDIUM = """
[bold #00D4FF]╔════════════════════════════════════════════╗[/]
[bold #00D4FF]║[/]                                            [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00F5FF]╔╗╔╔═╗╔╦╗╦ ╦╦╔╗╔╔═╗╦ ╦╦╔╦╗╔═╗[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00D4FF]║║║║ ║ ║ ╠═╣║║║║║ ╦╠═╣║ ║║║╣ [/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]  [bold #00B4FF]╝╚╝╚═╝ ╩ ╩ ╩╩╝╚╝╚═╝╩ ╩╩═╩╝╚═╝[/]  [bold #00D4FF]║[/]
[bold #00D4FF]║[/]                                            [bold #00D4FF]║[/]
[bold #00D4FF]╚════════════════════════════════════════════╝[/]"""

BANNER_COMPACT = """[bold #00D4FF]╔═══════════════════════════╗[/]
[bold #00D4FF]║[/]  [bold #00F5FF]N O T H I N G H I D E[/]  [bold #00D4FF]║[/]
[bold #00D4FF]╚═══════════════════════════╝[/]"""

SHIELD_ICON = """[bold #00D4FF]    ╔══╗    [/]
[bold #00D4FF]   ╔╝[/][bold #22C55E]██[/][bold #00D4FF]╚╗   [/]
[bold #00D4FF]  ╔╝[/][bold #22C55E]████[/][bold #00D4FF]╚╗  [/]
[bold #00D4FF]  ║[/][bold #22C55E]██████[/][bold #00D4FF]║  [/]
[bold #00D4FF]  ╚╗[/][bold #22C55E]████[/][bold #00D4FF]╔╝  [/]
[bold #00D4FF]   ╚╗[/][bold #22C55E]██[/][bold #00D4FF]╔╝   [/]
[bold #00D4FF]    ╚══╝    [/]"""

DIVIDER_DOUBLE = f"[{CYAN_PRIMARY}]{'═' * 60}[/{CYAN_PRIMARY}]"
DIVIDER_SINGLE = f"[{GRAY_DIM}]{'─' * 60}[/{GRAY_DIM}]"
DIVIDER_DOTS = f"[{GRAY_DIM}]{'·' * 60}[/{GRAY_DIM}]"


def get_terminal_size(console: Console) -> tuple[int, int]:
    """Get terminal width and height."""
    return console.width, console.height


def clear_screen(console: Console) -> None:
    """Clear the terminal screen."""
    console.clear()


def render_banner(console: Console, with_border: bool = True) -> None:
    """Render the NothingHide ASCII art banner.
    
    Adapts to terminal width for responsive display.
    """
    width = console.width
    console.print()
    
    if width >= 95:
        console.print(BANNER_FULL, justify="center")
    elif width >= 50:
        console.print(BANNER_MEDIUM, justify="center")
    else:
        console.print(BANNER_COMPACT, justify="center")
    
    console.print()


def render_tagline(console: Console) -> None:
    """Render the professional tagline."""
    tagline = Text()
    tagline.append("█", style=f"bold {CYAN_PRIMARY}")
    tagline.append(" SECURE EXPOSURE INTELLIGENCE ", style=f"bold {WHITE}")
    tagline.append("█", style=f"bold {CYAN_PRIMARY}")
    console.print(Align.center(tagline))


def render_version(console: Console) -> None:
    """Render version badge."""
    version_text = Text()
    version_text.append("┌─", style=GRAY_DIM)
    version_text.append(f" v{VERSION} ", style=f"bold {CYAN_PRIMARY}")
    version_text.append("─┐", style=GRAY_DIM)
    console.print(Align.center(version_text))


def render_welcome(console: Console, show_tagline: bool = True) -> None:
    """Render the complete welcome screen with professional styling."""
    console.print()
    render_banner(console)
    render_tagline(console)
    console.print()
    render_version(console)
    
    if show_tagline:
        console.print()
        desc = Text()
        desc.append("Check if your email or password has been exposed in data breaches", style=GRAY_LIGHT)
        console.print(Align.center(desc))
        
        source_info = Text()
        source_info.append("Using only lawful, publicly available sources", style=GRAY_DIM)
        console.print(Align.center(source_info))
    
    console.print()


def render_status(console: Console, status: str, status_type: str = "info") -> None:
    """Render a styled status indicator."""
    styles = {
        "info": (CYAN_PRIMARY, "◆"),
        "success": (GREEN_SUCCESS, "✓"),
        "warning": (AMBER_WARNING, "⚠"),
        "error": (RED_ERROR, "✗"),
    }
    
    color, symbol = styles.get(status_type, (CYAN_PRIMARY, "●"))
    
    text = Text()
    text.append(f"  {symbol} ", style=f"bold {color}")
    text.append(status, style=WHITE)
    console.print(text)


def render_menu(console: Console) -> None:
    """Render the main menu with professional styling."""
    console.print()
    
    menu_box = Text()
    menu_box.append("┌", style=CYAN_PRIMARY)
    menu_box.append("─" * 50, style=CYAN_PRIMARY)
    menu_box.append(" MAIN MENU ", style=f"bold {WHITE}")
    menu_box.append("─" * 5, style=CYAN_PRIMARY)
    menu_box.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(menu_box))
    
    console.print(Align.center(Text("│" + " " * 66 + "│", style=CYAN_PRIMARY)))
    
    menu_items = [
        ("1", "Email Breach Check", "Scan public breach databases"),
        ("2", "Password Security", "Check password exposure (k-anonymity)"),
        ("3", "Full Identity Scan", "Complete exposure analysis"),
        ("4", "Help & Information", "Documentation and guidance"),
        ("5", "Exit Application", "Close NothingHide"),
    ]
    
    for num, title, desc in menu_items:
        line = Text()
        line.append("│  ", style=CYAN_PRIMARY)
        line.append(f"[{num}]", style=f"bold {CYAN_GLOW}")
        line.append("  ", style="")
        line.append(f"{title:<22}", style=f"bold {WHITE}")
        line.append(f"{desc:<36}", style=GRAY_DIM)
        line.append("│", style=CYAN_PRIMARY)
        console.print(Align.center(line))
    
    console.print(Align.center(Text("│" + " " * 66 + "│", style=CYAN_PRIMARY)))
    
    menu_bottom = Text()
    menu_bottom.append("└", style=CYAN_PRIMARY)
    menu_bottom.append("─" * 66, style=CYAN_PRIMARY)
    menu_bottom.append("┘", style=CYAN_PRIMARY)
    console.print(Align.center(menu_bottom))
    
    console.print()


def render_input_prompt(console: Console) -> str:
    """Render the input prompt and get user choice."""
    prompt_text = Text()
    prompt_text.append("  ╰──▶ ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        return "5"


def render_keyboard_shortcuts(console: Console) -> None:
    """Render keyboard shortcuts footer with elegant styling."""
    shortcuts = Text()
    shortcuts.append("  ╭─────────────────────────────────────╮", style=GRAY_DIM)
    console.print(Align.center(shortcuts))
    
    keys = Text()
    keys.append("  │  ", style=GRAY_DIM)
    keys.append("Ctrl+C", style=f"bold {WHITE}")
    keys.append(" Exit  ", style=GRAY_DIM)
    keys.append("│", style=GRAY_DIM)
    keys.append("  ", style="")
    keys.append("?", style=f"bold {WHITE}")
    keys.append(" Help  ", style=GRAY_DIM)
    keys.append("│  ", style=GRAY_DIM)
    console.print(Align.center(keys))
    
    bottom = Text()
    bottom.append("  ╰─────────────────────────────────────╯", style=GRAY_DIM)
    console.print(Align.center(bottom))


def render_section_header(console: Console, title: str, icon: str = "◆") -> None:
    """Render a section header with professional styling."""
    console.print()
    
    header = Text()
    header.append("╔", style=f"bold {CYAN_PRIMARY}")
    header.append("═" * 8, style=f"bold {CYAN_PRIMARY}")
    header.append(f" {icon} {title} {icon} ", style=f"bold {WHITE}")
    header.append("═" * 8, style=f"bold {CYAN_PRIMARY}")
    header.append("╗", style=f"bold {CYAN_PRIMARY}")
    console.print(Align.center(header))
    
    console.print()


def render_result_box(
    console: Console,
    title: str,
    content: str,
    result_type: str = "info"
) -> None:
    """Render a result in a styled box."""
    colors = {
        "info": CYAN_PRIMARY,
        "success": GREEN_SUCCESS,
        "warning": AMBER_WARNING,
        "error": RED_ERROR,
    }
    
    color = colors.get(result_type, CYAN_PRIMARY)
    
    console.print(Panel(
        content,
        title=f"[bold {WHITE}]{title}[/bold {WHITE}]",
        border_style=color,
        box=box.DOUBLE,
        padding=(1, 3),
    ))


def render_command_header(console: Console, command_name: str, description: str = "") -> None:
    """Render a command header with consistent styling."""
    render_banner(console)
    
    header = Text()
    header.append("┌─", style=CYAN_PRIMARY)
    header.append(f" {command_name.upper()} ", style=f"bold {WHITE}")
    header.append("─┐", style=CYAN_PRIMARY)
    console.print(Align.center(header))
    
    if description:
        desc = Text()
        desc.append(description, style=GRAY_LIGHT)
        console.print(Align.center(desc))
    
    version_text = Text()
    version_text.append(f"v{VERSION}", style=GRAY_DIM)
    console.print(Align.center(version_text))
    console.print()


def render_footer(console: Console, data_source: str = "") -> None:
    """Render a footer with data source attribution."""
    console.print()
    
    if data_source:
        source = Text()
        source.append("┌─", style=GRAY_DIM)
        source.append(" Data Source: ", style=GRAY_DIM)
        source.append(data_source, style=GRAY_LIGHT)
        source.append(" ─┐", style=GRAY_DIM)
        console.print(Align.center(source))
    
    console.print()
    
    footer_line = Text()
    footer_line.append("╔═══════════════════════════════════════════════════════╗", style=CYAN_PRIMARY)
    console.print(Align.center(footer_line))
    
    brand = Text()
    brand.append("║", style=CYAN_PRIMARY)
    brand.append("          ", style="")
    brand.append("NOTHINGHIDE", style=f"bold {CYAN_GLOW}")
    brand.append(" │ ", style=GRAY_DIM)
    brand.append("Secure Exposure Intelligence", style=GRAY_LIGHT)
    brand.append("          ", style="")
    brand.append("║", style=CYAN_PRIMARY)
    console.print(Align.center(brand))
    
    footer_bottom = Text()
    footer_bottom.append("╚═══════════════════════════════════════════════════════╝", style=CYAN_PRIMARY)
    console.print(Align.center(footer_bottom))
    
    console.print()


def render_privacy_notice(console: Console) -> None:
    """Render a privacy notice with professional styling."""
    notice_box = Text()
    notice_box.append("╭─────────────────────────────────────────────────────────────────╮", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(notice_box))
    
    lock_line = Text()
    lock_line.append("│  ", style=f"bold {GREEN_SUCCESS}")
    lock_line.append("🔒 ", style="")
    lock_line.append("PRIVACY PROTECTED", style=f"bold {GREEN_SUCCESS}")
    lock_line.append(" │ Your data is never stored or logged      │", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(lock_line))
    
    method_line = Text()
    method_line.append("│  ", style=f"bold {GREEN_SUCCESS}")
    method_line.append("   Password checks use secure k-anonymity protocol          ", style=GRAY_LIGHT)
    method_line.append("│", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(method_line))
    
    notice_bottom = Text()
    notice_bottom.append("╰─────────────────────────────────────────────────────────────────╯", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(notice_bottom))


def render_loading_frame(console: Console, message: str) -> None:
    """Render a loading animation frame."""
    loading = Text()
    loading.append("  ⣾ ", style=f"bold {CYAN_PRIMARY}")
    loading.append(message, style=WHITE)
    console.print(loading, end="\r")


def render_success_banner(console: Console, message: str) -> None:
    """Render a success message with prominent styling."""
    console.print()
    
    success_box = Text()
    success_box.append("╔", style=f"bold {GREEN_SUCCESS}")
    success_box.append("═" * (len(message) + 10), style=f"bold {GREEN_SUCCESS}")
    success_box.append("╗", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(success_box))
    
    success_msg = Text()
    success_msg.append("║", style=f"bold {GREEN_SUCCESS}")
    success_msg.append(f"  ✓ {message}  ", style=f"bold {GREEN_GLOW}")
    success_msg.append("║", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(success_msg))
    
    success_bottom = Text()
    success_bottom.append("╚", style=f"bold {GREEN_SUCCESS}")
    success_bottom.append("═" * (len(message) + 10), style=f"bold {GREEN_SUCCESS}")
    success_bottom.append("╝", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(success_bottom))
    
    console.print()


def render_error_banner(console: Console, message: str) -> None:
    """Render an error message with prominent styling."""
    console.print()
    
    error_box = Text()
    error_box.append("╔", style=f"bold {RED_ERROR}")
    error_box.append("═" * (len(message) + 10), style=f"bold {RED_ERROR}")
    error_box.append("╗", style=f"bold {RED_ERROR}")
    console.print(Align.center(error_box))
    
    error_msg = Text()
    error_msg.append("║", style=f"bold {RED_ERROR}")
    error_msg.append(f"  ✗ {message}  ", style=f"bold {RED_GLOW}")
    error_msg.append("║", style=f"bold {RED_ERROR}")
    console.print(Align.center(error_msg))
    
    error_bottom = Text()
    error_bottom.append("╚", style=f"bold {RED_ERROR}")
    error_bottom.append("═" * (len(message) + 10), style=f"bold {RED_ERROR}")
    error_bottom.append("╝", style=f"bold {RED_ERROR}")
    console.print(Align.center(error_bottom))
    
    console.print()


def render_warning_banner(console: Console, message: str) -> None:
    """Render a warning message with prominent styling."""
    console.print()
    
    warning_box = Text()
    warning_box.append("╔", style=f"bold {AMBER_WARNING}")
    warning_box.append("═" * (len(message) + 10), style=f"bold {AMBER_WARNING}")
    warning_box.append("╗", style=f"bold {AMBER_WARNING}")
    console.print(Align.center(warning_box))
    
    warning_msg = Text()
    warning_msg.append("║", style=f"bold {AMBER_WARNING}")
    warning_msg.append(f"  ⚠ {message}  ", style=f"bold {AMBER_GLOW}")
    warning_msg.append("║", style=f"bold {AMBER_WARNING}")
    console.print(Align.center(warning_msg))
    
    warning_bottom = Text()
    warning_bottom.append("╚", style=f"bold {AMBER_WARNING}")
    warning_bottom.append("═" * (len(message) + 10), style=f"bold {AMBER_WARNING}")
    warning_bottom.append("╝", style=f"bold {AMBER_WARNING}")
    console.print(Align.center(warning_bottom))
    
    console.print()


def render_exposed_status(console: Console) -> None:
    """Render EXPOSED status with dramatic styling."""
    console.print()
    
    status_box = Text()
    status_box.append("╔══════════════════════════════════════╗", style=f"bold {RED_ERROR}")
    console.print(Align.center(status_box))
    
    status_line = Text()
    status_line.append("║", style=f"bold {RED_ERROR}")
    status_line.append("         STATUS: ", style=f"bold {WHITE}")
    status_line.append("EXPOSED", style=f"bold {RED_GLOW}")
    status_line.append("           ║", style=f"bold {RED_ERROR}")
    console.print(Align.center(status_line))
    
    status_bottom = Text()
    status_bottom.append("╚══════════════════════════════════════╝", style=f"bold {RED_ERROR}")
    console.print(Align.center(status_bottom))
    
    console.print()


def render_clear_status(console: Console) -> None:
    """Render CLEAR status with positive styling."""
    console.print()
    
    status_box = Text()
    status_box.append("╔══════════════════════════════════════╗", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_box))
    
    status_line = Text()
    status_line.append("║", style=f"bold {GREEN_SUCCESS}")
    status_line.append("          STATUS: ", style=f"bold {WHITE}")
    status_line.append("CLEAR", style=f"bold {GREEN_GLOW}")
    status_line.append("           ║", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_line))
    
    status_bottom = Text()
    status_bottom.append("╚══════════════════════════════════════╝", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_bottom))
    
    console.print()


def render_not_found_status(console: Console) -> None:
    """Render NOT FOUND status with positive styling."""
    console.print()
    
    status_box = Text()
    status_box.append("╔══════════════════════════════════════╗", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_box))
    
    status_line = Text()
    status_line.append("║", style=f"bold {GREEN_SUCCESS}")
    status_line.append("        STATUS: ", style=f"bold {WHITE}")
    status_line.append("NOT FOUND", style=f"bold {GREEN_GLOW}")
    status_line.append("         ║", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_line))
    
    status_bottom = Text()
    status_bottom.append("╚══════════════════════════════════════╝", style=f"bold {GREEN_SUCCESS}")
    console.print(Align.center(status_bottom))
    
    console.print()
