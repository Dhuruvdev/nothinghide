"""NothingHide CLI - Command Line Interface.

A professional security tool for checking public exposure of email addresses
and passwords using lawful, publicly available sources only.
"""

import sys
import getpass
from typing import Optional

import typer
from rich.console import Console
from rich.text import Text
from rich.align import Align

from . import __version__
from .core import (
    check_email,
    check_password,
    BreachScanner,
    BreachResult,
    PasswordResult,
)
from .config import (
    EXIT_SUCCESS,
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
)
from .exceptions import (
    NothingHideError,
    ValidationError,
    NetworkError,
)
from .branding import (
    render_banner,
    render_welcome,
    render_command_header,
    render_status,
    render_section_header,
    render_footer,
    render_privacy_notice,
    render_menu,
    render_input_prompt,
    render_keyboard_shortcuts,
    render_exposed_status,
    render_clear_status,
    render_not_found_status,
    render_success_banner,
    render_error_banner,
    render_warning_banner,
    CYAN_PRIMARY,
    CYAN_GLOW,
    GREEN_SUCCESS,
    GREEN_GLOW,
    AMBER_WARNING,
    RED_ERROR,
    RED_GLOW,
    GRAY_DIM,
    GRAY_LIGHT,
    WHITE,
)
from .utils import (
    console,
    error_console,
    create_breach_table,
    create_scan_table,
    calculate_risk_level,
    get_recommendations,
    render_recommendations,
)

app = typer.Typer(
    name="nothinghide",
    help="Check public exposure risk of your email and password using lawful sources.",
    add_completion=False,
)


def version_callback(value: bool):
    """Display version information with branding."""
    if value:
        render_welcome(console, show_tagline=True)
        raise typer.Exit()


def do_email_check() -> None:
    """Perform email breach check interactively."""
    render_command_header(console, "Email Breach Check", "Public breach database scan")
    
    input_box = Text()
    input_box.append("┌─", style=CYAN_PRIMARY)
    input_box.append(" Enter Email Address ", style=f"bold {WHITE}")
    input_box.append("─" * 35, style=CYAN_PRIMARY)
    input_box.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(input_box))
    
    prompt_text = Text()
    prompt_text.append("  ╰──▶ ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Operation cancelled")
        return
    
    if not email_address:
        render_error_banner(console, "No email address provided")
        return
    
    try:
        render_status(console, f"Target: {email_address}", "info")
        console.print()
        
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Querying breach databases...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            result = check_email(email_address)
        
        if result.breached:
            render_exposed_status(console)
            
            count_text = Text()
            count_text.append(f"Found in {result.breach_count} public breach(es)", style=f"bold {AMBER_WARNING}")
            console.print(Align.center(count_text))
            console.print()
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(Align.center(table))
            
            console.print()
            render_status(console, "Review account security for affected services", "warning")
            render_status(console, "Enable two-factor authentication where available", "warning")
            render_status(console, "Consider changing passwords for exposed accounts", "warning")
        else:
            render_clear_status(console)
            render_status(console, "No public breach found for this email", "success")
            render_status(console, "Continue practicing good security hygiene", "info")
        
        render_footer(console, result.source)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def do_password_check() -> None:
    """Perform password exposure check interactively."""
    render_command_header(console, "Password Security Check", "Secure k-anonymity scan")
    
    render_privacy_notice(console)
    console.print()
    
    render_status(console, "Using k-anonymity protocol - password never transmitted", "success")
    render_status(console, "Your password is hashed locally before checking", "info")
    console.print()
    
    input_box = Text()
    input_box.append("┌─", style=CYAN_PRIMARY)
    input_box.append(" Enter Password (Hidden) ", style=f"bold {WHITE}")
    input_box.append("─" * 31, style=CYAN_PRIMARY)
    input_box.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(input_box))
    
    try:
        password = getpass.getpass(prompt="  ╰──▶ ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Check cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Checking password securely...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            result = check_password(password)
        
        password = None
        
        if result.exposed:
            render_exposed_status(console)
            
            count_text = Text()
            count_text.append(f"Seen {result.count:,} time(s) in breach databases", style=f"bold {RED_ERROR}")
            console.print(Align.center(count_text))
            console.print()
            
            render_status(console, "Do not use this password for any account", "error")
            render_status(console, "Change this password immediately if in use", "error")
            render_status(console, "Use a unique, strong password for each service", "warning")
        else:
            render_not_found_status(console)
            render_status(console, "Password not found in known breach databases", "success")
            render_status(console, "This doesn't guarantee complete security", "info")
        
        if result.strength:
            console.print()
            strength_styles = {
                "WEAK": (RED_ERROR, "error"),
                "FAIR": (AMBER_WARNING, "warning"),
                "GOOD": (CYAN_PRIMARY, "info"),
                "STRONG": (GREEN_SUCCESS, "success"),
                "COMPROMISED": (RED_ERROR, "error"),
            }
            color, status_type = strength_styles.get(result.strength, (GRAY_DIM, "info"))
            render_status(console, f"Password Strength: {result.strength}", status_type)
        
        render_footer(console, result.source)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def do_full_scan() -> None:
    """Perform complete identity scan."""
    render_command_header(console, "Full Identity Scan", "Complete exposure analysis")
    
    input_box = Text()
    input_box.append("┌─", style=CYAN_PRIMARY)
    input_box.append(" Enter Email Address ", style=f"bold {WHITE}")
    input_box.append("─" * 35, style=CYAN_PRIMARY)
    input_box.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(input_box))
    
    prompt_text = Text()
    prompt_text.append("  ╰──▶ ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Scan cancelled")
        return
    
    if not email_address:
        render_error_banner(console, "No email address provided")
        return
    
    console.print()
    render_privacy_notice(console)
    console.print()
    
    input_box2 = Text()
    input_box2.append("┌─", style=CYAN_PRIMARY)
    input_box2.append(" Enter Password (Hidden) ", style=f"bold {WHITE}")
    input_box2.append("─" * 31, style=CYAN_PRIMARY)
    input_box2.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(input_box2))
    
    try:
        password = getpass.getpass(prompt="  ╰──▶ ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Scan cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        scanner = BreachScanner()
        
        console.print()
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Running complete identity scan...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            report = scanner.full_scan(email_address, password)
        
        password = None
        
        render_section_header(console, "SCAN RESULTS", "◈")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(Align.center(table))
        
        render_recommendations(console, report.recommendations)
        
        if report.email_result.breaches:
            render_section_header(console, "BREACH DETAILS", "⚠")
            breach_table = create_breach_table(report.email_result.breaches)
            console.print(Align.center(breach_table))
        
        render_footer(console, "HackCheck/XposedOrNot (email), Have I Been Pwned (password)")
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def show_help() -> None:
    """Display detailed help information."""
    render_banner(console)
    
    help_header = Text()
    help_header.append("┌─", style=CYAN_PRIMARY)
    help_header.append(" HELP & DOCUMENTATION ", style=f"bold {WHITE}")
    help_header.append("─" * 40, style=CYAN_PRIMARY)
    help_header.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(help_header))
    
    console.print()
    
    help_sections = [
        ("📧 EMAIL BREACH CHECK", 
         "Queries public breach databases to check if your email appears in known data breaches. This helps you understand if your credentials may have been compromised."),
        ("🔑 PASSWORD SECURITY CHECK", 
         "Uses k-anonymity protocol to securely check if your password has been exposed. Your password is NEVER transmitted - only a partial hash is sent for lookup."),
        ("🎯 FULL IDENTITY SCAN", 
         "Performs both email and password checks together, providing a complete risk assessment with actionable security recommendations."),
    ]
    
    for title, desc in help_sections:
        section = Text()
        section.append("│  ", style=CYAN_PRIMARY)
        section.append(title, style=f"bold {CYAN_GLOW}")
        section.append("  │", style=CYAN_PRIMARY)
        console.print(Align.center(section))
        
        desc_lines = [desc[i:i+55] for i in range(0, len(desc), 55)]
        for line in desc_lines:
            desc_text = Text()
            desc_text.append("│  ", style=CYAN_PRIMARY)
            desc_text.append(f"{line:<58}", style=GRAY_LIGHT)
            desc_text.append("│", style=CYAN_PRIMARY)
            console.print(Align.center(desc_text))
        console.print(Align.center(Text("│" + " " * 62 + "│", style=CYAN_PRIMARY)))
    
    help_bottom = Text()
    help_bottom.append("└", style=CYAN_PRIMARY)
    help_bottom.append("─" * 62, style=CYAN_PRIMARY)
    help_bottom.append("┘", style=CYAN_PRIMARY)
    console.print(Align.center(help_bottom))
    
    console.print()
    
    sources_header = Text()
    sources_header.append("┌─", style=CYAN_PRIMARY)
    sources_header.append(" DATA SOURCES ", style=f"bold {WHITE}")
    sources_header.append("─" * 46, style=CYAN_PRIMARY)
    sources_header.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(sources_header))
    
    sources = [
        ("Email Breaches:", "HackCheck, XposedOrNot"),
        ("Password Check:", "Have I Been Pwned (k-anonymity)"),
    ]
    
    for label, value in sources:
        source_line = Text()
        source_line.append("│  ", style=CYAN_PRIMARY)
        source_line.append(f"{label:<18}", style=f"bold {WHITE}")
        source_line.append(f"{value:<40}", style=GRAY_LIGHT)
        source_line.append("│", style=CYAN_PRIMARY)
        console.print(Align.center(source_line))
    
    sources_bottom = Text()
    sources_bottom.append("└", style=CYAN_PRIMARY)
    sources_bottom.append("─" * 62, style=CYAN_PRIMARY)
    sources_bottom.append("┘", style=CYAN_PRIMARY)
    console.print(Align.center(sources_bottom))
    
    console.print()
    render_keyboard_shortcuts(console)


def interactive_menu() -> None:
    """Run the interactive menu interface."""
    while True:
        try:
            render_welcome(console, show_tagline=True)
            
            render_status(console, "Ready for security checks", "success")
            render_status(console, "All checks use lawful public sources only", "info")
            
            render_menu(console)
            render_keyboard_shortcuts(console)
            console.print()
            
            choice = render_input_prompt(console)
            
            if choice == "1":
                do_email_check()
                console.print()
                continue_prompt = Text()
                continue_prompt.append("  ╭─", style=GRAY_DIM)
                continue_prompt.append(" Press Enter to continue ", style=GRAY_LIGHT)
                continue_prompt.append("─╮", style=GRAY_DIM)
                console.print(Align.center(continue_prompt))
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "2":
                do_password_check()
                console.print()
                continue_prompt = Text()
                continue_prompt.append("  ╭─", style=GRAY_DIM)
                continue_prompt.append(" Press Enter to continue ", style=GRAY_LIGHT)
                continue_prompt.append("─╮", style=GRAY_DIM)
                console.print(Align.center(continue_prompt))
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "3":
                do_full_scan()
                console.print()
                continue_prompt = Text()
                continue_prompt.append("  ╭─", style=GRAY_DIM)
                continue_prompt.append(" Press Enter to continue ", style=GRAY_LIGHT)
                continue_prompt.append("─╮", style=GRAY_DIM)
                console.print(Align.center(continue_prompt))
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "4" or choice == "?":
                show_help()
                console.print()
                continue_prompt = Text()
                continue_prompt.append("  ╭─", style=GRAY_DIM)
                continue_prompt.append(" Press Enter to continue ", style=GRAY_LIGHT)
                continue_prompt.append("─╮", style=GRAY_DIM)
                console.print(Align.center(continue_prompt))
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "5" or choice.lower() in ("exit", "quit", "q"):
                console.print()
                goodbye = Text()
                goodbye.append("╔════════════════════════════════════════════════╗", style=f"bold {CYAN_PRIMARY}")
                console.print(Align.center(goodbye))
                goodbye_msg = Text()
                goodbye_msg.append("║", style=f"bold {CYAN_PRIMARY}")
                goodbye_msg.append("       Thank you for using NothingHide       ", style=f"bold {WHITE}")
                goodbye_msg.append("║", style=f"bold {CYAN_PRIMARY}")
                console.print(Align.center(goodbye_msg))
                goodbye_sub = Text()
                goodbye_sub.append("║", style=f"bold {CYAN_PRIMARY}")
                goodbye_sub.append("              Stay secure!                    ", style=GRAY_LIGHT)
                goodbye_sub.append("║", style=f"bold {CYAN_PRIMARY}")
                console.print(Align.center(goodbye_sub))
                goodbye_bottom = Text()
                goodbye_bottom.append("╚════════════════════════════════════════════════╝", style=f"bold {CYAN_PRIMARY}")
                console.print(Align.center(goodbye_bottom))
                console.print()
                break
            else:
                render_warning_banner(console, "Invalid option. Please choose 1-5")
                console.print()
                continue_prompt = Text()
                continue_prompt.append("  ╭─", style=GRAY_DIM)
                continue_prompt.append(" Press Enter to continue ", style=GRAY_LIGHT)
                continue_prompt.append("─╮", style=GRAY_DIM)
                console.print(Align.center(continue_prompt))
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
                    
        except KeyboardInterrupt:
            console.print()
            goodbye = Text()
            goodbye.append("╔════════════════════════════════════════════════╗", style=f"bold {CYAN_PRIMARY}")
            console.print(Align.center(goodbye))
            goodbye_msg = Text()
            goodbye_msg.append("║", style=f"bold {CYAN_PRIMARY}")
            goodbye_msg.append("       Thank you for using NothingHide       ", style=f"bold {WHITE}")
            goodbye_msg.append("║", style=f"bold {CYAN_PRIMARY}")
            console.print(Align.center(goodbye_msg))
            goodbye_sub = Text()
            goodbye_sub.append("║", style=f"bold {CYAN_PRIMARY}")
            goodbye_sub.append("              Stay secure!                    ", style=GRAY_LIGHT)
            goodbye_sub.append("║", style=f"bold {CYAN_PRIMARY}")
            console.print(Align.center(goodbye_sub))
            goodbye_bottom = Text()
            goodbye_bottom.append("╚════════════════════════════════════════════════╝", style=f"bold {CYAN_PRIMARY}")
            console.print(Align.center(goodbye_bottom))
            console.print()
            break


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """NothingHide - Security exposure check tool.
    
    Check if your email or password has been exposed in public data breaches.
    Uses only lawful, publicly available data sources.
    """
    if ctx.invoked_subcommand is None:
        interactive_menu()


@app.command()
def email(
    email_address: str = typer.Argument(
        ...,
        help="Email address to check for breaches.",
    ),
):
    """Check if an email address appears in known public data breaches."""
    try:
        render_command_header(console, "Email Breach Check", "Public breach database scan")
        
        render_status(console, f"Target: {email_address}", "info")
        console.print()
        
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Querying breach databases...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            result = check_email(email_address)
        
        if result.breached:
            render_exposed_status(console)
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(Align.center(table))
            
            render_status(console, "Review account security for affected services", "warning")
        else:
            render_clear_status(console)
            render_status(console, "No public breach found for this email", "success")
        
        render_footer(console, result.source)
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


@app.command()
def password():
    """Check if a password has been exposed in known data breaches."""
    try:
        render_command_header(console, "Password Security Check", "Secure k-anonymity scan")
        
        render_privacy_notice(console)
        console.print()
        
        pwd = getpass.getpass(prompt="Enter password to check (input hidden): ")
        
        if not pwd:
            render_error_banner(console, "No password provided")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Checking password securely...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            result = check_password(pwd)
        
        pwd = None
        
        if result.exposed:
            render_exposed_status(console)
            render_status(console, "Do not use this password", "error")
        else:
            render_not_found_status(console)
            render_status(console, "Password not found in breach databases", "success")
        
        render_footer(console, result.source)
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


@app.command()
def scan(
    email_address: str = typer.Argument(
        ...,
        help="Email address to include in identity scan.",
    ),
):
    """Run a complete identity scan (email + password check)."""
    try:
        render_command_header(console, "Full Identity Scan", "Complete exposure analysis")
        
        render_status(console, f"Target: {email_address}", "info")
        render_privacy_notice(console)
        console.print()
        
        pwd = getpass.getpass(prompt="Enter password to check (input hidden): ")
        
        if not pwd:
            render_error_banner(console, "No password provided")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        scanner = BreachScanner()
        
        with console.status(f"[bold {CYAN_PRIMARY}]  ⣿ Running complete scan...[/bold {CYAN_PRIMARY}]", spinner="dots12"):
            report = scanner.full_scan(email_address, pwd)
        
        pwd = None
        
        render_section_header(console, "SCAN RESULTS", "◈")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(Align.center(table))
        
        render_recommendations(console, report.recommendations)
        
        render_footer(console, "Multiple Sources")
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


def main():
    """Main entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        render_warning_banner(console, "Operation cancelled")
        sys.exit(EXIT_INPUT_ERROR)
    except typer.Exit as e:
        sys.exit(e.exit_code)
    except Exception:
        render_error_banner(error_console, "An unexpected error occurred")
        sys.exit(EXIT_INTERNAL_ERROR)


if __name__ == "__main__":
    main()
