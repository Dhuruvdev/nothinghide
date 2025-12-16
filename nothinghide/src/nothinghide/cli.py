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
    CYAN,
    GREEN,
    YELLOW,
    RED,
    GRAY,
    WHITE,
    PURPLE,
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
    
    console.print(f"  [{CYAN}]Enter email address:[/{CYAN}]")
    prompt = Text()
    prompt.append("  >> ", style=f"bold {CYAN}")
    console.print(prompt, end="")
    
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
        
        with console.status(f"[bold {CYAN}]  ▸ Querying breach databases...[/]", spinner="dots"):
            result = check_email(email_address)
        
        if result.breached:
            render_exposed_status(console)
            
            console.print(f"  [{YELLOW}]Found in {result.breach_count} breach(es)[/{YELLOW}]")
            console.print()
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(table)
            
            console.print()
            render_status(console, "Review account security for affected services", "warning")
            render_status(console, "Enable 2FA where available", "warning")
            render_status(console, "Consider changing passwords", "warning")
        else:
            render_clear_status(console)
            render_status(console, "No public breach found", "success")
        
        render_footer(console, result.source)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def do_password_check() -> None:
    """Perform password exposure check interactively."""
    render_command_header(console, "Password Check", "Secure k-anonymity scan")
    
    render_privacy_notice(console)
    
    render_status(console, "k-anonymity protocol - password never transmitted", "success")
    render_status(console, "Only partial hash sent for lookup", "info")
    console.print()
    
    console.print(f"  [{CYAN}]Enter password (hidden):[/{CYAN}]")
    
    try:
        password = getpass.getpass(prompt="  >> ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Check cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        with console.status(f"[bold {CYAN}]  ▸ Checking password...[/]", spinner="dots"):
            result = check_password(password)
        
        password = None
        
        if result.exposed:
            render_exposed_status(console)
            
            console.print(f"  [{RED}]Seen {result.count:,} time(s) in breaches[/{RED}]")
            console.print()
            
            render_status(console, "DO NOT use this password", "error")
            render_status(console, "Change immediately if in use", "error")
        else:
            render_not_found_status(console)
            render_status(console, "Password not found in breach databases", "success")
        
        if result.strength:
            strength_colors = {
                "WEAK": RED,
                "FAIR": YELLOW,
                "GOOD": CYAN,
                "STRONG": GREEN,
                "COMPROMISED": RED,
            }
            color = strength_colors.get(result.strength, GRAY)
            console.print(f"  [{GRAY}]Strength:[/{GRAY}] [{color}]{result.strength}[/{color}]")
        
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
    
    console.print(f"  [{CYAN}]Enter email address:[/{CYAN}]")
    prompt = Text()
    prompt.append("  >> ", style=f"bold {CYAN}")
    console.print(prompt, end="")
    
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
    
    console.print(f"  [{CYAN}]Enter password (hidden):[/{CYAN}]")
    
    try:
        password = getpass.getpass(prompt="  >> ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Scan cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        scanner = BreachScanner()
        
        console.print()
        with console.status(f"[bold {CYAN}]  ▸ Running identity scan...[/]", spinner="dots"):
            report = scanner.full_scan(email_address, password)
        
        password = None
        
        render_section_header(console, "SCAN RESULTS")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(table)
        
        render_recommendations(console, report.recommendations)
        
        if report.email_result.breaches:
            render_section_header(console, "BREACH DETAILS")
            breach_table = create_breach_table(report.email_result.breaches)
            console.print(breach_table)
        
        render_footer(console, "HackCheck/XposedOrNot, Have I Been Pwned")
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def show_help() -> None:
    """Display detailed help information."""
    render_banner(console)
    
    render_section_header(console, "HELP")
    
    sections = [
        ("EMAIL BREACH CHECK", "Queries public breach databases for your email"),
        ("PASSWORD CHECK", "Uses k-anonymity to check exposure (secure)"),
        ("FULL SCAN", "Both checks + risk assessment + recommendations"),
    ]
    
    for title, desc in sections:
        console.print(f"  [{CYAN}]{title}[/{CYAN}]")
        console.print(f"  [{GRAY}]{desc}[/{GRAY}]")
        console.print()
    
    render_section_header(console, "DATA SOURCES")
    
    console.print(f"  [{WHITE}]Email:[/{WHITE}] [{GRAY}]HackCheck, XposedOrNot[/{GRAY}]")
    console.print(f"  [{WHITE}]Password:[/{WHITE}] [{GRAY}]Have I Been Pwned (k-anonymity)[/{GRAY}]")
    console.print()
    
    render_keyboard_shortcuts(console)


def interactive_menu() -> None:
    """Run the interactive menu interface."""
    while True:
        try:
            render_welcome(console, show_tagline=True)
            
            render_status(console, "Ready for security checks", "success")
            render_status(console, "All checks use lawful public sources", "info")
            
            render_menu(console)
            render_keyboard_shortcuts(console)
            console.print()
            
            choice = render_input_prompt(console)
            
            if choice == "1":
                do_email_check()
                console.print(f"  [{GRAY}]Press Enter to continue...[/{GRAY}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "2":
                do_password_check()
                console.print(f"  [{GRAY}]Press Enter to continue...[/{GRAY}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "3":
                do_full_scan()
                console.print(f"  [{GRAY}]Press Enter to continue...[/{GRAY}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "4" or choice == "?":
                show_help()
                console.print(f"  [{GRAY}]Press Enter to continue...[/{GRAY}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "5" or choice.lower() in ("exit", "quit", "q"):
                console.print()
                console.print(f"  [{PURPLE}]▓▓▓[/{PURPLE}] [{WHITE}]Thanks for using NothingHide. Stay secure.[/{WHITE}] [{PURPLE}]▓▓▓[/{PURPLE}]")
                console.print()
                break
            else:
                render_warning_banner(console, "Invalid option. Choose 1-5")
                console.print(f"  [{GRAY}]Press Enter to continue...[/{GRAY}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
                    
        except KeyboardInterrupt:
            console.print()
            console.print(f"  [{PURPLE}]▓▓▓[/{PURPLE}] [{WHITE}]Thanks for using NothingHide. Stay secure.[/{WHITE}] [{PURPLE}]▓▓▓[/{PURPLE}]")
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
        
        with console.status(f"[bold {CYAN}]  ▸ Querying breach databases...[/]", spinner="dots"):
            result = check_email(email_address)
        
        if result.breached:
            render_exposed_status(console)
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(table)
            
            render_status(console, "Review account security", "warning")
        else:
            render_clear_status(console)
            render_status(console, "No breach found", "success")
        
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
        render_command_header(console, "Password Check", "Secure k-anonymity scan")
        
        render_privacy_notice(console)
        console.print()
        
        pwd = getpass.getpass(prompt="Enter password (hidden): ")
        
        if not pwd:
            render_error_banner(console, "No password provided")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        with console.status(f"[bold {CYAN}]  ▸ Checking password...[/]", spinner="dots"):
            result = check_password(pwd)
        
        pwd = None
        
        if result.exposed:
            render_exposed_status(console)
            render_status(console, "Do not use this password", "error")
        else:
            render_not_found_status(console)
            render_status(console, "Password not found in databases", "success")
        
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
        
        pwd = getpass.getpass(prompt="Enter password (hidden): ")
        
        if not pwd:
            render_error_banner(console, "No password provided")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        scanner = BreachScanner()
        
        with console.status(f"[bold {CYAN}]  ▸ Running complete scan...[/]", spinner="dots"):
            report = scanner.full_scan(email_address, pwd)
        
        pwd = None
        
        render_section_header(console, "SCAN RESULTS")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(table)
        
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
