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
    CYAN_PRIMARY,
    GREEN_SUCCESS,
    AMBER_WARNING,
    RED_ERROR,
    GRAY_DIM,
)
from .utils import (
    console,
    error_console,
    create_breach_table,
    create_scan_table,
    calculate_risk_level,
    get_recommendations,
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
    
    console.print(f"[{CYAN_PRIMARY}]Enter email address to check:[/{CYAN_PRIMARY}]")
    prompt_text = Text()
    prompt_text.append("> ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n[{AMBER_WARNING}]Operation cancelled.[/{AMBER_WARNING}]")
        return
    
    if not email_address:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No email address provided.")
        return
    
    try:
        render_status(console, f"Target: {email_address}", "info")
        console.print()
        
        with console.status(f"[{CYAN_PRIMARY}]Querying breach databases...[/{CYAN_PRIMARY}]", spinner="dots"):
            result = check_email(email_address)
        
        console.print()
        
        if result.breached:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            count_text = Text()
            count_text.append(f"Found in {result.breach_count} public breach(es)", style=AMBER_WARNING)
            console.print(Align.center(count_text))
            console.print()
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(table)
            
            console.print()
            render_status(console, "Review account security for affected services", "warning")
            render_status(console, "Enable two-factor authentication where available", "warning")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("CLEAR", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            
            console.print()
            render_status(console, "No public breach found for this email", "success")
        
        render_footer(console, result.source)
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except Exception as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected error occurred.")


def do_password_check() -> None:
    """Perform password exposure check interactively."""
    render_command_header(console, "Password Check", "Secure k-anonymity scan")
    
    render_privacy_notice(console)
    console.print()
    
    render_status(console, "Using k-anonymity protocol", "info")
    render_status(console, "Password never transmitted or stored", "info")
    console.print()
    
    try:
        password = getpass.getpass(prompt="Enter password to check (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n[{AMBER_WARNING}]Check cancelled.[/{AMBER_WARNING}]")
        return
    
    if not password:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No password provided.")
        return
    
    try:
        with console.status(f"[{CYAN_PRIMARY}]Checking password...[/{CYAN_PRIMARY}]", spinner="dots"):
            result = check_password(password)
        
        password = None
        
        console.print()
        
        if result.exposed:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            count_text = Text()
            count_text.append(f"Seen {result.count:,} time(s) in breach databases", style=RED_ERROR)
            console.print(Align.center(count_text))
            console.print()
            
            render_status(console, "Do not use this password for any account", "error")
            render_status(console, "Change this password immediately if in use", "warning")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("NOT FOUND", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            
            console.print()
            render_status(console, "Password not found in known breach databases", "success")
        
        if result.strength:
            console.print()
            strength_color = {
                "WEAK": RED_ERROR,
                "FAIR": AMBER_WARNING,
                "GOOD": CYAN_PRIMARY,
                "STRONG": GREEN_SUCCESS,
                "COMPROMISED": RED_ERROR,
            }.get(result.strength, GRAY_DIM)
            render_status(console, f"Strength: {result.strength}", 
                         "success" if result.strength == "STRONG" else "warning")
        
        render_footer(console, result.source)
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except Exception as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected error occurred.")


def do_full_scan() -> None:
    """Perform complete identity scan."""
    render_command_header(console, "Identity Scan", "Complete exposure analysis")
    
    console.print(f"[{CYAN_PRIMARY}]Enter email address for scan:[/{CYAN_PRIMARY}]")
    prompt_text = Text()
    prompt_text.append("> ", style=f"bold {CYAN_PRIMARY}")
    console.print(prompt_text, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n[{AMBER_WARNING}]Scan cancelled.[/{AMBER_WARNING}]")
        return
    
    if not email_address:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No email address provided.")
        return
    
    render_privacy_notice(console)
    console.print()
    
    try:
        password = getpass.getpass(prompt="Enter password to check (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n[{AMBER_WARNING}]Scan cancelled.[/{AMBER_WARNING}]")
        return
    
    if not password:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No password provided.")
        return
    
    try:
        scanner = BreachScanner()
        
        console.print()
        with console.status(f"[{CYAN_PRIMARY}]Running complete identity scan...[/{CYAN_PRIMARY}]", spinner="dots"):
            report = scanner.full_scan(email_address, password)
        
        password = None
        
        console.print()
        render_section_header(console, "SCAN RESULTS")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(table)
        
        console.print()
        console.print(f"[bold {CYAN_PRIMARY}]Recommendations:[/bold {CYAN_PRIMARY}]")
        console.print()
        for i, rec in enumerate(report.recommendations, 1):
            console.print(f"  [{CYAN_PRIMARY}]{i}.[/{CYAN_PRIMARY}] {rec}")
        
        if report.email_result.breaches:
            console.print()
            render_section_header(console, "BREACH DETAILS")
            breach_table = create_breach_table(report.email_result.breaches)
            console.print(breach_table)
        
        render_footer(console, "HackCheck/XposedOrNot (email), Have I Been Pwned (password)")
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
    except Exception as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected error occurred.")


def show_help() -> None:
    """Display detailed help information."""
    render_banner(console)
    
    console.print(f"[bold {CYAN_PRIMARY}]NOTHINGHIDE HELP[/bold {CYAN_PRIMARY}]", justify="center")
    console.print()
    
    help_sections = [
        ("Email Check", "Queries public breach databases to see if your email appears in known data breaches."),
        ("Password Check", "Uses k-anonymity to check if your password has been exposed. Password is NEVER transmitted."),
        ("Full Scan", "Performs both checks together with a complete risk assessment and recommendations."),
    ]
    
    for title, desc in help_sections:
        console.print(f"[bold {CYAN_PRIMARY}]{title}[/bold {CYAN_PRIMARY}]")
        console.print(f"  [{GRAY_DIM}]{desc}[/{GRAY_DIM}]")
        console.print()
    
    console.print(f"[bold {CYAN_PRIMARY}]Data Sources[/bold {CYAN_PRIMARY}]")
    console.print(f"  [{GRAY_DIM}]Email: HackCheck, XposedOrNot[/{GRAY_DIM}]")
    console.print(f"  [{GRAY_DIM}]Password: Have I Been Pwned (k-anonymity)[/{GRAY_DIM}]")
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
                console.print(f"\n[{GRAY_DIM}]Press Enter to continue...[/{GRAY_DIM}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "2":
                do_password_check()
                console.print(f"\n[{GRAY_DIM}]Press Enter to continue...[/{GRAY_DIM}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "3":
                do_full_scan()
                console.print(f"\n[{GRAY_DIM}]Press Enter to continue...[/{GRAY_DIM}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "4" or choice == "?":
                show_help()
                console.print(f"\n[{GRAY_DIM}]Press Enter to continue...[/{GRAY_DIM}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            elif choice == "5" or choice.lower() in ("exit", "quit", "q"):
                console.print(f"\n[{CYAN_PRIMARY}]Goodbye! Stay secure.[/{CYAN_PRIMARY}]")
                break
            else:
                console.print(f"\n[{AMBER_WARNING}]Invalid option. Please choose 1-5.[/{AMBER_WARNING}]")
                console.print(f"[{GRAY_DIM}]Press Enter to continue...[/{GRAY_DIM}]")
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
                    
        except KeyboardInterrupt:
            console.print(f"\n\n[{CYAN_PRIMARY}]Goodbye! Stay secure.[/{CYAN_PRIMARY}]")
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
        
        with console.status(f"[{CYAN_PRIMARY}]Querying breach databases...[/{CYAN_PRIMARY}]", spinner="dots"):
            result = check_email(email_address)
        
        console.print()
        
        if result.breached:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            if result.breaches:
                table = create_breach_table(result.breaches)
                console.print(table)
            
            render_status(console, "Review account security for affected services", "warning")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("CLEAR", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            render_status(console, "No public breach found for this email", "success")
        
        render_footer(console, result.source)
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


@app.command()
def password():
    """Check if a password has been exposed in known data breaches."""
    try:
        render_command_header(console, "Password Check", "Secure k-anonymity scan")
        
        render_privacy_notice(console)
        console.print()
        
        pwd = getpass.getpass(prompt="Enter password to check (input hidden): ")
        
        if not pwd:
            error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No password provided.")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        with console.status(f"[{CYAN_PRIMARY}]Checking password...[/{CYAN_PRIMARY}]", spinner="dots"):
            result = check_password(pwd)
        
        pwd = None
        
        console.print()
        
        if result.exposed:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            render_status(console, "Do not use this password", "error")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("NOT FOUND", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            
            render_status(console, "Password not found in breach databases", "success")
        
        render_footer(console, result.source)
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
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
        render_command_header(console, "Identity Scan", "Complete exposure analysis")
        
        render_status(console, f"Target: {email_address}", "info")
        render_privacy_notice(console)
        console.print()
        
        pwd = getpass.getpass(prompt="Enter password to check (input hidden): ")
        
        if not pwd:
            error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] No password provided.")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        scanner = BreachScanner()
        
        with console.status(f"[{CYAN_PRIMARY}]Running complete scan...[/{CYAN_PRIMARY}]", spinner="dots"):
            report = scanner.full_scan(email_address, pwd)
        
        pwd = None
        
        console.print()
        render_section_header(console, "SCAN RESULTS")
        
        table = create_scan_table(
            report.email_result.to_dict(),
            report.password_result.to_dict(),
            report.risk_level,
        )
        console.print(table)
        
        console.print()
        for i, rec in enumerate(report.recommendations, 1):
            console.print(f"  [{CYAN_PRIMARY}]{i}.[/{CYAN_PRIMARY}] {rec}")
        
        render_footer(console, "Multiple Sources")
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


def main():
    """Main entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print(f"\n[{AMBER_WARNING}]Operation cancelled.[/{AMBER_WARNING}]")
        sys.exit(EXIT_INPUT_ERROR)
    except typer.Exit as e:
        sys.exit(e.exit_code)
    except Exception:
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected error occurred.")
        sys.exit(EXIT_INTERNAL_ERROR)


if __name__ == "__main__":
    main()
