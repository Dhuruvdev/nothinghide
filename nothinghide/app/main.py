"""NothingHide CLI - Main entry point.

A professional security tool for checking public exposure of email addresses
and passwords using lawful, publicly available sources only.

This tool:
- Uses k-anonymity for password checks (password never transmitted)
- Queries only public breach databases
- Never stores user data
- Provides honest, actionable security guidance
"""

import sys
import logging
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

from . import __version__
from .config import (
    EXIT_SUCCESS,
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
    VERSION,
)
from .email_check import check_email
from .password_check import check_password_interactive
from .scan import run_identity_scan
from .utils import (
    console,
    error_console,
    create_breach_table,
    create_scan_table,
    validate_email_address,
    logger,
)
from .branding import (
    render_banner,
    render_welcome,
    render_command_header,
    render_status,
    render_section_header,
    render_result_box,
    render_footer,
    render_privacy_notice,
    CYAN_PRIMARY,
    GREEN_SUCCESS,
    AMBER_WARNING,
    RED_ERROR,
    GRAY_DIM,
)

app = typer.Typer(
    name="nothinghide",
    help="Check public exposure risk of your email and password using lawful sources.",
    add_completion=False,
    no_args_is_help=True,
)


def handle_internal_error(e: Exception) -> None:
    """Handle unexpected internal errors without exposing stack traces.
    
    Logs the full exception with traceback for debugging, but only shows
    a user-friendly message to the console.
    
    Args:
        e: The exception that was raised.
    """
    logger.exception("Internal error occurred")
    error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected internal error occurred.")
    raise typer.Exit(code=EXIT_INTERNAL_ERROR)


def version_callback(value: bool):
    """Display version information with branding."""
    if value:
        render_welcome(console, show_tagline=True)
        raise typer.Exit()


@app.callback()
def main(
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
    pass


@app.command()
def email(
    email_address: str = typer.Argument(
        ...,
        help="Email address to check for breaches.",
    ),
):
    """Check if an email address appears in known public data breaches.
    
    This queries public breach databases and returns information about
    any breaches where this email was found. No data is stored.
    
    Example:
        nothinghide email user@example.com
    """
    try:
        render_command_header(console, "Email Breach Check", "Public breach database scan")
        
        is_valid, validation_result = validate_email_address(email_address)
        if not is_valid:
            error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] Invalid email format: {validation_result}")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        render_status(console, f"Target: {validation_result}", "info")
        console.print()
        
        with console.status(f"[{CYAN_PRIMARY}]Querying breach databases...[/{CYAN_PRIMARY}]", spinner="dots"):
            result = check_email(email_address)
        
        if result.get("error"):
            if result.get("validation_error"):
                error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {result.get('message')}")
                raise typer.Exit(code=EXIT_INPUT_ERROR)
            else:
                error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {result.get('message')}")
                raise typer.Exit(code=EXIT_NETWORK_ERROR)
        
        console.print()
        
        if result.get("breached"):
            breach_count = result.get('breach_count', 0)
            
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            count_text = Text()
            count_text.append(f"Found in {breach_count} public breach(es)", style=AMBER_WARNING)
            console.print(Align.center(count_text))
            console.print()
            
            if result.get("breaches"):
                table = create_breach_table(result["breaches"])
                console.print(table)
            
            console.print()
            render_status(console, "Review account security for affected services", "warning")
            render_status(console, "Enable two-factor authentication where available", "warning")
            render_status(console, "Consider changing passwords on breached accounts", "warning")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("CLEAR", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            
            console.print()
            render_status(console, "No public breach found for this email", "success")
            console.print()
            console.print(f"[{GRAY_DIM}]Note: This only checks known public breaches. Continue practicing good security hygiene.[/{GRAY_DIM}]")
        
        render_footer(console, result.get('source', 'Unknown'))
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print(f"\n[{AMBER_WARNING}]Operation cancelled.[/{AMBER_WARNING}]")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except Exception as e:
        handle_internal_error(e)


@app.command()
def password():
    """Check if a password has been exposed in known data breaches.
    
    This uses the Have I Been Pwned Pwned Passwords API with k-anonymity.
    Your password is NEVER transmitted - only the first 5 characters of
    its SHA-1 hash are sent, and comparison happens locally.
    
    Example:
        nothinghide password
    """
    try:
        render_command_header(console, "Password Check", "Secure k-anonymity scan")
        
        render_privacy_notice(console)
        console.print()
        
        render_status(console, "Using k-anonymity protocol", "info")
        render_status(console, "Password never transmitted or stored", "info")
        console.print()
        
        result = check_password_interactive()
        
        if result.get("error"):
            if result.get("cancelled"):
                console.print(f"\n[{AMBER_WARNING}]Check cancelled.[/{AMBER_WARNING}]")
                raise typer.Exit(code=EXIT_INPUT_ERROR)
            elif result.get("validation_error"):
                error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {result.get('message')}")
                raise typer.Exit(code=EXIT_INPUT_ERROR)
            else:
                error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] {result.get('message')}")
                raise typer.Exit(code=EXIT_NETWORK_ERROR)
        
        console.print()
        
        if result.get("exposed"):
            count = result.get("count", 0)
            
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("EXPOSED", style=f"bold {RED_ERROR}")
            console.print(Align.center(result_text))
            
            count_text = Text()
            count_text.append(f"Seen {count:,} time(s) in breach databases", style=RED_ERROR)
            console.print(Align.center(count_text))
            console.print()
            
            render_status(console, "Do not use this password for any account", "error")
            render_status(console, "Change this password immediately if in use", "warning")
            render_status(console, "Use a unique, strong password for each account", "warning")
        else:
            result_text = Text()
            result_text.append("STATUS: ", style="bold")
            result_text.append("NOT FOUND", style=f"bold {GREEN_SUCCESS}")
            console.print(Align.center(result_text))
            
            console.print()
            render_status(console, "Password not found in known breach databases", "success")
            console.print()
            console.print(f"[{GRAY_DIM}]Note: This does not guarantee the password is secure or strong.[/{GRAY_DIM}]")
        
        render_footer(console, result.get('source', 'Have I Been Pwned'))
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print(f"\n[{AMBER_WARNING}]Check cancelled.[/{AMBER_WARNING}]")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except Exception as e:
        handle_internal_error(e)


@app.command()
def scan(
    email_address: str = typer.Argument(
        ...,
        help="Email address to include in identity scan.",
    ),
):
    """Run a complete identity scan (email + password check).
    
    This performs both an email breach check and a password exposure check,
    then provides an overall risk assessment with actionable recommendations.
    
    Example:
        nothinghide scan user@example.com
    """
    try:
        render_command_header(console, "Identity Scan", "Complete exposure analysis")
        
        is_valid, validation_result = validate_email_address(email_address)
        if not is_valid:
            error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] Invalid email format: {validation_result}")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        render_status(console, f"Target: {validation_result}", "info")
        render_privacy_notice(console)
        console.print()
        
        console.print(f"[bold {CYAN_PRIMARY}]STEP 1/2[/bold {CYAN_PRIMARY}] [bold]Email Breach Check[/bold]")
        console.print()
        
        with console.status(f"[{CYAN_PRIMARY}]Querying breach databases...[/{CYAN_PRIMARY}]", spinner="dots"):
            from .email_check import check_email as do_email_check
            email_result = do_email_check(email_address)
        
        if email_result.get("error") and not email_result.get("validation_error"):
            render_status(console, "Email check unavailable - API error", "warning")
            email_result = {
                "breached": False,
                "breach_count": 0,
                "breaches": [],
            }
        elif email_result.get("breached"):
            render_status(console, f"Found {email_result.get('breach_count', 0)} breach(es)", "warning")
        else:
            render_status(console, "No breaches found", "success")
        
        console.print()
        console.print(f"[bold {CYAN_PRIMARY}]STEP 2/2[/bold {CYAN_PRIMARY}] [bold]Password Exposure Check[/bold]")
        console.print()
        
        from .password_check import check_password_interactive as do_password_check
        password_result = do_password_check()
        
        if password_result.get("error"):
            if password_result.get("cancelled"):
                console.print(f"\n[{AMBER_WARNING}]Scan cancelled.[/{AMBER_WARNING}]")
                raise typer.Exit(code=EXIT_INPUT_ERROR)
            render_status(console, "Password check unavailable", "warning")
            password_result = {
                "exposed": False,
                "count": 0,
            }
        elif password_result.get("exposed"):
            render_status(console, f"Password exposed ({password_result.get('count', 0):,} times)", "error")
        else:
            render_status(console, "Password not found in breaches", "success")
        
        from .utils import calculate_risk_level, get_recommendations
        
        email_breached = email_result.get("breached", False)
        password_exposed = password_result.get("exposed", False)
        breach_count = email_result.get("breach_count", 0)
        
        risk_level = calculate_risk_level(email_breached, password_exposed, breach_count)
        recommendations = get_recommendations(risk_level, email_breached, password_exposed)
        
        console.print()
        render_section_header(console, "SCAN RESULTS")
        
        table = create_scan_table(email_result, password_result, risk_level)
        console.print(table)
        
        console.print()
        console.print(f"[bold {CYAN_PRIMARY}]Recommendations:[/bold {CYAN_PRIMARY}]")
        console.print()
        for i, rec in enumerate(recommendations, 1):
            console.print(f"  [{CYAN_PRIMARY}]{i}.[/{CYAN_PRIMARY}] {rec}")
        
        if email_result.get("breaches"):
            console.print()
            render_section_header(console, "BREACH DETAILS")
            breach_table = create_breach_table(email_result["breaches"])
            console.print(breach_table)
        
        render_footer(console, "HackCheck/XposedOrNot (email), Have I Been Pwned (password)")
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print(f"\n[{AMBER_WARNING}]Scan cancelled.[/{AMBER_WARNING}]")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except Exception as e:
        handle_internal_error(e)


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print(f"\n[{AMBER_WARNING}]Operation cancelled.[/{AMBER_WARNING}]")
        sys.exit(EXIT_INPUT_ERROR)
    except typer.Exit as e:
        sys.exit(e.exit_code)
    except Exception as e:
        logger.exception("Internal error occurred")
        error_console.print(f"[{RED_ERROR}]Error:[/{RED_ERROR}] An unexpected internal error occurred.")
        sys.exit(EXIT_INTERNAL_ERROR)
