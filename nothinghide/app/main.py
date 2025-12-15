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
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import (
    EXIT_SUCCESS,
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
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
)

app = typer.Typer(
    name="nothinghide",
    help="Check public exposure risk of your email and password using lawful sources.",
    add_completion=False,
    no_args_is_help=True,
)


def version_callback(value: bool):
    """Display version information."""
    if value:
        console.print(f"nothinghide version {__version__}")
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
    is_valid, validation_result = validate_email_address(email_address)
    if not is_valid:
        error_console.print(f"[red]Error:[/red] Invalid email format: {validation_result}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    
    console.print(f"\nChecking breaches for: [cyan]{validation_result}[/cyan]\n")
    
    with console.status("Querying breach databases..."):
        result = check_email(email_address)
    
    if result.get("error"):
        if result.get("validation_error"):
            error_console.print(f"[red]Error:[/red] {result.get('message')}")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        else:
            error_console.print(f"[red]Error:[/red] {result.get('message')}")
            raise typer.Exit(code=EXIT_NETWORK_ERROR)
    
    if result.get("breached"):
        console.print(f"[yellow]This email was found in {result.get('breach_count', 0)} public breach(es).[/yellow]\n")
        
        if result.get("breaches"):
            table = create_breach_table(result["breaches"])
            console.print(table)
        
        console.print("\n[dim]Recommendation: Review account security and enable 2FA where available.[/dim]")
    else:
        console.print("[green]No public breach found for this email.[/green]")
        console.print("\n[dim]Note: This only checks known public breaches. Continue practicing good security hygiene.[/dim]")
    
    console.print(f"\n[dim]Data source: {result.get('source', 'Unknown')}[/dim]")
    raise typer.Exit(code=EXIT_SUCCESS)


@app.command()
def password():
    """Check if a password has been exposed in known data breaches.
    
    This uses the Have I Been Pwned Pwned Passwords API with k-anonymity.
    Your password is NEVER transmitted - only the first 5 characters of
    its SHA-1 hash are sent, and comparison happens locally.
    
    Example:
        nothinghide password
    """
    console.print("\n[bold]Password Exposure Check[/bold]")
    console.print("[dim]Your password will be checked securely using k-anonymity.[/dim]")
    console.print("[dim]The password is never transmitted or stored.[/dim]\n")
    
    result = check_password_interactive()
    
    if result.get("error"):
        if result.get("cancelled"):
            console.print("\n[yellow]Check cancelled.[/yellow]")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        elif result.get("validation_error"):
            error_console.print(f"[red]Error:[/red] {result.get('message')}")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        else:
            error_console.print(f"[red]Error:[/red] {result.get('message')}")
            raise typer.Exit(code=EXIT_NETWORK_ERROR)
    
    console.print()
    
    if result.get("exposed"):
        count = result.get("count", 0)
        console.print(f"[red]Exposed: YES[/red]")
        console.print(f"[red]Times seen: {count:,}[/red]")
        console.print("\n[yellow]This password has been found in data breaches.[/yellow]")
        console.print("[yellow]Do not use this password for any account.[/yellow]")
    else:
        console.print("[green]Exposed: NO[/green]")
        console.print("\n[green]This password was not found in known breach databases.[/green]")
        console.print("[dim]Note: This does not guarantee the password is secure.[/dim]")
    
    console.print(f"\n[dim]Data source: {result.get('source', 'Have I Been Pwned')}[/dim]")
    raise typer.Exit(code=EXIT_SUCCESS)


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
    is_valid, validation_result = validate_email_address(email_address)
    if not is_valid:
        error_console.print(f"[red]Error:[/red] Invalid email format: {validation_result}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    
    console.print("\n[bold]Identity Scan[/bold]")
    console.print(f"Email: [cyan]{validation_result}[/cyan]")
    console.print("[dim]This will check your email and password for exposure.[/dim]\n")
    
    console.print("[bold]Step 1/2:[/bold] Checking email breaches...")
    with console.status("Querying breach databases..."):
        from .email_check import check_email as do_email_check
        email_result = do_email_check(email_address)
    
    if email_result.get("error") and not email_result.get("validation_error"):
        console.print("[yellow]Warning: Email check encountered an error. Proceeding with password check.[/yellow]")
        email_result = {
            "breached": False,
            "breach_count": 0,
            "breaches": [],
        }
    elif email_result.get("breached"):
        console.print(f"[yellow]Found {email_result.get('breach_count', 0)} breach(es)[/yellow]")
    else:
        console.print("[green]No breaches found[/green]")
    
    console.print("\n[bold]Step 2/2:[/bold] Checking password exposure...")
    console.print("[dim]Your password will be checked securely using k-anonymity.[/dim]\n")
    
    from .password_check import check_password_interactive as do_password_check
    password_result = do_password_check()
    
    if password_result.get("error"):
        if password_result.get("cancelled"):
            console.print("\n[yellow]Scan cancelled.[/yellow]")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        console.print("[yellow]Warning: Password check encountered an error.[/yellow]")
        password_result = {
            "exposed": False,
            "count": 0,
        }
    elif password_result.get("exposed"):
        console.print(f"[red]Password exposed ({password_result.get('count', 0):,} times)[/red]")
    else:
        console.print("[green]Password not found in breaches[/green]")
    
    from .utils import calculate_risk_level, get_recommendations
    
    email_breached = email_result.get("breached", False)
    password_exposed = password_result.get("exposed", False)
    breach_count = email_result.get("breach_count", 0)
    
    risk_level = calculate_risk_level(email_breached, password_exposed, breach_count)
    recommendations = get_recommendations(risk_level, email_breached, password_exposed)
    
    console.print("\n")
    table = create_scan_table(email_result, password_result, risk_level)
    console.print(table)
    
    console.print("\n[bold]Recommendations:[/bold]")
    for i, rec in enumerate(recommendations, 1):
        console.print(f"  {i}. {rec}")
    
    if email_result.get("breaches"):
        console.print("\n[bold]Breach Details:[/bold]")
        breach_table = create_breach_table(email_result["breaches"])
        console.print(breach_table)
    
    console.print("\n[dim]Data sources: HackCheck/XposedOrNot (email), Have I Been Pwned (password)[/dim]")
    raise typer.Exit(code=EXIT_SUCCESS)


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled.[/yellow]")
        sys.exit(EXIT_INPUT_ERROR)
    except Exception as e:
        error_console.print(f"[red]Internal error:[/red] An unexpected error occurred.")
        sys.exit(EXIT_INTERNAL_ERROR)
