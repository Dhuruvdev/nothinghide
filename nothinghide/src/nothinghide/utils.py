"""Utility functions for validation, formatting, and helpers.

This module provides shared utilities used across the NothingHide CLI tool.
"""

import hashlib
import logging
import sys
from typing import Optional

from email_validator import validate_email, EmailNotValidError
from rich.console import Console
from rich.table import Table

from .config import (
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
)

console = Console()
error_console = Console(stderr=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.NullHandler()],
)
logger = logging.getLogger(__name__)


def validate_email_address(email: str) -> tuple[bool, str]:
    """Validate email address format.
    
    Args:
        email: Email address to validate.
        
    Returns:
        Tuple of (is_valid, normalized_email_or_error_message).
    """
    try:
        valid = validate_email(email, check_deliverability=False)
        return True, valid.normalized
    except EmailNotValidError as e:
        return False, str(e)


def hash_password_sha1(password: str) -> str:
    """Hash password using SHA-1 for HIBP k-anonymity check.
    
    Args:
        password: Plain text password (never stored or logged).
        
    Returns:
        Uppercase SHA-1 hash of the password.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def get_hash_prefix_suffix(sha1_hash: str) -> tuple[str, str]:
    """Split SHA-1 hash into prefix and suffix for k-anonymity.
    
    Args:
        sha1_hash: Full SHA-1 hash string.
        
    Returns:
        Tuple of (first 5 characters, remaining characters).
    """
    return sha1_hash[:5], sha1_hash[5:]


def print_error(message: str, exit_code: int = EXIT_INPUT_ERROR) -> None:
    """Print error message and exit with specified code.
    
    Args:
        message: Error message to display.
        exit_code: Exit code (1=input, 2=network, 3=internal).
    """
    error_console.print(f"[red]Error:[/red] {message}")
    sys.exit(exit_code)


def print_warning(message: str) -> None:
    """Print warning message without exiting.
    
    Args:
        message: Warning message to display.
    """
    console.print(f"[yellow]Warning:[/yellow] {message}")


def print_success(message: str) -> None:
    """Print success message.
    
    Args:
        message: Success message to display.
    """
    console.print(f"[green]{message}[/green]")


def print_info(message: str) -> None:
    """Print informational message.
    
    Args:
        message: Info message to display.
    """
    console.print(message)


def create_breach_table(breaches: list[dict]) -> Table:
    """Create a formatted table for breach results.
    
    Args:
        breaches: List of breach dictionaries with name, year, data_classes.
        
    Returns:
        Rich Table object for display.
    """
    table = Table(title="Breach Results", show_header=True, header_style="bold")
    table.add_column("Breach Name", style="cyan", no_wrap=True)
    table.add_column("Year", justify="center")
    table.add_column("Exposed Data Categories", style="dim")
    
    for breach in breaches:
        name = breach.get("name", "Unknown")
        year = str(breach.get("year", "Unknown"))
        data_classes = ", ".join(breach.get("data_classes", ["Unknown"]))
        table.add_row(name, year, data_classes)
    
    return table


def create_scan_table(email_result: dict, password_result: dict, risk_level: str) -> Table:
    """Create a formatted table for identity scan results.
    
    Args:
        email_result: Email check result dictionary.
        password_result: Password check result dictionary.
        risk_level: Computed risk level (LOW/MEDIUM/HIGH).
        
    Returns:
        Rich Table object for display.
    """
    table = Table(title="Identity Scan Results", show_header=True, header_style="bold")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")
    
    email_status = "EXPOSED" if email_result.get("breached") else "CLEAR"
    email_style = "red" if email_result.get("breached") else "green"
    email_details = f"{email_result.get('breach_count', 0)} breach(es) found" if email_result.get("breached") else "No breaches found"
    table.add_row("Email", f"[{email_style}]{email_status}[/{email_style}]", email_details)
    
    pwd_status = "EXPOSED" if password_result.get("exposed") else "CLEAR"
    pwd_style = "red" if password_result.get("exposed") else "green"
    pwd_details = f"Seen {password_result.get('count', 0)} time(s)" if password_result.get("exposed") else "Not found in breach databases"
    table.add_row("Password", f"[{pwd_style}]{pwd_status}[/{pwd_style}]", pwd_details)
    
    risk_style = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk_level, "white")
    table.add_row("Risk Level", f"[{risk_style}]{risk_level}[/{risk_style}]", "")
    
    return table


def calculate_risk_level(email_breached: bool, password_exposed: bool, breach_count: int = 0) -> str:
    """Calculate overall risk level based on check results.
    
    Args:
        email_breached: Whether email was found in breaches.
        password_exposed: Whether password was found exposed.
        breach_count: Number of breaches found.
        
    Returns:
        Risk level string: LOW, MEDIUM, or HIGH.
    """
    if password_exposed and email_breached:
        return RISK_HIGH
    elif password_exposed or breach_count >= 3:
        return RISK_HIGH
    elif email_breached:
        return RISK_MEDIUM
    else:
        return RISK_LOW


def get_recommendations(risk_level: str, email_breached: bool, password_exposed: bool) -> list[str]:
    """Get actionable security recommendations based on results.
    
    Args:
        risk_level: Computed risk level.
        email_breached: Whether email was found in breaches.
        password_exposed: Whether password was found exposed.
        
    Returns:
        List of recommendation strings.
    """
    recommendations = []
    
    if password_exposed:
        recommendations.append("Change this password immediately on all accounts where it is used.")
        recommendations.append("Use a unique, strong password for each account.")
    
    if email_breached:
        recommendations.append("Review account security for services associated with this email.")
        recommendations.append("Enable two-factor authentication where available.")
    
    if risk_level in [RISK_MEDIUM, RISK_HIGH]:
        recommendations.append("Consider using a password manager to generate and store unique passwords.")
        recommendations.append("Monitor your accounts for unauthorized activity.")
    
    if not recommendations:
        recommendations.append("No immediate action required. Continue practicing good security hygiene.")
    
    return recommendations
