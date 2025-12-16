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
from rich import box
from rich.text import Text
from rich.panel import Panel
from rich.align import Align

from .config import (
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
)

CYAN_PRIMARY = "#00D4FF"
CYAN_GLOW = "#00F5FF"
GREEN_SUCCESS = "#22C55E"
GREEN_GLOW = "#4ADE80"
AMBER_WARNING = "#FBBF24"
RED_ERROR = "#EF4444"
GRAY_DIM = "#6B7280"
GRAY_LIGHT = "#9CA3AF"
WHITE = "#F9FAFB"

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
    error_text = Text()
    error_text.append("  ✗ ", style=f"bold {RED_ERROR}")
    error_text.append("Error: ", style=f"bold {RED_ERROR}")
    error_text.append(message, style=WHITE)
    error_console.print(error_text)
    sys.exit(exit_code)


def print_warning(message: str) -> None:
    """Print warning message without exiting.
    
    Args:
        message: Warning message to display.
    """
    warn_text = Text()
    warn_text.append("  ⚠ ", style=f"bold {AMBER_WARNING}")
    warn_text.append("Warning: ", style=f"bold {AMBER_WARNING}")
    warn_text.append(message, style=WHITE)
    console.print(warn_text)


def print_success(message: str) -> None:
    """Print success message.
    
    Args:
        message: Success message to display.
    """
    success_text = Text()
    success_text.append("  ✓ ", style=f"bold {GREEN_SUCCESS}")
    success_text.append(message, style=WHITE)
    console.print(success_text)


def print_info(message: str) -> None:
    """Print informational message.
    
    Args:
        message: Info message to display.
    """
    info_text = Text()
    info_text.append("  ◆ ", style=f"bold {CYAN_PRIMARY}")
    info_text.append(message, style=WHITE)
    console.print(info_text)


def create_breach_table(breaches: list[dict]) -> Table:
    """Create a beautifully formatted table for breach results.
    
    Args:
        breaches: List of breach dictionaries with name, year, data_classes.
        
    Returns:
        Rich Table object for display.
    """
    table = Table(
        title="[bold]Breach Details[/bold]",
        title_style=f"bold {CYAN_GLOW}",
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN_PRIMARY,
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
        expand=False,
    )
    
    table.add_column("Breach Name", style=f"bold {CYAN_GLOW}", no_wrap=True, justify="left")
    table.add_column("Year", style=f"bold {AMBER_WARNING}", justify="center", width=8)
    table.add_column("Exposed Data Categories", style=GRAY_LIGHT, justify="left")
    
    for breach in breaches:
        name = breach.get("name", "Unknown")
        year = str(breach.get("year", "N/A"))
        data_classes = breach.get("data_classes", ["Unknown"])
        if isinstance(data_classes, list):
            data_str = ", ".join(data_classes)
        else:
            data_str = str(data_classes)
        table.add_row(name, year, data_str)
    
    return table


def create_scan_table(email_result: dict, password_result: dict, risk_level: str) -> Table:
    """Create a beautifully formatted table for identity scan results.
    
    Args:
        email_result: Email check result dictionary.
        password_result: Password check result dictionary.
        risk_level: Computed risk level (LOW/MEDIUM/HIGH/CRITICAL).
        
    Returns:
        Rich Table object for display.
    """
    table = Table(
        title="[bold]Identity Scan Report[/bold]",
        title_style=f"bold {CYAN_GLOW}",
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN_PRIMARY,
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
        expand=False,
    )
    
    table.add_column("Check Type", style=f"bold {WHITE}", no_wrap=True, justify="left", width=15)
    table.add_column("Status", justify="center", width=12)
    table.add_column("Details", style=GRAY_LIGHT, justify="left", width=35)
    
    email_breached = email_result.get("breached", False)
    email_status = Text("EXPOSED", style=f"bold {RED_ERROR}") if email_breached else Text("CLEAR", style=f"bold {GREEN_SUCCESS}")
    email_details = f"Found in {email_result.get('breach_count', 0)} breach(es)" if email_breached else "No breaches detected"
    table.add_row(
        Text("📧 Email", style=f"bold {CYAN_GLOW}"),
        email_status,
        email_details
    )
    
    pwd_exposed = password_result.get("exposed", False)
    pwd_status = Text("EXPOSED", style=f"bold {RED_ERROR}") if pwd_exposed else Text("CLEAR", style=f"bold {GREEN_SUCCESS}")
    pwd_count = password_result.get('count', 0)
    pwd_details = f"Seen {pwd_count:,} time(s) in breaches" if pwd_exposed else "Not found in breach databases"
    table.add_row(
        Text("🔑 Password", style=f"bold {CYAN_GLOW}"),
        pwd_status,
        pwd_details
    )
    
    table.add_row("", "", "")
    
    risk_styles = {
        RISK_LOW: (GREEN_SUCCESS, "✓"),
        RISK_MEDIUM: (AMBER_WARNING, "⚠"),
        RISK_HIGH: (RED_ERROR, "⚠"),
        RISK_CRITICAL: (RED_ERROR, "✗"),
    }
    risk_color, risk_icon = risk_styles.get(risk_level, (GRAY_DIM, "●"))
    risk_text = Text(f"{risk_icon} {risk_level}", style=f"bold {risk_color}")
    
    table.add_row(
        Text("🎯 Risk Level", style=f"bold {WHITE}"),
        risk_text,
        get_risk_description(risk_level)
    )
    
    return table


def get_risk_description(risk_level: str) -> str:
    """Get a description for the risk level."""
    descriptions = {
        RISK_LOW: "No significant exposure detected",
        RISK_MEDIUM: "Some exposure detected, action recommended",
        RISK_HIGH: "Significant exposure, immediate action required",
        RISK_CRITICAL: "Critical exposure, urgent action required",
    }
    return descriptions.get(risk_level, "Unknown risk level")


def calculate_risk_level(email_breached: bool, password_exposed: bool, breach_count: int = 0) -> str:
    """Calculate overall risk level based on check results.
    
    Args:
        email_breached: Whether email was found in breaches.
        password_exposed: Whether password was found exposed.
        breach_count: Number of breaches found.
        
    Returns:
        Risk level string: LOW, MEDIUM, HIGH, or CRITICAL.
    """
    if password_exposed and email_breached:
        return RISK_CRITICAL
    elif password_exposed:
        return RISK_HIGH
    elif email_breached and breach_count >= 5:
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
        recommendations.append("Change this password immediately on all accounts")
        recommendations.append("Use a unique, strong password for each service")
        recommendations.append("Consider using a password manager")
    
    if email_breached:
        recommendations.append("Review account security for affected services")
        recommendations.append("Enable two-factor authentication (2FA) everywhere")
        recommendations.append("Be vigilant for phishing attempts")
    
    if risk_level in [RISK_HIGH, RISK_CRITICAL]:
        recommendations.append("Monitor your accounts for unauthorized activity")
        recommendations.append("Consider a security freeze on credit bureaus")
    
    if not recommendations:
        recommendations.append("No immediate action required")
        recommendations.append("Continue practicing good security hygiene")
        recommendations.append("Regularly check for new exposures")
    
    return recommendations


def render_recommendations(console: Console, recommendations: list[str]) -> None:
    """Render recommendations with beautiful styling."""
    console.print()
    
    header = Text()
    header.append("┌─", style=CYAN_PRIMARY)
    header.append(" RECOMMENDATIONS ", style=f"bold {WHITE}")
    header.append("─" * 40, style=CYAN_PRIMARY)
    header.append("┐", style=CYAN_PRIMARY)
    console.print(Align.center(header))
    
    for i, rec in enumerate(recommendations, 1):
        line = Text()
        line.append("│  ", style=CYAN_PRIMARY)
        line.append(f"{i}.", style=f"bold {CYAN_GLOW}")
        line.append(f"  {rec:<52}", style=WHITE)
        line.append("│", style=CYAN_PRIMARY)
        console.print(Align.center(line))
    
    bottom = Text()
    bottom.append("└", style=CYAN_PRIMARY)
    bottom.append("─" * 58, style=CYAN_PRIMARY)
    bottom.append("┘", style=CYAN_PRIMARY)
    console.print(Align.center(bottom))
    
    console.print()
