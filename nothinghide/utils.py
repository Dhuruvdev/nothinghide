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

from .config import (
    EXIT_INPUT_ERROR,
    EXIT_NETWORK_ERROR,
    EXIT_INTERNAL_ERROR,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL,
)

CYAN = "#00F5FF"
GREEN = "#22C55E"
YELLOW = "#FBBF24"
RED = "#FF3B3B"
GRAY = "#6B7280"
WHITE = "#FFFFFF"
PURPLE = "#A855F7"

console = Console()
error_console = Console(stderr=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.NullHandler()],
)
logger = logging.getLogger(__name__)


def validate_email_address(email: str) -> tuple[bool, str]:
    """Validate email address format."""
    try:
        valid = validate_email(email, check_deliverability=False)
        return True, valid.normalized
    except EmailNotValidError as e:
        return False, str(e)


def hash_password_sha1(password: str) -> str:
    """Hash password using SHA-1 for HIBP k-anonymity check."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def get_hash_prefix_suffix(sha1_hash: str) -> tuple[str, str]:
    """Split SHA-1 hash into prefix and suffix for k-anonymity."""
    return sha1_hash[:5], sha1_hash[5:]


def print_error(message: str, exit_code: int = EXIT_INPUT_ERROR) -> None:
    """Print error message and exit."""
    error_console.print(f"  [{RED}]✗ Error:[/{RED}] {message}")
    sys.exit(exit_code)


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"  [{YELLOW}]! Warning:[/{YELLOW}] {message}")


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"  [{GREEN}]✓[/{GREEN}] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"  [{CYAN}]▸[/{CYAN}] {message}")


def create_breach_table(breaches: list[dict]) -> Table:
    """Create a clean table for breach results."""
    table = Table(
        title=None,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=PURPLE,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
    )
    
    table.add_column("Breach", style=f"bold {CYAN}", no_wrap=True)
    table.add_column("Year", style=YELLOW, justify="center", width=6)
    table.add_column("Exposed Data", style=GRAY)
    
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
    """Create a clean table for identity scan results."""
    table = Table(
        title=None,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=PURPLE,
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
    )
    
    table.add_column("Check", style=f"bold {WHITE}", no_wrap=True, width=12)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Details", style=GRAY, width=30)
    
    email_breached = email_result.get("breached", False)
    email_status = Text("EXPOSED", style=f"bold {RED}") if email_breached else Text("CLEAR", style=f"bold {GREEN}")
    email_details = f"{email_result.get('breach_count', 0)} breach(es)" if email_breached else "No breaches"
    table.add_row("Email", email_status, email_details)
    
    pwd_exposed = password_result.get("exposed", False)
    pwd_status = Text("EXPOSED", style=f"bold {RED}") if pwd_exposed else Text("CLEAR", style=f"bold {GREEN}")
    pwd_count = password_result.get('count', 0)
    pwd_details = f"Seen {pwd_count:,}x" if pwd_exposed else "Not found"
    table.add_row("Password", pwd_status, pwd_details)
    
    risk_colors = {
        RISK_LOW: GREEN,
        RISK_MEDIUM: YELLOW,
        RISK_HIGH: RED,
        RISK_CRITICAL: RED,
    }
    risk_color = risk_colors.get(risk_level, GRAY)
    risk_text = Text(risk_level, style=f"bold {risk_color}")
    table.add_row("Risk", risk_text, "")
    
    return table


def calculate_risk_level(email_breached: bool, password_exposed: bool, breach_count: int = 0) -> str:
    """Calculate overall risk level based on check results."""
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
    """Get actionable security recommendations."""
    recommendations = []
    
    if password_exposed:
        recommendations.append("Change this password immediately")
        recommendations.append("Use unique passwords for each service")
        recommendations.append("Consider a password manager")
    
    if email_breached:
        recommendations.append("Review security for affected services")
        recommendations.append("Enable 2FA everywhere")
        recommendations.append("Watch for phishing attempts")
    
    if risk_level in [RISK_HIGH, RISK_CRITICAL]:
        recommendations.append("Monitor accounts for unauthorized activity")
    
    if not recommendations:
        recommendations.append("No immediate action required")
        recommendations.append("Continue good security practices")
    
    return recommendations


def render_recommendations(console: Console, recommendations: list[str]) -> None:
    """Render recommendations list."""
    console.print()
    console.print(f"  [{PURPLE}]▓[/{PURPLE}] [{WHITE}]RECOMMENDATIONS[/{WHITE}] [{PURPLE}]▓[/{PURPLE}]")
    console.print(f"  [{PURPLE}]{'─' * 20}[/{PURPLE}]")
    console.print()
    
    for i, rec in enumerate(recommendations, 1):
        console.print(f"  [{CYAN}]{i}.[/{CYAN}] [{WHITE}]{rec}[/{WHITE}]")
    
    console.print()
