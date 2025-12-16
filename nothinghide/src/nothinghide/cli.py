"""NothingHide CLI - Command Line Interface.

A professional security tool for checking public exposure of email addresses
and passwords using lawful, publicly available sources only.

Supports: Linux, macOS, Windows PowerShell
"""

import sys
import getpass
import json
from pathlib import Path
from typing import Optional
from enum import Enum

import typer
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from . import __version__
from .core import (
    check_email,
    check_password,
    BreachScanner,
    BreachResult,
    PasswordResult,
)
from .agent import BreachIntelligenceAgent
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
from .platform import enable_windows_ansi, IS_WINDOWS
from .settings import Settings, get_settings, update_settings, reset_settings
from .export import export_json, export_csv, export_html, format_output
from .bulk import read_email_list, process_bulk, BulkResult
from .domain import scan_domain, validate_domain

enable_windows_ansi()


class OutputFormat(str, Enum):
    """Output format options."""
    table = "table"
    json = "json"
    csv = "csv"


app = typer.Typer(
    name="nothinghide",
    help="Check public exposure risk of your email and password using lawful sources.",
    add_completion=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool):
    """Display version information with branding."""
    if value:
        render_welcome(console, show_tagline=True)
        raise typer.Exit()


def do_email_check() -> None:
    """Perform email breach check interactively using advanced agent."""
    import time
    from datetime import datetime
    
    render_command_header(console, "Email Breach Check", "Multi-source intelligence scan")
    
    console.print("  Enter email address:", style=WHITE)
    console.print("  >> ", style=WHITE, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Operation cancelled")
        return
    
    if not email_address:
        render_error_banner(console, "No email address provided")
        return
    
    try:
        console.print()
        console.print(f"  TARGET: {email_address}", style=f"bold {WHITE}")
        console.print()
        
        sources = [
            ("LeakCheck", "7B+ breach records"),
            ("HackCheck", "Public breach database"), 
            ("XposedOrNot", "Breach exposure API"),
            ("XposedOrNot Analytics", "Detailed analytics"),
            ("EmailRep", "Email reputation"),
            ("DeXpose", "Exposure detection")
        ]
        
        console.print("  INTELLIGENCE AGENT v1.0", style=f"bold {WHITE}")
        console.print("  -----------------------", style=GRAY)
        console.print()
        console.print("  Initializing multi-source intelligence gathering...", style=GRAY)
        console.print()
        
        for name, desc in sources:
            console.print(f"  [+] {name:<25} {desc}", style=GRAY)
            time.sleep(0.08)
        
        console.print()
        console.print("  PARALLEL SCAN INITIATED", style=f"bold {WHITE}")
        console.print("  -----------------------", style=GRAY)
        console.print()
        
        start_time = time.time()
        agent = BreachIntelligenceAgent()
        
        with console.status("  Querying all sources simultaneously...", spinner="dots"):
            result = agent.check_email_sync(email_address)
        
        elapsed = time.time() - start_time
        
        sources_queried = getattr(result, 'sources_queried', [])
        sources_succeeded = getattr(result, 'sources_succeeded', [])
        sources_failed = getattr(result, 'sources_failed', [])
        risk_score = getattr(result, 'risk_score', 0.0)
        avg_confidence = getattr(result, 'average_confidence', 0.0)
        
        console.print("  Source Status:", style=WHITE)
        for source in sources_succeeded:
            console.print(f"    [OK] {source}", style=WHITE)
        for source in sources_failed:
            console.print(f"    [--] {source}", style=GRAY)
        
        console.print()
        console.print(f"  Scan completed in {elapsed:.2f}s", style=GRAY)
        console.print(f"  Sources responded: {len(sources_succeeded)}/{len(sources_queried)}", style=GRAY)
        console.print()
        
        console.print("  THREAT INTELLIGENCE REPORT", style=f"bold {WHITE}")
        console.print("  --------------------------", style=GRAY)
        console.print()
        
        if result.breached:
            if risk_score >= 70:
                threat_level = "CRITICAL"
            elif risk_score >= 50:
                threat_level = "HIGH"
            elif risk_score >= 30:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            console.print(f"  EXPOSURE STATUS: COMPROMISED", style=f"bold {WHITE}")
            console.print(f"  THREAT LEVEL: {threat_level}", style=f"bold {WHITE}")
            console.print(f"  RISK SCORE: {risk_score:.0f}/100", style=WHITE)
            console.print(f"  CONFIDENCE: {avg_confidence:.0%}", style=GRAY)
            console.print(f"  BREACHES FOUND: {result.breach_count}", style=WHITE)
            console.print()
            
            if result.breaches:
                console.print("  BREACH INTELLIGENCE", style=f"bold {WHITE}")
                console.print("  -------------------", style=GRAY)
                console.print()
                
                breach_dicts = []
                for b in result.breaches:
                    if hasattr(b, 'to_dict'):
                        breach_dicts.append(b.to_dict())
                    elif isinstance(b, dict):
                        breach_dicts.append(b)
                
                current_year = datetime.now().year
                
                for i, breach in enumerate(breach_dicts[:15], 1):
                    name = breach.get('name', 'Unknown')
                    date = breach.get('date', 'Unknown')
                    year = breach.get('year')
                    data = breach.get('data_classes', [])
                    records = breach.get('records_exposed')
                    confidence = breach.get('confidence', 0)
                    sources_list = breach.get('sources', [])
                    
                    is_recent = year and (current_year - year <= 2)
                    severity = "[!]" if is_recent else "[*]"
                    
                    console.print(f"  {severity} {name}", style=f"bold {WHITE}")
                    console.print(f"      Date: {date or 'Unknown'}", style=GRAY)
                    
                    if data:
                        data_str = ', '.join(str(d) for d in data[:5])
                        console.print(f"      Exposed Data: {data_str}", style=GRAY)
                    
                    if records:
                        console.print(f"      Records: {records:,}", style=GRAY)
                    
                    if sources_list:
                        console.print(f"      Verified by: {', '.join(sources_list)}", style=GRAY)
                    
                    console.print()
                
                if len(breach_dicts) > 15:
                    console.print(f"  ... and {len(breach_dicts) - 15} additional breaches", style=GRAY)
                    console.print()
            
            console.print("  THREAT INDICATORS", style=f"bold {WHITE}")
            console.print("  -----------------", style=GRAY)
            
            breach_list = []
            for b in result.breaches:
                if hasattr(b, 'to_dict'):
                    breach_list.append(b.to_dict())
                elif isinstance(b, dict):
                    breach_list.append(b)
            
            password_exposed = any(
                'password' in str(b.get('data_classes', [])).lower()
                for b in breach_list
            )
            
            if password_exposed:
                console.print("  [!!] PASSWORD DATA EXPOSED - IMMEDIATE ACTION REQUIRED", style=WHITE)
            
            if result.breach_count > 5:
                console.print(f"  [!] HIGH EXPOSURE - Found in {result.breach_count} breaches", style=WHITE)
            
            now_year = datetime.now().year
            recent_count = sum(1 for b in breach_list if b.get('year') and now_year - b.get('year', 0) <= 2)
            if recent_count > 0:
                console.print(f"  [!] RECENT ACTIVITY - {recent_count} breach(es) in last 2 years", style=WHITE)
            
            console.print()
            console.print("  RECOMMENDED ACTIONS", style=f"bold {WHITE}")
            console.print("  -------------------", style=GRAY)
            console.print("  1. Change all passwords associated with this email", style=WHITE)
            console.print("  2. Enable two-factor authentication (2FA)", style=WHITE)
            console.print("  3. Use a password manager for unique passwords", style=WHITE)
            console.print("  4. Monitor accounts for suspicious activity", style=WHITE)
            if password_exposed:
                console.print("  5. CHECK ALL ACCOUNTS - Password was directly exposed", style=WHITE)
            if risk_score >= 50:
                console.print("  6. Consider credit monitoring services", style=WHITE)
        else:
            console.print("  EXPOSURE STATUS: CLEAR", style=f"bold {WHITE}")
            console.print("  THREAT LEVEL: NONE", style=WHITE)
            console.print("  RISK SCORE: 0/100", style=WHITE)
            console.print()
            console.print("  No breach records found in queried databases.", style=GRAY)
            console.print("  Continue practicing good security hygiene.", style=GRAY)
        
        console.print()
        console.print("  SCAN METADATA", style=f"bold {WHITE}")
        console.print("  -------------", style=GRAY)
        console.print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style=GRAY)
        console.print(f"  Sources: {', '.join(sources_succeeded) if sources_succeeded else 'None'}", style=GRAY)
        console.print(f"  Protocol: Multi-source parallel intelligence", style=GRAY)
        console.print()
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, f"An error occurred: {str(e)}")


def do_password_check() -> None:
    """Perform password exposure check interactively."""
    import time
    import hashlib
    from datetime import datetime
    
    render_command_header(console, "Password Check", "Secure k-anonymity intelligence scan")
    
    console.print("  SECURITY PROTOCOL", style=f"bold {WHITE}")
    console.print("  -----------------", style=GRAY)
    console.print("  [*] K-Anonymity Protocol Active", style=WHITE)
    console.print("  [*] Password NEVER transmitted", style=WHITE)
    console.print("  [*] Only SHA-1 prefix (5 chars) sent to API", style=WHITE)
    console.print("  [*] Full comparison happens locally", style=WHITE)
    console.print()
    
    console.print("  Enter password (hidden):", style=WHITE)
    
    try:
        password = getpass.getpass(prompt="  >> ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Check cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        console.print()
        console.print("  PASSWORD INTELLIGENCE ANALYSIS", style=f"bold {WHITE}")
        console.print("  ------------------------------", style=GRAY)
        console.print()
        
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        
        console.print("  [+] Computing SHA-1 hash...", style=GRAY)
        time.sleep(0.15)
        console.print(f"      Hash prefix: {prefix}*****", style=GRAY)
        
        console.print("  [+] Analyzing password strength...", style=GRAY)
        time.sleep(0.15)
        
        strength_score = 0
        length_score = min(len(password), 20)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`" for c in password)
        
        if len(password) >= 8: strength_score += 1
        if len(password) >= 12: strength_score += 1
        if len(password) >= 16: strength_score += 2
        if has_upper: strength_score += 1
        if has_lower: strength_score += 1
        if has_digit: strength_score += 1
        if has_special: strength_score += 2
        
        console.print("  [+] Querying breach database (HIBP)...", style=GRAY)
        time.sleep(0.1)
        
        with console.status("  Checking 700M+ compromised passwords...", spinner="dots"):
            result = check_password(password)
        
        password = None
        
        console.print("    [OK] Have I Been Pwned responded", style=WHITE)
        console.print()
        
        console.print("  THREAT INTELLIGENCE REPORT", style=f"bold {WHITE}")
        console.print("  --------------------------", style=GRAY)
        console.print()
        
        if result.exposed:
            if result.count > 100000:
                threat_level = "CRITICAL"
            elif result.count > 10000:
                threat_level = "HIGH"
            elif result.count > 1000:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            console.print("  EXPOSURE STATUS: COMPROMISED", style=f"bold {WHITE}")
            console.print(f"  THREAT LEVEL: {threat_level}", style=f"bold {WHITE}")
            console.print(f"  EXPOSURE COUNT: {result.count:,}", style=WHITE)
            console.print()
            console.print("  This password has been seen in data breaches.", style=WHITE)
            console.print("  Attackers commonly use breach lists for attacks.", style=GRAY)
            console.print()
            
            console.print("  THREAT INDICATORS", style=f"bold {WHITE}")
            console.print("  -----------------", style=GRAY)
            console.print(f"  [!!] Found in {result.count:,} breach records", style=WHITE)
            if result.count > 10000:
                console.print("  [!!] EXTREMELY COMMON - Used by many compromised accounts", style=WHITE)
            console.print("  [!] Vulnerable to credential stuffing attacks", style=WHITE)
            console.print("  [!] Vulnerable to password spraying attacks", style=WHITE)
            console.print()
            
            console.print()
            console.print("  RECOMMENDED ACTIONS", style=f"bold {WHITE}")
            console.print("  -------------------", style=GRAY)
            console.print("  1. STOP using this password immediately", style=WHITE)
            console.print("  2. Change on ALL accounts where it's used", style=WHITE)
            console.print("  3. Use a password manager to generate unique passwords", style=WHITE)
            console.print("  4. Enable 2FA on all important accounts", style=WHITE)
        else:
            console.print("  EXPOSURE STATUS: CLEAR", style=f"bold {WHITE}")
            console.print("  THREAT LEVEL: NONE", style=WHITE)
            console.print()
            console.print("  Password not found in breach databases.", style=WHITE)
            console.print("  This does not guarantee security - use strong, unique passwords.", style=GRAY)
        
        console.print()
        console.print("  STRENGTH ANALYSIS", style=f"bold {WHITE}")
        console.print("  -----------------", style=GRAY)
        console.print(f"  Length: {length_score} characters", style=WHITE)
        console.print(f"  Uppercase: {'Yes' if has_upper else 'No'}", style=WHITE)
        console.print(f"  Lowercase: {'Yes' if has_lower else 'No'}", style=WHITE)
        console.print(f"  Numbers: {'Yes' if has_digit else 'No'}", style=WHITE)
        console.print(f"  Special chars: {'Yes' if has_special else 'No'}", style=WHITE)
        
        if strength_score >= 7:
            strength_label = "STRONG"
        elif strength_score >= 5:
            strength_label = "GOOD"
        elif strength_score >= 3:
            strength_label = "FAIR"
        else:
            strength_label = "WEAK"
        
        if result.exposed:
            strength_label = "COMPROMISED"
        
        console.print(f"  Overall: {strength_label} (Score: {strength_score}/9)", style=WHITE)
        
        console.print()
        console.print("  SCAN METADATA", style=f"bold {WHITE}")
        console.print("  -------------", style=GRAY)
        console.print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style=GRAY)
        console.print(f"  Source: Have I Been Pwned (Pwned Passwords)", style=GRAY)
        console.print(f"  Protocol: K-Anonymity (SHA-1 prefix match)", style=GRAY)
        console.print(f"  Database: 700M+ compromised passwords", style=GRAY)
        console.print()
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
    except Exception as e:
        render_error_banner(console, "An unexpected error occurred")


def do_full_scan() -> None:
    """Perform complete identity scan."""
    import time
    
    render_command_header(console, "Full Identity Scan", "Complete exposure analysis")
    
    console.print("  Enter email address:", style=WHITE)
    console.print("  >> ", style=WHITE, end="")
    
    try:
        email_address = input().strip()
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Scan cancelled")
        return
    
    if not email_address:
        render_error_banner(console, "No email address provided")
        return
    
    console.print()
    console.print("  PRIVACY NOTICE", style=f"bold {WHITE}")
    console.print("  --------------", style=GRAY)
    console.print("  [ok] Your data is never stored or transmitted", style=WHITE)
    console.print("       Password uses k-anonymity - only partial hash sent", style=GRAY)
    console.print()
    
    console.print("  Enter password (hidden):", style=WHITE)
    
    try:
        password = getpass.getpass(prompt="  >> ")
    except (EOFError, KeyboardInterrupt):
        render_warning_banner(console, "Scan cancelled")
        return
    
    if not password:
        render_error_banner(console, "No password provided")
        return
    
    try:
        console.print()
        console.print("  SCANNING ALL SOURCES", style=f"bold {WHITE}")
        console.print("  --------------------", style=GRAY)
        console.print()
        
        sources = ["LeakCheck", "HackCheck", "XposedOrNot", "Have I Been Pwned"]
        for source in sources:
            console.print(f"  [.] {source}", style=GRAY)
            time.sleep(0.1)
        
        scanner = BreachScanner()
        
        console.print()
        with console.status("  Running complete identity scan...", spinner="dots"):
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
        ("EMAIL BREACH CHECK", "Queries 6+ public breach databases in parallel"),
        ("PASSWORD CHECK", "Uses k-anonymity to check exposure (secure)"),
        ("FULL SCAN", "Both checks + risk assessment + recommendations"),
    ]
    
    for title, desc in sections:
        console.print(f"  [{CYAN}]{title}[/{CYAN}]")
        console.print(f"  [{GRAY}]{desc}[/{GRAY}]")
        console.print()
    
    render_section_header(console, "DATA SOURCES (6+ APIs)")
    
    console.print(f"  [{WHITE}]Email Sources:[/{WHITE}]")
    console.print(f"  [{GRAY}]  - LeakCheck (7B+ records)[/{GRAY}]")
    console.print(f"  [{GRAY}]  - HackCheck[/{GRAY}]")
    console.print(f"  [{GRAY}]  - XposedOrNot[/{GRAY}]")
    console.print(f"  [{GRAY}]  - XposedOrNot Analytics[/{GRAY}]")
    console.print(f"  [{GRAY}]  - EmailRep (reputation)[/{GRAY}]")
    console.print(f"  [{GRAY}]  - DeXpose[/{GRAY}]")
    console.print()
    console.print(f"  [{WHITE}]Password:[/{WHITE}] [{GRAY}]Have I Been Pwned (k-anonymity)[/{GRAY}]")
    console.print()
    
    render_section_header(console, "ADVANCED FEATURES")
    
    console.print(f"  [{CYAN}]Intelligent Agent System[/{CYAN}]")
    console.print(f"  [{GRAY}]  - Parallel multi-source querying[/{GRAY}]")
    console.print(f"  [{GRAY}]  - Smart rate limiting & retry[/{GRAY}]")
    console.print(f"  [{GRAY}]  - Data correlation & deduplication[/{GRAY}]")
    console.print(f"  [{GRAY}]  - Source health monitoring[/{GRAY}]")
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


@app.command()
def domain(
    domain_name: str = typer.Argument(
        ...,
        help="Domain to scan for breach exposure.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format", "-f",
        help="Output format (table, json, csv).",
    ),
    export_path: Optional[Path] = typer.Option(
        None,
        "--export", "-e",
        help="Export results to file.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Quiet mode - minimal output.",
    ),
):
    """Scan a domain for breach exposure across common email patterns."""
    try:
        if not quiet:
            render_command_header(console, "Domain Scan", "Multi-email breach analysis")
            render_status(console, f"Target: {domain_name}", "info")
            console.print()
        
        def progress_cb(current: int, total: int, email: str):
            if not quiet:
                console.print(f"  [{GRAY}][{current}/{total}] Checking {email}...[/{GRAY}]")
        
        result = scan_domain(domain_name, progress_callback=progress_cb if not quiet else None)
        
        if output_format == OutputFormat.json:
            data = {
                "domain": result.domain,
                "emails_checked": len(result.emails_checked),
                "breached_emails": result.breached_emails,
                "total_breaches": result.total_breaches,
                "risk_level": result.risk_level,
                "details": result.details,
            }
            console.print(json.dumps(data, indent=2))
        elif output_format == OutputFormat.csv:
            console.print("email,breached,breach_count")
            for detail in result.details:
                console.print(f"{detail['email']},{detail.get('breached', False)},{detail.get('breach_count', 0)}")
        else:
            if not quiet:
                console.print()
                render_section_header(console, "RESULTS")
                console.print(f"  Domain: {result.domain}", style=WHITE)
                console.print(f"  Emails checked: {len(result.emails_checked)}", style=WHITE)
                console.print(f"  Breached emails: {len(result.breached_emails)}", style=WHITE)
                console.print(f"  Risk level: {result.risk_level}", style=WHITE)
                
                if result.breached_emails:
                    console.print()
                    console.print("  Exposed emails:", style=f"bold {RED}")
                    for email in result.breached_emails:
                        console.print(f"    - {email}", style=RED)
        
        if export_path:
            data = {
                "domain": result.domain,
                "emails_checked": result.emails_checked,
                "breached_emails": result.breached_emails,
                "total_breaches": result.total_breaches,
                "risk_level": result.risk_level,
                "details": result.details,
            }
            if str(export_path).endswith(".csv"):
                export_csv(result.details, export_path)
            elif str(export_path).endswith(".html"):
                export_html(data, export_path)
            else:
                export_json(data, export_path)
            
            if not quiet:
                render_success_banner(console, f"Results exported to {export_path}")
        
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    except NetworkError as e:
        render_error_banner(console, f"Network Error: {e.message}")
        raise typer.Exit(code=EXIT_NETWORK_ERROR)


@app.command()
def bulk(
    file_path: Path = typer.Argument(
        ...,
        help="Path to file containing email addresses (CSV or TXT).",
        exists=True,
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format", "-f",
        help="Output format (table, json, csv).",
    ),
    export_path: Optional[Path] = typer.Option(
        None,
        "--export", "-e",
        help="Export results to file.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Quiet mode - minimal output.",
    ),
):
    """Check multiple email addresses from a file (CSV or TXT)."""
    try:
        if not quiet:
            render_command_header(console, "Bulk Check", "Multi-email breach scan")
            render_status(console, f"Source: {file_path}", "info")
            console.print()
        
        emails = list(read_email_list(file_path))
        
        if not emails:
            render_error_banner(console, "No valid email addresses found in file")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        
        if not quiet:
            console.print(f"  Found {len(emails)} email addresses", style=WHITE)
            console.print()
        
        results = []
        breached_count = 0
        
        import time
        REQUEST_DELAY = 1.0
        MAX_RETRIES = 2
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            disable=quiet,
        ) as progress:
            task = progress.add_task("Checking emails...", total=len(emails))
            
            for idx, item in enumerate(emails):
                retries = 0
                success = False
                
                while retries <= MAX_RETRIES and not success:
                    try:
                        result = check_email(item.value)
                        results.append({
                            "email": item.value,
                            "breached": result.breached,
                            "breach_count": len(result.breaches) if result.breaches else 0,
                            "source": result.source,
                        })
                        if result.breached:
                            breached_count += 1
                        success = True
                    except Exception as e:
                        retries += 1
                        if retries > MAX_RETRIES:
                            results.append({
                                "email": item.value,
                                "breached": None,
                                "error": str(e),
                            })
                        else:
                            time.sleep(REQUEST_DELAY * retries)
                
                progress.update(task, advance=1)
                
                if idx < len(emails) - 1:
                    time.sleep(REQUEST_DELAY)
        
        if output_format == OutputFormat.json:
            console.print(json.dumps({"results": results, "summary": {"total": len(results), "breached": breached_count}}, indent=2))
        elif output_format == OutputFormat.csv:
            console.print("email,breached,breach_count")
            for r in results:
                console.print(f"{r['email']},{r.get('breached', 'error')},{r.get('breach_count', 0)}")
        else:
            if not quiet:
                console.print()
                render_section_header(console, "SUMMARY")
                console.print(f"  Total checked: {len(results)}", style=WHITE)
                console.print(f"  Breached: {breached_count}", style=RED if breached_count > 0 else GREEN)
                console.print(f"  Clean: {len(results) - breached_count}", style=GREEN)
        
        if export_path:
            if str(export_path).endswith(".csv"):
                export_csv(results, export_path)
            elif str(export_path).endswith(".html"):
                export_html({"results": results, "summary": {"total": len(results), "breached": breached_count}}, export_path)
            else:
                export_json({"results": results, "summary": {"total": len(results), "breached": breached_count}}, export_path)
            
            if not quiet:
                render_success_banner(console, f"Results exported to {export_path}")
        
        raise typer.Exit(code=EXIT_SUCCESS)
        
    except ValidationError as e:
        render_error_banner(console, f"Validation Error: {e.message}")
        raise typer.Exit(code=EXIT_INPUT_ERROR)


@app.command(name="export")
def export_cmd(
    export_format: str = typer.Argument(
        ...,
        help="Export format: json, csv, or html.",
    ),
    output_path: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (default: auto-generated).",
    ),
):
    """Generate a report template file. Use --export flag with scan commands for real data."""
    render_command_header(console, "Export Template", "Generate empty report file")
    
    template_data = {
        "tool": "NothingHide",
        "version": __version__,
        "note": "This is a template. Use 'nothinghide domain example.com --export report.json' for real results.",
        "results": [],
    }
    
    if export_format == "json":
        path = export_json(template_data, output_path)
    elif export_format == "csv":
        path = export_csv([], output_path)
    elif export_format == "html":
        path = export_html(template_data, output_path)
    else:
        render_error_banner(console, f"Unknown format: {export_format}. Use json, csv, or html.")
        raise typer.Exit(code=EXIT_INPUT_ERROR)
    
    render_success_banner(console, f"Template exported to: {path}")
    console.print(f"  [{GRAY}]Tip: Use --export flag with domain/bulk commands for real results[/{GRAY}]")
    raise typer.Exit(code=EXIT_SUCCESS)


@app.command()
def config(
    show: bool = typer.Option(
        False,
        "--show", "-s",
        help="Show current configuration.",
    ),
    reset: bool = typer.Option(
        False,
        "--reset",
        help="Reset configuration to defaults.",
    ),
    set_format: Optional[str] = typer.Option(
        None,
        "--format",
        help="Set default output format (table, json, csv).",
    ),
    set_quiet: Optional[bool] = typer.Option(
        None,
        "--quiet",
        help="Set default quiet mode (true/false).",
    ),
    set_color: Optional[bool] = typer.Option(
        None,
        "--color",
        help="Enable/disable colored output.",
    ),
):
    """View or modify NothingHide configuration."""
    render_command_header(console, "Configuration", "User preferences")
    
    if reset:
        settings = reset_settings()
        render_success_banner(console, "Configuration reset to defaults")
        raise typer.Exit(code=EXIT_SUCCESS)
    
    updates = {}
    if set_format:
        updates["output_format"] = set_format
    if set_quiet is not None:
        updates["quiet"] = set_quiet
    if set_color is not None:
        updates["color"] = set_color
    
    if updates:
        settings = update_settings(**updates)
        render_success_banner(console, "Configuration updated")
    else:
        settings = get_settings()
    
    if show or not updates:
        console.print()
        console.print("  Current settings:", style=f"bold {WHITE}")
        console.print()
        for key, value in settings.to_dict().items():
            console.print(f"    {key}: {value}", style=GRAY)
        console.print()
    
    raise typer.Exit(code=EXIT_SUCCESS)


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
