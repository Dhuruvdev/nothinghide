"""Domain scanning functionality for NothingHide."""

import re
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass

from .core import check_email
from .exceptions import ValidationError


@dataclass
class DomainResult:
    """Result of a domain scan."""
    domain: str
    emails_checked: List[str]
    breached_emails: List[str]
    total_breaches: int
    risk_level: str
    details: List[Dict[str, Any]]


def validate_domain(domain: str) -> str:
    """Validate and normalize a domain name."""
    domain = domain.strip().lower()
    
    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    
    if domain.startswith("www."):
        domain = domain[4:]
    
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$"
    if not re.match(pattern, domain):
        raise ValidationError(f"Invalid domain format: {domain}")
    
    return domain


def generate_common_emails(domain: str) -> List[str]:
    """Generate common email patterns for a domain."""
    prefixes = [
        "admin",
        "info",
        "contact",
        "support",
        "sales",
        "hello",
        "help",
        "mail",
        "office",
        "team",
        "hr",
        "careers",
        "jobs",
        "billing",
        "accounts",
        "security",
        "webmaster",
        "postmaster",
        "noreply",
        "no-reply",
    ]
    
    return [f"{prefix}@{domain}" for prefix in prefixes]


import time

REQUEST_DELAY = 1.0
MAX_RETRIES = 2

def scan_domain(
    domain: str,
    emails: Optional[List[str]] = None,
    check_common: bool = True,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    request_delay: float = REQUEST_DELAY
) -> DomainResult:
    """Scan a domain for breach exposure.
    
    Args:
        domain: Domain to scan
        emails: Optional list of specific emails to check
        check_common: If True, also check common email patterns
        progress_callback: Optional callback(current, total, email) for progress
        request_delay: Delay between requests to avoid rate limiting
    
    Returns:
        DomainResult with scan results
    """
    domain = validate_domain(domain)
    
    emails_to_check = list(emails) if emails else []
    
    if check_common:
        common_emails = generate_common_emails(domain)
        for email in common_emails:
            if email not in emails_to_check:
                emails_to_check.append(email)
    
    breached_emails = []
    details = []
    total_breaches = 0
    
    for i, email in enumerate(emails_to_check):
        if progress_callback:
            progress_callback(i + 1, len(emails_to_check), email)
        
        retries = 0
        while retries <= MAX_RETRIES:
            try:
                result = check_email(email)
                
                detail = {
                    "email": email,
                    "breached": result.breached,
                    "breach_count": len(result.breaches) if result.breaches else 0,
                    "breaches": result.breaches or []
                }
                details.append(detail)
                
                if result.breached:
                    breached_emails.append(email)
                    total_breaches += len(result.breaches) if result.breaches else 1
                
                break
                    
            except Exception as e:
                retries += 1
                if retries > MAX_RETRIES:
                    details.append({
                        "email": email,
                        "breached": None,
                        "error": str(e)
                    })
                else:
                    time.sleep(request_delay * retries)
        
        if i < len(emails_to_check) - 1:
            time.sleep(request_delay)
    
    if not breached_emails:
        risk_level = "LOW"
    elif len(breached_emails) <= 2:
        risk_level = "MEDIUM"
    elif len(breached_emails) <= 5:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"
    
    return DomainResult(
        domain=domain,
        emails_checked=emails_to_check,
        breached_emails=breached_emails,
        total_breaches=total_breaches,
        risk_level=risk_level,
        details=details
    )
