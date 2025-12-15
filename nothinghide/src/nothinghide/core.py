"""Core API for NothingHide library.

This module provides the main public API for checking email and
password exposure in data breaches.

Example:
    from nothinghide import check_email, check_password
    
    # Check email
    result = check_email("user@example.com")
    if result.breached:
        print(f"Found in {result.breach_count} breaches!")
    
    # Check password
    result = check_password("mypassword123")
    if result.exposed:
        print(f"Seen {result.count} times in breaches!")
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

from .email_checker import EmailChecker, validate_email_address
from .password_checker import PasswordChecker
from .config import RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL
from .exceptions import NothingHideError, ValidationError, NetworkError


@dataclass
class BreachResult:
    """Result of an email breach check.
    
    Attributes:
        email: The email address that was checked.
        breached: Whether the email was found in breaches.
        breach_count: Number of breaches found.
        breaches: List of breach details.
        source: API source used for the check.
        checked_at: When the check was performed.
    """
    email: str
    breached: bool
    breach_count: int = 0
    breaches: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "Unknown"
    checked_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.checked_at is None:
            self.checked_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "email": self.email,
            "breached": self.breached,
            "breach_count": self.breach_count,
            "breaches": self.breaches,
            "source": self.source,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


@dataclass
class PasswordResult:
    """Result of a password exposure check.
    
    Attributes:
        exposed: Whether the password was found in breaches.
        count: Number of times the password appeared.
        source: API source used for the check.
        strength: Password strength assessment.
        checked_at: When the check was performed.
    """
    exposed: bool
    count: int = 0
    source: str = "Have I Been Pwned"
    strength: Optional[str] = None
    feedback: List[str] = field(default_factory=list)
    checked_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.checked_at is None:
            self.checked_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "exposed": self.exposed,
            "count": self.count,
            "source": self.source,
            "strength": self.strength,
            "feedback": self.feedback,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


@dataclass
class ScanReport:
    """Complete identity scan report.
    
    Attributes:
        email_result: Email breach check result.
        password_result: Password exposure result.
        risk_level: Computed risk level.
        recommendations: List of security recommendations.
        scanned_at: When the scan was performed.
    """
    email_result: BreachResult
    password_result: PasswordResult
    risk_level: str
    recommendations: List[str] = field(default_factory=list)
    scanned_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "email_result": self.email_result.to_dict(),
            "password_result": self.password_result.to_dict(),
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }


def check_email(email: str, timeout: float = 15.0) -> BreachResult:
    """Check if an email address appears in known data breaches.
    
    This queries public breach databases and returns information about
    any breaches where this email was found. No data is stored.
    
    Args:
        email: Email address to check.
        timeout: Request timeout in seconds.
        
    Returns:
        BreachResult with breach information.
        
    Raises:
        ValidationError: If email is invalid.
        NetworkError: If API request fails.
        
    Example:
        result = check_email("user@example.com")
        if result.breached:
            for breach in result.breaches:
                print(f"Found in {breach['name']}")
    """
    checker = EmailChecker(timeout=timeout)
    raw_result = checker.check(email)
    
    return BreachResult(
        email=email,
        breached=raw_result.get("breached", False),
        breach_count=raw_result.get("breach_count", 0),
        breaches=raw_result.get("breaches", []),
        source=raw_result.get("source", "Unknown"),
    )


def check_password(password: str, timeout: float = 15.0) -> PasswordResult:
    """Check if a password has been exposed in known data breaches.
    
    Uses the Have I Been Pwned Pwned Passwords API with k-anonymity.
    Your password is NEVER transmitted - only the first 5 characters
    of its SHA-1 hash are sent, and comparison happens locally.
    
    Args:
        password: Password to check (never stored or logged).
        timeout: Request timeout in seconds.
        
    Returns:
        PasswordResult with exposure information.
        
    Raises:
        ValidationError: If password is empty.
        NetworkError: If API request fails.
        
    Example:
        result = check_password("mypassword123")
        if result.exposed:
            print(f"Password found {result.count} times!")
    """
    checker = PasswordChecker(timeout=timeout)
    raw_result = checker.check_strength(password)
    
    return PasswordResult(
        exposed=raw_result.get("exposed", False),
        count=raw_result.get("count", 0),
        source=raw_result.get("source", "Have I Been Pwned"),
        strength=raw_result.get("strength"),
        feedback=raw_result.get("feedback", []),
    )


async def async_check_email(email: str, timeout: float = 10.0) -> BreachResult:
    """Async version of check_email.
    
    Args:
        email: Email address to check.
        timeout: Request timeout in seconds.
        
    Returns:
        BreachResult with breach information.
    """
    checker = EmailChecker(timeout=timeout)
    raw_result = await checker.async_check(email)
    
    return BreachResult(
        email=email,
        breached=raw_result.get("breached", False),
        breach_count=raw_result.get("breach_count", 0),
        breaches=raw_result.get("breaches", []),
        source=raw_result.get("source", "Unknown"),
    )


async def async_check_password(password: str, timeout: float = 10.0) -> PasswordResult:
    """Async version of check_password.
    
    Args:
        password: Password to check.
        timeout: Request timeout in seconds.
        
    Returns:
        PasswordResult with exposure information.
    """
    checker = PasswordChecker(timeout=timeout)
    raw_result = await checker.async_check(password)
    
    return PasswordResult(
        exposed=raw_result.get("exposed", False),
        count=raw_result.get("count", 0),
        source=raw_result.get("source", "Have I Been Pwned"),
    )


def calculate_risk_level(
    email_breached: bool,
    password_exposed: bool,
    breach_count: int = 0,
    password_exposure_count: int = 0
) -> str:
    """Calculate overall risk level based on check results.
    
    Args:
        email_breached: Whether email was found in breaches.
        password_exposed: Whether password was found exposed.
        breach_count: Number of email breaches found.
        password_exposure_count: Number of times password was exposed.
        
    Returns:
        Risk level string: LOW, MEDIUM, HIGH, or CRITICAL.
    """
    if password_exposed and email_breached:
        if password_exposure_count > 100 or breach_count >= 5:
            return RISK_CRITICAL
        return RISK_HIGH
    elif password_exposed:
        if password_exposure_count > 1000:
            return RISK_HIGH
        return RISK_HIGH
    elif email_breached:
        if breach_count >= 5:
            return RISK_HIGH
        elif breach_count >= 2:
            return RISK_MEDIUM
        return RISK_MEDIUM
    else:
        return RISK_LOW


def get_recommendations(
    risk_level: str,
    email_breached: bool,
    password_exposed: bool
) -> List[str]:
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
        recommendations.append(
            "Change this password immediately on all accounts where it is used."
        )
        recommendations.append(
            "Use a unique, strong password for each account."
        )
        recommendations.append(
            "Consider using a password manager to generate secure passwords."
        )
    
    if email_breached:
        recommendations.append(
            "Review account security for services associated with this email."
        )
        recommendations.append(
            "Enable two-factor authentication where available."
        )
        recommendations.append(
            "Be cautious of phishing attempts targeting this email."
        )
    
    if risk_level in [RISK_HIGH, RISK_CRITICAL]:
        recommendations.append(
            "Monitor your accounts for unauthorized activity."
        )
        recommendations.append(
            "Consider setting up credit monitoring if financial data was exposed."
        )
    
    if not recommendations:
        recommendations.append(
            "No immediate action required. Continue practicing good security hygiene."
        )
    
    return recommendations


class BreachScanner:
    """Complete identity breach scanner.
    
    Performs comprehensive email and password exposure checks
    and generates risk assessments with recommendations.
    
    Example:
        scanner = BreachScanner()
        report = scanner.full_scan("user@example.com", "mypassword")
        
        print(f"Risk Level: {report.risk_level}")
        for rec in report.recommendations:
            print(f"- {rec}")
    """
    
    def __init__(
        self,
        timeout: float = 15.0,
        xposedornot_api_key: Optional[str] = None,
    ):
        """Initialize BreachScanner.
        
        Args:
            timeout: Request timeout in seconds.
            xposedornot_api_key: Optional API key for XposedOrNot.
        """
        self.email_checker = EmailChecker(
            timeout=timeout,
            xposedornot_api_key=xposedornot_api_key,
        )
        self.password_checker = PasswordChecker(timeout=timeout)
    
    def full_scan(self, email: str, password: str) -> ScanReport:
        """Perform complete identity scan.
        
        Args:
            email: Email address to check.
            password: Password to check (never stored).
            
        Returns:
            ScanReport with complete results and recommendations.
        """
        email_raw = self.email_checker.check(email)
        email_result = BreachResult(
            email=email,
            breached=email_raw.get("breached", False),
            breach_count=email_raw.get("breach_count", 0),
            breaches=email_raw.get("breaches", []),
            source=email_raw.get("source", "Unknown"),
        )
        
        password_raw = self.password_checker.check_strength(password)
        password_result = PasswordResult(
            exposed=password_raw.get("exposed", False),
            count=password_raw.get("count", 0),
            source=password_raw.get("source", "Have I Been Pwned"),
            strength=password_raw.get("strength"),
            feedback=password_raw.get("feedback", []),
        )
        
        risk_level = calculate_risk_level(
            email_result.breached,
            password_result.exposed,
            email_result.breach_count,
            password_result.count,
        )
        
        recommendations = get_recommendations(
            risk_level,
            email_result.breached,
            password_result.exposed,
        )
        
        return ScanReport(
            email_result=email_result,
            password_result=password_result,
            risk_level=risk_level,
            recommendations=recommendations,
        )
    
    async def async_full_scan(self, email: str, password: str) -> ScanReport:
        """Async version of full_scan.
        
        Args:
            email: Email address to check.
            password: Password to check.
            
        Returns:
            ScanReport with complete results.
        """
        email_task = self.email_checker.async_check(email)
        password_task = self.password_checker.async_check(password)
        
        email_raw, password_raw = await asyncio.gather(email_task, password_task)
        
        email_result = BreachResult(
            email=email,
            breached=email_raw.get("breached", False),
            breach_count=email_raw.get("breach_count", 0),
            breaches=email_raw.get("breaches", []),
            source=email_raw.get("source", "Unknown"),
        )
        
        password_result = PasswordResult(
            exposed=password_raw.get("exposed", False),
            count=password_raw.get("count", 0),
            source=password_raw.get("source", "Have I Been Pwned"),
        )
        
        risk_level = calculate_risk_level(
            email_result.breached,
            password_result.exposed,
            email_result.breach_count,
            password_result.count,
        )
        
        recommendations = get_recommendations(
            risk_level,
            email_result.breached,
            password_result.exposed,
        )
        
        return ScanReport(
            email_result=email_result,
            password_result=password_result,
            risk_level=risk_level,
            recommendations=recommendations,
        )
    
    def check_email(self, email: str) -> BreachResult:
        """Check email only.
        
        Args:
            email: Email address to check.
            
        Returns:
            BreachResult with breach information.
        """
        raw_result = self.email_checker.check(email)
        return BreachResult(
            email=email,
            breached=raw_result.get("breached", False),
            breach_count=raw_result.get("breach_count", 0),
            breaches=raw_result.get("breaches", []),
            source=raw_result.get("source", "Unknown"),
        )
    
    def check_password(self, password: str) -> PasswordResult:
        """Check password only.
        
        Args:
            password: Password to check.
            
        Returns:
            PasswordResult with exposure information.
        """
        raw_result = self.password_checker.check_strength(password)
        return PasswordResult(
            exposed=raw_result.get("exposed", False),
            count=raw_result.get("count", 0),
            source=raw_result.get("source", "Have I Been Pwned"),
            strength=raw_result.get("strength"),
            feedback=raw_result.get("feedback", []),
        )
