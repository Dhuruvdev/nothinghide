"""NothingHide - Security Exposure Intelligence Library.

A professional Python library for checking email and password exposure
in public data breaches using lawful, publicly available sources.

Usage:
    # Simple API
    from nothinghide import check_email, check_password
    
    result = check_email("user@example.com")
    result = check_password("mypassword123")
    
    # Async API
    from nothinghide import async_check_email, async_check_password
    
    result = await async_check_email("user@example.com")
    result = await async_check_password("mypassword123")
    
    # Full scan
    from nothinghide import BreachScanner
    
    scanner = BreachScanner()
    report = scanner.full_scan("user@example.com", "mypassword123")

Security Guarantees:
    - Passwords are NEVER transmitted - only SHA-1 hash prefix (5 chars)
    - K-anonymity protocol ensures privacy
    - No data is stored or logged
    - All sources are lawful and publicly available
"""

__version__ = "1.0.0"
__author__ = "NothingHide Team"
__license__ = "MIT"

from .core import (
    check_email,
    check_password,
    async_check_email,
    async_check_password,
    BreachScanner,
    BreachResult,
    PasswordResult,
    ScanReport,
)

from .email_checker import (
    EmailChecker,
    check_email_hackcheck,
    check_email_xposedornot,
)

from .password_checker import (
    PasswordChecker,
    check_password_hibp,
    hash_password_sha1,
)

from .exceptions import (
    NothingHideError,
    ValidationError,
    NetworkError,
    APIError,
    RateLimitError,
)

__all__ = [
    "__version__",
    "check_email",
    "check_password",
    "async_check_email",
    "async_check_password",
    "BreachScanner",
    "BreachResult",
    "PasswordResult",
    "ScanReport",
    "EmailChecker",
    "PasswordChecker",
    "check_email_hackcheck",
    "check_email_xposedornot",
    "check_password_hibp",
    "hash_password_sha1",
    "NothingHideError",
    "ValidationError",
    "NetworkError",
    "APIError",
    "RateLimitError",
]
