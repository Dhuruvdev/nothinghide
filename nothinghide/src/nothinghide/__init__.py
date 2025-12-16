"""NothingHide - Security Exposure Intelligence Library.

A professional Python library for checking email and password exposure
in public data breaches using lawful, publicly available sources.

Features:
    - Multi-source breach intelligence from 6+ APIs
    - Intelligent parallel processing with rate limiting
    - Automatic source failover and retry
    - Data correlation and deduplication
    - Domain reputation analysis
    - Paste site monitoring
    - k-anonymity password checking

Usage:
    # Simple API
    from nothinghide import check_email, check_password
    
    result = check_email("user@example.com")
    result = check_password("mypassword123")
    
    # Advanced Agent API (recommended)
    from nothinghide import BreachIntelligenceAgent
    
    agent = BreachIntelligenceAgent()
    result = agent.check_email_sync("user@example.com")
    
    # Async usage
    result = await agent.check_email("user@example.com")
    
    # Full intelligence gathering
    intel = agent.get_full_intelligence("user@example.com")
    
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

from .agent import (
    BreachIntelligenceAgent,
    AgentConfig,
    CorrelatedResult,
    DomainChecker,
    ThreatIntelligence,
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
    "BreachIntelligenceAgent",
    "AgentConfig",
    "CorrelatedResult",
    "DomainChecker",
    "ThreatIntelligence",
]
