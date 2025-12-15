"""Combined identity scan module.

This module runs both email and password checks, calculates an overall
risk level, and provides actionable security recommendations.
"""

from .email_check import check_email
from .password_check import check_password_interactive, check_password_hibp
from .utils import (
    calculate_risk_level,
    get_recommendations,
    validate_email_address,
)


def run_identity_scan(email: str) -> dict:
    """Run a complete identity scan (email + password check).
    
    Args:
        email: Email address to check.
        
    Returns:
        Dictionary with complete scan results including:
        - email_result: Email breach check results
        - password_result: Password exposure check results
        - risk_level: Overall risk assessment (LOW/MEDIUM/HIGH)
        - recommendations: List of actionable security steps
    """
    is_valid, validation_result = validate_email_address(email)
    if not is_valid:
        return {
            "error": True,
            "message": f"Invalid email format: {validation_result}",
            "validation_error": True,
        }
    
    email_result = check_email(email)
    
    if email_result.get("error") and not email_result.get("validation_error"):
        email_result = {
            "breached": False,
            "breach_count": 0,
            "breaches": [],
            "warning": "Email check unavailable - API error",
        }
    
    password_result = check_password_interactive()
    
    if password_result.get("error"):
        if password_result.get("cancelled"):
            return {
                "error": True,
                "message": "Scan cancelled by user.",
                "cancelled": True,
            }
        
        password_result = {
            "exposed": False,
            "count": 0,
            "warning": "Password check unavailable",
        }
    
    email_breached = email_result.get("breached", False)
    password_exposed = password_result.get("exposed", False)
    breach_count = email_result.get("breach_count", 0)
    
    risk_level = calculate_risk_level(
        email_breached=email_breached,
        password_exposed=password_exposed,
        breach_count=breach_count,
    )
    
    recommendations = get_recommendations(
        risk_level=risk_level,
        email_breached=email_breached,
        password_exposed=password_exposed,
    )
    
    return {
        "email_result": email_result,
        "password_result": password_result,
        "risk_level": risk_level,
        "recommendations": recommendations,
    }


def run_email_only_scan(email: str) -> dict:
    """Run email-only scan without password check.
    
    Args:
        email: Email address to check.
        
    Returns:
        Dictionary with email scan results.
    """
    return check_email(email)


def run_password_only_scan(password: str | None = None) -> dict:
    """Run password-only scan.
    
    Args:
        password: Optional password string. If None, prompts interactively.
        
    Returns:
        Dictionary with password scan results.
    """
    if password:
        return check_password_hibp(password)
    return check_password_interactive()
