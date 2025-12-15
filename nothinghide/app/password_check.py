"""Password exposure checking module.

This module implements secure password checking using the Have I Been Pwned
Pwned Passwords API with k-anonymity. The password is NEVER transmitted -
only the first 5 characters of its SHA-1 hash are sent, and the comparison
is done locally.

SECURITY GUARANTEES:
- Password is never logged or stored
- Password is never transmitted over the network
- Only SHA-1 hash prefix (5 chars) is sent to API
- Full hash comparison happens locally
"""

import getpass
import httpx
import logging
from typing import Optional

from .config import (
    HIBP_PASSWORD_API,
    REQUEST_TIMEOUT,
    USER_AGENT,
)
from .utils import (
    hash_password_sha1,
    get_hash_prefix_suffix,
    logger,
)

logger = logging.getLogger(__name__)


def get_password_securely() -> str:
    """Prompt user for password with no echo.
    
    Uses getpass for secure input - characters are not displayed.
    
    Returns:
        Password string (never stored beyond this function scope).
    """
    return getpass.getpass(prompt="Enter password to check (input hidden): ")


def check_password_hibp(password: str) -> dict:
    """Check if password has been exposed using HIBP k-anonymity API.
    
    This uses the Pwned Passwords API which is free and requires no authentication.
    The password is hashed with SHA-1, and only the first 5 characters of the hash
    are sent to the API. The API returns all hash suffixes that match the prefix,
    and comparison is done locally.
    
    Args:
        password: Plain text password to check (never stored or logged).
        
    Returns:
        Dictionary with exposure status and count.
    """
    if not password:
        return {
            "error": True,
            "message": "Password cannot be empty.",
            "validation_error": True,
        }
    
    sha1_hash = hash_password_sha1(password)
    prefix, suffix = get_hash_prefix_suffix(sha1_hash)
    
    url = HIBP_PASSWORD_API.format(prefix=prefix)
    
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Add-Padding": "true",
                },
            )
            
            if response.status_code != 200:
                return {
                    "error": True,
                    "message": f"Password check API returned status {response.status_code}",
                }
            
            hash_suffixes = response.text.splitlines()
            
            for line in hash_suffixes:
                if ":" not in line:
                    continue
                    
                hash_suffix, count_str = line.split(":", 1)
                hash_suffix = hash_suffix.strip()
                
                if hash_suffix.upper() == suffix:
                    try:
                        count = int(count_str.strip())
                    except ValueError:
                        count = 1
                    
                    return {
                        "exposed": True,
                        "count": count,
                        "source": "Have I Been Pwned",
                    }
            
            return {
                "exposed": False,
                "count": 0,
                "source": "Have I Been Pwned",
            }
            
    except httpx.TimeoutException:
        return {
            "error": True,
            "message": "Request timed out. Please try again.",
        }
    except httpx.RequestError as e:
        logger.warning(f"HIBP password check request failed: {e}")
        return {
            "error": True,
            "message": "Network error occurred. Check your connection.",
        }
    except Exception as e:
        logger.error(f"Unexpected error in password check: {e}")
        return {
            "error": True,
            "message": "An unexpected error occurred during password check.",
        }


def check_password_interactive() -> dict:
    """Interactive password check with secure input.
    
    Prompts user for password, checks it, and returns results.
    Password is cleared from memory after check.
    
    Returns:
        Dictionary with exposure status and count.
    """
    try:
        password = get_password_securely()
        
        if not password:
            return {
                "error": True,
                "message": "No password provided.",
                "validation_error": True,
            }
        
        result = check_password_hibp(password)
        
        password = None
        
        return result
        
    except KeyboardInterrupt:
        return {
            "error": True,
            "message": "Password input cancelled.",
            "cancelled": True,
        }
    except EOFError:
        return {
            "error": True,
            "message": "No password input received.",
            "validation_error": True,
        }
