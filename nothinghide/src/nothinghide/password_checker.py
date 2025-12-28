"""Secure password breach checking using k-anonymity.

This module implements the Have I Been Pwned Pwned Passwords API
with k-anonymity protocol. Passwords are NEVER transmitted - only
the first 5 characters of the SHA-1 hash are sent.

SECURITY GUARANTEES:
- Password is never logged or stored
- Password is never transmitted over the network
- Only SHA-1 hash prefix (5 chars) is sent to API
- Full hash comparison happens locally
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime

import httpx

from .config import (
    HIBP_PASSWORD_API,
    REQUEST_TIMEOUT,
    ASYNC_TIMEOUT,
    USER_AGENT,
)
from .exceptions import (
    ValidationError,
    NetworkError,
    APIError,
    RateLimitError,
)

logger = logging.getLogger(__name__)


def hash_password_sha1(password: str) -> str:
    """Hash password using SHA-1 for HIBP k-anonymity check.
    
    Note: SHA-1 is used because it's what HIBP requires, not for
    security purposes. The k-anonymity model provides privacy protection.
    
    Args:
        password: Plain text password (never stored or logged).
        
    Returns:
        Uppercase SHA-1 hash of the password.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def get_hash_prefix_suffix(sha1_hash: str) -> tuple:
    """Split SHA-1 hash into prefix and suffix for k-anonymity.
    
    The first 5 characters are sent to the API, the remaining
    characters are used for local comparison only.
    
    Args:
        sha1_hash: Full SHA-1 hash string.
        
    Returns:
        Tuple of (first 5 characters, remaining characters).
    """
    return sha1_hash[:5], sha1_hash[5:]


def check_password_hibp(
    password: str,
    timeout: float = REQUEST_TIMEOUT,
    enable_padding: bool = True
) -> Dict[str, Any]:
    """Check if password has been exposed using HIBP k-anonymity API.
    
    This uses the Pwned Passwords API which is free and requires no
    authentication. The password is hashed with SHA-1, and only the
    first 5 characters of the hash are sent to the API.
    
    Args:
        password: Plain text password to check (never stored or logged).
        timeout: Request timeout in seconds.
        enable_padding: Whether to enable response padding (recommended).
        
    Returns:
        Dictionary with exposure status and count.
        
    Raises:
        ValidationError: If password is empty.
        NetworkError: If API request fails.
    """
    if not password:
        raise ValidationError("Password cannot be empty", field="password")
    
    sha1_hash = hash_password_sha1(password)
    prefix, suffix = get_hash_prefix_suffix(sha1_hash)
    
    url = HIBP_PASSWORD_API.format(prefix=prefix)
    
    headers = {"User-Agent": USER_AGENT}
    if enable_padding:
        headers["Add-Padding"] = "true"
    
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers)
            
            if response.status_code == 429:
                raise RateLimitError("Have I Been Pwned")
            
            if response.status_code != 200:
                raise APIError(
                    f"API returned status {response.status_code}",
                    api_name="Have I Been Pwned",
                    status_code=response.status_code,
                )
            
            for line in response.text.splitlines():
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
            
    except (RateLimitError, APIError):
        raise
    except httpx.TimeoutException:
        raise NetworkError("Request timed out", url=url)
    except httpx.RequestError as e:
        logger.warning(f"HIBP password check request failed: {e}")
        raise NetworkError("Network error occurred", url=url)


async def async_check_password_hibp(
    password: str,
    timeout: float = ASYNC_TIMEOUT,
    enable_padding: bool = True
) -> Dict[str, Any]:
    """Async version of HIBP password check.
    
    Args:
        password: Plain text password to check.
        timeout: Request timeout in seconds.
        enable_padding: Whether to enable response padding.
        
    Returns:
        Dictionary with exposure status and count.
    """
    if not password:
        raise ValidationError("Password cannot be empty", field="password")
    
    sha1_hash = hash_password_sha1(password)
    prefix, suffix = get_hash_prefix_suffix(sha1_hash)
    
    url = HIBP_PASSWORD_API.format(prefix=prefix)
    
    headers = {"User-Agent": USER_AGENT}
    if enable_padding:
        headers["Add-Padding"] = "true"
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 429:
                raise RateLimitError("Have I Been Pwned")
            
            if response.status_code != 200:
                raise APIError(
                    f"API returned status {response.status_code}",
                    api_name="Have I Been Pwned",
                    status_code=response.status_code,
                )
            
            for line in response.text.splitlines():
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
            raise NetworkError("Request timed out", url=url)


class PasswordChecker:
    """Secure password breach checker using k-anonymity.
    
    Provides privacy-preserving password exposure detection.
    Passwords are NEVER transmitted - only SHA-1 hash prefixes.
    
    Example:
        checker = PasswordChecker()
        result = checker.check("mypassword123")
        
        if result["exposed"]:
            print(f"Password found {result['count']} times!")
        
        # Async usage
        result = await checker.async_check("mypassword123")
    """
    
    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT,
        enable_padding: bool = True,
    ):
        """Initialize PasswordChecker.
        
        Args:
            timeout: Request timeout in seconds.
            enable_padding: Whether to enable response padding.
        """
        self.timeout = timeout
        self.enable_padding = enable_padding
        self._last_check_time: Optional[datetime] = None
    
    def check(self, password: str) -> Dict[str, Any]:
        """Check if password has been exposed in breaches with fuzzy variations."""
        # Check original
        result = check_password_hibp(
            password,
            timeout=self.timeout,
            enable_padding=self.enable_padding,
        )
        
        # Check common variations (fuzzy matching)
        variations = [
            password.lower(),
            password + "1",
            password + "!",
        ]
        
        max_count = result.get("count", 0)
        exposed = result.get("exposed", False)
        
        for var in set(variations):
            if var == password: continue
            try:
                res = check_password_hibp(var, timeout=self.timeout)
                if res.get("exposed"):
                    exposed = True
                    max_count = max(max_count, res.get("count", 0))
            except:
                continue
                
        result["exposed"] = exposed
        result["count"] = max_count
        self._last_check_time = datetime.now()
        return result
    
    async def async_check(self, password: str) -> Dict[str, Any]:
        """Async check if password has been exposed.
        
        Args:
            password: Plain text password to check.
            
        Returns:
            Dictionary with exposure status and count.
        """
        result = await async_check_password_hibp(
            password,
            timeout=self.timeout,
            enable_padding=self.enable_padding,
        )
        self._last_check_time = datetime.now()
        return result
    
    def check_strength(self, password: str) -> Dict[str, Any]:
        """Check password strength and exposure.
        
        Provides both exposure status and basic strength analysis.
        
        Args:
            password: Plain text password to check.
            
        Returns:
            Dictionary with exposure and strength information.
        """
        exposure_result = self.check(password)
        
        strength_score = 0
        feedback = []
        
        if len(password) >= 8:
            strength_score += 1
        else:
            feedback.append("Use at least 8 characters")
        
        if len(password) >= 12:
            strength_score += 1
        
        if len(password) >= 16:
            strength_score += 1
        
        if any(c.isupper() for c in password):
            strength_score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            strength_score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            strength_score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            strength_score += 1
        else:
            feedback.append("Add special characters")
        
        if strength_score <= 2:
            strength = "WEAK"
        elif strength_score <= 4:
            strength = "FAIR"
        elif strength_score <= 5:
            strength = "GOOD"
        else:
            strength = "STRONG"
        
        if exposure_result.get("exposed"):
            strength = "COMPROMISED"
            feedback.insert(0, "This password has been exposed in data breaches")
        
        return {
            **exposure_result,
            "strength": strength,
            "strength_score": strength_score,
            "feedback": feedback,
        }
