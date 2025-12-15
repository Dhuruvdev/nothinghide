"""Advanced email breach checking with multiple API sources and fallbacks.

This module provides comprehensive email breach detection using multiple
public breach databases with automatic fallback support.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime

import httpx
from email_validator import validate_email, EmailNotValidError

from .config import (
    HACKCHECK_API,
    XPOSEDORNOT_API,
    REQUEST_TIMEOUT,
    ASYNC_TIMEOUT,
    USER_AGENT,
    MAX_RETRIES,
    RETRY_DELAY,
)
from .exceptions import (
    ValidationError,
    NetworkError,
    APIError,
    RateLimitError,
)

logger = logging.getLogger(__name__)


@dataclass
class BreachInfo:
    """Information about a single breach."""
    name: str
    year: str = "Unknown"
    date: Optional[str] = None
    data_classes: List[str] = field(default_factory=lambda: ["Unknown"])
    description: Optional[str] = None
    is_verified: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "year": self.year,
            "date": self.date,
            "data_classes": self.data_classes,
            "description": self.description,
            "is_verified": self.is_verified,
        }


def validate_email_address(email: str) -> str:
    """Validate and normalize an email address.
    
    Args:
        email: Email address to validate.
        
    Returns:
        Normalized email address.
        
    Raises:
        ValidationError: If email is invalid.
    """
    try:
        result = validate_email(email, check_deliverability=False)
        return result.normalized
    except EmailNotValidError as e:
        raise ValidationError(str(e), field="email")


def extract_year(date_string: str) -> str:
    """Extract year from various date formats.
    
    Args:
        date_string: Date string in various formats.
        
    Returns:
        Year string or 'Unknown'.
    """
    if not date_string:
        return "Unknown"
    
    try:
        if len(date_string) >= 4:
            year = date_string[:4]
            if year.isdigit() and 1990 <= int(year) <= 2030:
                return year
        
        for sep in ["-", "/", "."]:
            if sep in date_string:
                parts = date_string.split(sep)
                for part in parts:
                    if len(part) == 4 and part.isdigit():
                        year_val = int(part)
                        if 1990 <= year_val <= 2030:
                            return str(year_val)
        
        return "Unknown"
    except Exception:
        return "Unknown"


def check_email_hackcheck(email: str, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
    """Check email against HackCheck API.
    
    Args:
        email: Validated email address to check.
        timeout: Request timeout in seconds.
        
    Returns:
        Dictionary with breach results or error information.
    """
    url = HACKCHECK_API.format(email=email)
    
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(
                url,
                headers={"User-Agent": USER_AGENT},
            )
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "HackCheck",
                }
            
            if response.status_code == 429:
                raise RateLimitError("HackCheck")
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list) and len(data) > 0:
                    breaches = []
                    for breach in data:
                        breach_info = BreachInfo(
                            name=breach.get("Title", breach.get("Name", "Unknown")),
                            year=extract_year(breach.get("BreachDate", breach.get("AddedDate", ""))),
                            date=breach.get("BreachDate"),
                            data_classes=breach.get("DataClasses", ["Unknown"]),
                        )
                        breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "HackCheck",
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "HackCheck",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="HackCheck",
                status_code=response.status_code,
            )
            
    except (RateLimitError, APIError):
        raise
    except httpx.TimeoutException:
        raise NetworkError("Request timed out", url=url)
    except httpx.RequestError as e:
        logger.warning(f"HackCheck request failed: {e}")
        raise NetworkError("Network error occurred", url=url)


def check_email_xposedornot(
    email: str, 
    api_key: Optional[str] = None,
    timeout: float = REQUEST_TIMEOUT
) -> Dict[str, Any]:
    """Check email against XposedOrNot API.
    
    Args:
        email: Validated email address to check.
        api_key: Optional API key for XposedOrNot.
        timeout: Request timeout in seconds.
        
    Returns:
        Dictionary with breach results or error information.
    """
    url = XPOSEDORNOT_API.format(email=email)
    headers = {"User-Agent": USER_AGENT}
    
    if api_key:
        headers["x-api-key"] = api_key
    
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers)
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot",
                }
            
            if response.status_code == 429:
                raise RateLimitError("XposedOrNot")
            
            if response.status_code == 200:
                data = response.json()
                
                breaches_data = data.get("breaches") or data.get("ExposedBreaches", {}).get("breaches_details", [])
                
                if breaches_data:
                    breaches = []
                    
                    if isinstance(breaches_data, list):
                        for item in breaches_data:
                            if isinstance(item, str):
                                breach_info = BreachInfo(name=item)
                            else:
                                breach_info = BreachInfo(
                                    name=item.get("breach", item.get("name", "Unknown")),
                                    year=extract_year(item.get("xposed_date", "")),
                                    date=item.get("xposed_date"),
                                    data_classes=item.get("xposed_data", ["Unknown"]),
                                )
                            breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "XposedOrNot",
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="XposedOrNot",
                status_code=response.status_code,
            )
            
    except (RateLimitError, APIError):
        raise
    except httpx.TimeoutException:
        raise NetworkError("Request timed out", url=url)
    except httpx.RequestError as e:
        logger.warning(f"XposedOrNot request failed: {e}")
        raise NetworkError("Network error occurred", url=url)


async def async_check_email_hackcheck(
    email: str,
    timeout: float = ASYNC_TIMEOUT
) -> Dict[str, Any]:
    """Async version of HackCheck email check.
    
    Args:
        email: Validated email address to check.
        timeout: Request timeout in seconds.
        
    Returns:
        Dictionary with breach results.
    """
    url = HACKCHECK_API.format(email=email)
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(
                url,
                headers={"User-Agent": USER_AGENT},
            )
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "HackCheck",
                }
            
            if response.status_code == 429:
                raise RateLimitError("HackCheck")
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list) and len(data) > 0:
                    breaches = []
                    for breach in data:
                        breach_info = BreachInfo(
                            name=breach.get("Title", breach.get("Name", "Unknown")),
                            year=extract_year(breach.get("BreachDate", "")),
                            date=breach.get("BreachDate"),
                            data_classes=breach.get("DataClasses", ["Unknown"]),
                        )
                        breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "HackCheck",
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "HackCheck",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="HackCheck",
                status_code=response.status_code,
            )
            
        except httpx.TimeoutException:
            raise NetworkError("Request timed out", url=url)


async def async_check_email_xposedornot(
    email: str,
    api_key: Optional[str] = None,
    timeout: float = ASYNC_TIMEOUT
) -> Dict[str, Any]:
    """Async version of XposedOrNot email check.
    
    Args:
        email: Validated email address to check.
        api_key: Optional API key.
        timeout: Request timeout in seconds.
        
    Returns:
        Dictionary with breach results.
    """
    url = XPOSEDORNOT_API.format(email=email)
    headers = {"User-Agent": USER_AGENT}
    
    if api_key:
        headers["x-api-key"] = api_key
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot",
                }
            
            if response.status_code == 200:
                data = response.json()
                breaches_data = data.get("breaches") or data.get("ExposedBreaches", {}).get("breaches_details", [])
                
                if breaches_data:
                    breaches = []
                    for item in breaches_data:
                        if isinstance(item, str):
                            breach_info = BreachInfo(name=item)
                        else:
                            breach_info = BreachInfo(
                                name=item.get("breach", item.get("name", "Unknown")),
                                year=extract_year(item.get("xposed_date", "")),
                            )
                        breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "XposedOrNot",
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="XposedOrNot",
                status_code=response.status_code,
            )
            
        except httpx.TimeoutException:
            raise NetworkError("Request timed out", url=url)


class EmailChecker:
    """Advanced email breach checker with multiple API sources.
    
    Provides comprehensive email breach detection with automatic
    fallback between multiple public breach databases.
    
    Example:
        checker = EmailChecker()
        result = checker.check("user@example.com")
        
        # Async usage
        result = await checker.async_check("user@example.com")
    """
    
    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        xposedornot_api_key: Optional[str] = None,
    ):
        """Initialize EmailChecker.
        
        Args:
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            xposedornot_api_key: Optional API key for XposedOrNot.
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.xposedornot_api_key = xposedornot_api_key
        self._last_check_time: Optional[datetime] = None
        self._last_source: Optional[str] = None
    
    def check(self, email: str) -> Dict[str, Any]:
        """Check email for breaches using multiple sources.
        
        Args:
            email: Email address to check.
            
        Returns:
            Dictionary with breach results.
            
        Raises:
            ValidationError: If email is invalid.
            NetworkError: If all API sources fail.
        """
        normalized_email = validate_email_address(email)
        
        try:
            result = check_email_hackcheck(normalized_email, self.timeout)
            self._last_source = "HackCheck"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"HackCheck failed: {e}")
        
        try:
            result = check_email_xposedornot(
                normalized_email,
                api_key=self.xposedornot_api_key,
                timeout=self.timeout,
            )
            self._last_source = "XposedOrNot"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"XposedOrNot failed: {e}")
        
        raise NetworkError("All breach database sources unavailable")
    
    async def async_check(self, email: str) -> Dict[str, Any]:
        """Async check email for breaches.
        
        Args:
            email: Email address to check.
            
        Returns:
            Dictionary with breach results.
        """
        normalized_email = validate_email_address(email)
        
        try:
            result = await async_check_email_hackcheck(normalized_email, self.timeout)
            self._last_source = "HackCheck"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"HackCheck async failed: {e}")
        
        try:
            result = await async_check_email_xposedornot(
                normalized_email,
                api_key=self.xposedornot_api_key,
                timeout=self.timeout,
            )
            self._last_source = "XposedOrNot"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"XposedOrNot async failed: {e}")
        
        raise NetworkError("All breach database sources unavailable")
    
    async def check_multiple(self, emails: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check multiple emails concurrently.
        
        Args:
            emails: List of email addresses to check.
            
        Returns:
            Dictionary mapping email to results.
        """
        results = {}
        tasks = []
        
        for email in emails:
            tasks.append(self._safe_async_check(email))
        
        completed = await asyncio.gather(*tasks)
        
        for email, result in zip(emails, completed):
            results[email] = result
        
        return results
    
    async def _safe_async_check(self, email: str) -> Dict[str, Any]:
        """Safe async check that returns error dict on failure."""
        try:
            return await self.async_check(email)
        except Exception as e:
            return {
                "error": True,
                "message": str(e),
                "email": email,
            }
