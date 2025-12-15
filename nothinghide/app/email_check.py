"""Email breach checking module.

This module queries public breach databases to check if an email address
has been exposed in known data breaches. Uses lawful, publicly available APIs only.
"""

import httpx
import logging
from typing import Optional

from .config import (
    HACKCHECK_API,
    XPOSEDORNOT_API,
    REQUEST_TIMEOUT,
    USER_AGENT,
    EXIT_NETWORK_ERROR,
)
from .utils import validate_email_address, print_error, logger

logger = logging.getLogger(__name__)


def check_email_hackcheck(email: str) -> dict:
    """Check email against HackCheck API (free, no auth required).
    
    Args:
        email: Validated email address to check.
        
    Returns:
        Dictionary with breach results or error information.
    """
    url = HACKCHECK_API.format(email=email)
    
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
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
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list) and len(data) > 0:
                    breaches = []
                    for breach in data:
                        breach_info = {
                            "name": breach.get("Title", breach.get("Name", "Unknown")),
                            "year": extract_year(breach.get("BreachDate", breach.get("AddedDate", ""))),
                            "data_classes": breach.get("DataClasses", ["Unknown"]),
                        }
                        breaches.append(breach_info)
                    
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
            
            return {
                "error": True,
                "message": f"API returned status {response.status_code}",
                "source": "HackCheck",
            }
            
    except httpx.TimeoutException:
        return {
            "error": True,
            "message": "Request timed out. Please try again.",
            "source": "HackCheck",
        }
    except httpx.RequestError as e:
        logger.warning(f"HackCheck request failed: {e}")
        return {
            "error": True,
            "message": "Network error occurred. Check your connection.",
            "source": "HackCheck",
        }
    except Exception as e:
        logger.error(f"Unexpected error in HackCheck: {e}")
        return {
            "error": True,
            "message": "An unexpected error occurred.",
            "source": "HackCheck",
        }


def check_email_xposedornot(email: str, api_key: Optional[str] = None) -> dict:
    """Check email against XposedOrNot API (backup).
    
    Args:
        email: Validated email address to check.
        api_key: Optional API key for XposedOrNot.
        
    Returns:
        Dictionary with breach results or error information.
    """
    url = XPOSEDORNOT_API.format(email=email)
    headers = {"User-Agent": USER_AGENT}
    
    if api_key:
        headers["x-api-key"] = api_key
    
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            response = client.get(url, headers=headers)
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot",
                }
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("breaches"):
                    breaches = []
                    for breach_name in data.get("breaches", []):
                        breach_info = {
                            "name": breach_name,
                            "year": "Unknown",
                            "data_classes": ["Unknown"],
                        }
                        breaches.append(breach_info)
                    
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
            
            return {
                "error": True,
                "message": f"API returned status {response.status_code}",
                "source": "XposedOrNot",
            }
            
    except httpx.TimeoutException:
        return {
            "error": True,
            "message": "Request timed out. Please try again.",
            "source": "XposedOrNot",
        }
    except httpx.RequestError as e:
        logger.warning(f"XposedOrNot request failed: {e}")
        return {
            "error": True,
            "message": "Network error occurred. Check your connection.",
            "source": "XposedOrNot",
        }
    except Exception as e:
        logger.error(f"Unexpected error in XposedOrNot: {e}")
        return {
            "error": True,
            "message": "An unexpected error occurred.",
            "source": "XposedOrNot",
        }


def check_email(email: str) -> dict:
    """Check email against available breach databases with fallback.
    
    This function tries HackCheck first (no auth required), then falls back
    to XposedOrNot if the primary source fails.
    
    Args:
        email: Email address to check.
        
    Returns:
        Dictionary with breach results.
    """
    is_valid, result = validate_email_address(email)
    if not is_valid:
        return {
            "error": True,
            "message": f"Invalid email format: {result}",
            "validation_error": True,
        }
    
    normalized_email = result
    
    hackcheck_result = check_email_hackcheck(normalized_email)
    if not hackcheck_result.get("error"):
        return hackcheck_result
    
    xposed_result = check_email_xposedornot(normalized_email)
    if not xposed_result.get("error"):
        return xposed_result
    
    return {
        "error": True,
        "message": "Unable to check breach databases. All API sources unavailable.",
        "source": "None",
    }


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
                        year = int(part)
                        if 1990 <= year <= 2030:
                            return str(year)
        
        return "Unknown"
    except Exception:
        return "Unknown"
