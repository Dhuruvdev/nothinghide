"""Advanced email breach checking with multiple FREE API sources.

This module provides comprehensive email breach detection using multiple
FREE public breach databases with automatic fallback and aggregation.

Supported FREE APIs (no API key required):
- LeakCheck Public API (7B+ records)
- HackCheck API
- XposedOrNot API
- XposedOrNot Breach Analytics
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from datetime import datetime

import httpx
from email_validator import validate_email, EmailNotValidError

from .config import (
    HACKCHECK_API,
    XPOSEDORNOT_API,
    XPOSEDORNOT_BREACH_ANALYTICS,
    LEAKCHECK_PUBLIC_API,
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
    source_api: str = "Unknown"
    records_exposed: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "year": self.year,
            "date": self.date,
            "data_classes": self.data_classes,
            "description": self.description,
            "is_verified": self.is_verified,
            "source_api": self.source_api,
            "records_exposed": self.records_exposed,
        }


def validate_email_address(email: str) -> str:
    """Validate and normalize an email address."""
    try:
        result = validate_email(email, check_deliverability=False)
        return result.normalized
    except EmailNotValidError as e:
        raise ValidationError(str(e), field="email")


def extract_year(date_string: str) -> str:
    """Extract year from various date formats."""
    if not date_string:
        return "Unknown"
    
    try:
        date_string = str(date_string)
        
        if len(date_string) >= 4:
            year = date_string[:4]
            if year.isdigit() and 1990 <= int(year) <= 2030:
                return year
        
        for sep in ["-", "/", ".", "_"]:
            if sep in date_string:
                parts = date_string.split(sep)
                for part in parts:
                    if len(part) == 4 and part.isdigit():
                        year_val = int(part)
                        if 1990 <= year_val <= 2030:
                            return str(year_val)
                    elif len(part) == 2 and part.isdigit():
                        year_val = int(part)
                        if year_val >= 90:
                            return f"19{part}"
                        elif year_val <= 30:
                            return f"20{part}"
        
        return "Unknown"
    except Exception:
        return "Unknown"


def check_email_leakcheck(email: str, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
    """Check email against LeakCheck Public API (FREE, no key required).
    
    LeakCheck has 7B+ records and provides breach sources with dates.
    """
    url = LEAKCHECK_PUBLIC_API.format(email=email)
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "LeakCheck",
                }
            
            if response.status_code == 429:
                raise RateLimitError("LeakCheck")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("success") and data.get("found", 0) > 0:
                    breaches = []
                    seen_breaches: Set[str] = set()
                    
                    for result in data.get("result", []):
                        sources = result.get("sources", [])
                        last_breach = result.get("last_breach", "")
                        
                        for source in sources:
                            source_name = source if isinstance(source, str) else str(source)
                            
                            if source_name.lower() in seen_breaches:
                                continue
                            seen_breaches.add(source_name.lower())
                            
                            breach_info = BreachInfo(
                                name=source_name,
                                year=extract_year(last_breach),
                                date=last_breach if last_breach else None,
                                data_classes=["Credentials", "Email"],
                                source_api="LeakCheck",
                            )
                            breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "LeakCheck",
                        "total_records": data.get("found", len(breaches)),
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "LeakCheck",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="LeakCheck",
                status_code=response.status_code,
            )
            
    except (RateLimitError, APIError):
        raise
    except httpx.TimeoutException:
        raise NetworkError("Request timed out", url=url)
    except httpx.RequestError as e:
        logger.warning(f"LeakCheck request failed: {e}")
        raise NetworkError("Network error occurred", url=url)
    except Exception as e:
        logger.warning(f"LeakCheck unexpected error: {e}")
        raise APIError(str(e), api_name="LeakCheck")


def check_email_hackcheck(email: str, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
    """Check email against HackCheck API (FREE)."""
    url = HACKCHECK_API.format(email=email)
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
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
                            source_api="HackCheck",
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
    """Check email against XposedOrNot API (FREE)."""
    url = XPOSEDORNOT_API.format(email=email)
    headers = {"User-Agent": USER_AGENT}
    
    if api_key:
        headers["x-api-key"] = api_key
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
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
                                breach_info = BreachInfo(name=item, source_api="XposedOrNot")
                            else:
                                breach_info = BreachInfo(
                                    name=item.get("breach", item.get("name", "Unknown")),
                                    year=extract_year(item.get("xposed_date", "")),
                                    date=item.get("xposed_date"),
                                    data_classes=item.get("xposed_data", ["Unknown"]),
                                    source_api="XposedOrNot",
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


def check_email_xposedornot_analytics(
    email: str,
    timeout: float = REQUEST_TIMEOUT
) -> Dict[str, Any]:
    """Check email against XposedOrNot Breach Analytics API (FREE).
    
    This endpoint provides more detailed breach analytics.
    """
    url = XPOSEDORNOT_BREACH_ANALYTICS.format(email=email)
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(
                url,
                headers={"User-Agent": USER_AGENT},
            )
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot Analytics",
                }
            
            if response.status_code == 429:
                raise RateLimitError("XposedOrNot Analytics")
            
            if response.status_code == 200:
                data = response.json()
                
                exposed_breaches = data.get("ExposedBreaches", {})
                breaches_details = exposed_breaches.get("breaches_details", [])
                
                if breaches_details:
                    breaches = []
                    
                    for item in breaches_details:
                        data_classes = item.get("xposed_data", "").split(";") if item.get("xposed_data") else ["Unknown"]
                        data_classes = [d.strip() for d in data_classes if d.strip()]
                        
                        breach_info = BreachInfo(
                            name=item.get("breach", "Unknown"),
                            year=extract_year(item.get("xposed_date", "")),
                            date=item.get("xposed_date"),
                            data_classes=data_classes if data_classes else ["Unknown"],
                            description=item.get("details"),
                            source_api="XposedOrNot Analytics",
                            records_exposed=item.get("xposed_records"),
                        )
                        breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "XposedOrNot Analytics",
                        "risk_score": data.get("BreachMetrics", {}).get("risk", {}).get("risk_score"),
                        "paste_count": exposed_breaches.get("pastes_count", 0),
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "XposedOrNot Analytics",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="XposedOrNot Analytics",
                status_code=response.status_code,
            )
            
    except (RateLimitError, APIError):
        raise
    except httpx.TimeoutException:
        raise NetworkError("Request timed out", url=url)
    except httpx.RequestError as e:
        logger.warning(f"XposedOrNot Analytics request failed: {e}")
        raise NetworkError("Network error occurred", url=url)


async def async_check_email_leakcheck(
    email: str,
    timeout: float = ASYNC_TIMEOUT
) -> Dict[str, Any]:
    """Async version of LeakCheck email check."""
    url = LEAKCHECK_PUBLIC_API.format(email=email)
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            response = await client.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                },
            )
            
            if response.status_code == 404:
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "LeakCheck",
                }
            
            if response.status_code == 429:
                raise RateLimitError("LeakCheck")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("success") and data.get("found", 0) > 0:
                    breaches = []
                    seen_breaches: Set[str] = set()
                    
                    for result in data.get("result", []):
                        sources = result.get("sources", [])
                        last_breach = result.get("last_breach", "")
                        
                        for source in sources:
                            source_name = source if isinstance(source, str) else str(source)
                            
                            if source_name.lower() in seen_breaches:
                                continue
                            seen_breaches.add(source_name.lower())
                            
                            breach_info = BreachInfo(
                                name=source_name,
                                year=extract_year(last_breach),
                                date=last_breach if last_breach else None,
                                source_api="LeakCheck",
                            )
                            breaches.append(breach_info.to_dict())
                    
                    return {
                        "breached": True,
                        "breaches": breaches,
                        "breach_count": len(breaches),
                        "source": "LeakCheck",
                    }
                
                return {
                    "breached": False,
                    "breaches": [],
                    "breach_count": 0,
                    "source": "LeakCheck",
                }
            
            raise APIError(
                f"API returned status {response.status_code}",
                api_name="LeakCheck",
                status_code=response.status_code,
            )
            
        except httpx.TimeoutException:
            raise NetworkError("Request timed out", url=url)


async def async_check_email_hackcheck(
    email: str,
    timeout: float = ASYNC_TIMEOUT
) -> Dict[str, Any]:
    """Async version of HackCheck email check."""
    url = HACKCHECK_API.format(email=email)
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
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
                            source_api="HackCheck",
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
    """Async version of XposedOrNot email check."""
    url = XPOSEDORNOT_API.format(email=email)
    headers = {"User-Agent": USER_AGENT}
    
    if api_key:
        headers["x-api-key"] = api_key
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
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
                            breach_info = BreachInfo(name=item, source_api="XposedOrNot")
                        else:
                            breach_info = BreachInfo(
                                name=item.get("breach", item.get("name", "Unknown")),
                                year=extract_year(item.get("xposed_date", "")),
                                source_api="XposedOrNot",
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


def merge_breach_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge results from multiple API sources, deduplicating breaches."""
    all_breaches = []
    seen_breaches: Set[str] = set()
    sources_used = []
    total_records = 0
    
    for result in results:
        if result.get("breached"):
            source = result.get("source", "Unknown")
            if source not in sources_used:
                sources_used.append(source)
            
            total_records += result.get("total_records", result.get("breach_count", 0))
            
            for breach in result.get("breaches", []):
                breach_key = breach.get("name", "").lower().strip()
                
                if breach_key and breach_key not in seen_breaches:
                    seen_breaches.add(breach_key)
                    all_breaches.append(breach)
    
    if all_breaches:
        all_breaches.sort(key=lambda x: (x.get("year", "0000") if x.get("year") != "Unknown" else "0000"), reverse=True)
    
    return {
        "breached": len(all_breaches) > 0,
        "breaches": all_breaches,
        "breach_count": len(all_breaches),
        "source": " + ".join(sources_used) if sources_used else "Multiple APIs",
        "total_records": total_records,
    }


class EmailChecker:
    """Advanced email breach checker with multiple FREE API sources.
    
    Queries multiple free breach databases simultaneously and
    aggregates results for comprehensive exposure detection.
    
    FREE APIs used (no API key required):
    - LeakCheck Public API (7B+ records)
    - HackCheck API
    - XposedOrNot API
    - XposedOrNot Breach Analytics
    
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
        aggregate_all: bool = True,
    ):
        """Initialize EmailChecker.
        
        Args:
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            xposedornot_api_key: Optional API key for XposedOrNot.
            aggregate_all: If True, query all APIs and merge results.
                          If False, stop at first successful result.
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.xposedornot_api_key = xposedornot_api_key
        self.aggregate_all = aggregate_all
        self._last_check_time: Optional[datetime] = None
        self._last_source: Optional[str] = None
    
    def check(self, email: str) -> Dict[str, Any]:
        """Check email for breaches using multiple FREE sources.
        
        Args:
            email: Email address to check.
            
        Returns:
            Dictionary with aggregated breach results.
            
        Raises:
            ValidationError: If email is invalid.
            NetworkError: If all API sources fail.
        """
        normalized_email = validate_email_address(email)
        
        if self.aggregate_all:
            return self._check_all_sources(normalized_email)
        else:
            return self._check_with_fallback(normalized_email)
    
    def _check_all_sources(self, email: str) -> Dict[str, Any]:
        """Query all sources and merge results."""
        results = []
        errors = []
        
        check_functions = [
            ("LeakCheck", lambda: check_email_leakcheck(email, self.timeout)),
            ("HackCheck", lambda: check_email_hackcheck(email, self.timeout)),
            ("XposedOrNot", lambda: check_email_xposedornot(email, self.xposedornot_api_key, self.timeout)),
            ("XposedOrNot Analytics", lambda: check_email_xposedornot_analytics(email, self.timeout)),
        ]
        
        for name, func in check_functions:
            try:
                result = func()
                results.append(result)
                logger.info(f"{name}: {'Breached' if result.get('breached') else 'Clear'}")
            except (NetworkError, APIError, RateLimitError) as e:
                logger.warning(f"{name} failed: {e}")
                errors.append(f"{name}: {str(e)}")
            except Exception as e:
                logger.warning(f"{name} unexpected error: {e}")
                errors.append(f"{name}: {str(e)}")
        
        if results:
            merged = merge_breach_results(results)
            self._last_source = merged.get("source")
            self._last_check_time = datetime.now()
            return merged
        
        raise NetworkError(f"All breach database sources failed: {'; '.join(errors)}")
    
    def _check_with_fallback(self, email: str) -> Dict[str, Any]:
        """Check sources in order, stopping at first success."""
        try:
            result = check_email_leakcheck(email, self.timeout)
            self._last_source = "LeakCheck"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"LeakCheck failed: {e}")
        
        try:
            result = check_email_hackcheck(email, self.timeout)
            self._last_source = "HackCheck"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"HackCheck failed: {e}")
        
        try:
            result = check_email_xposedornot(
                email,
                api_key=self.xposedornot_api_key,
                timeout=self.timeout,
            )
            self._last_source = "XposedOrNot"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"XposedOrNot failed: {e}")
        
        try:
            result = check_email_xposedornot_analytics(email, self.timeout)
            self._last_source = "XposedOrNot Analytics"
            self._last_check_time = datetime.now()
            return result
        except (NetworkError, APIError, RateLimitError) as e:
            logger.warning(f"XposedOrNot Analytics failed: {e}")
        
        raise NetworkError("All breach database sources unavailable")
    
    async def async_check(self, email: str) -> Dict[str, Any]:
        """Async check email for breaches using all sources concurrently.
        
        Args:
            email: Email address to check.
            
        Returns:
            Dictionary with aggregated breach results.
        """
        normalized_email = validate_email_address(email)
        
        tasks = [
            self._safe_async_call(async_check_email_leakcheck(normalized_email, self.timeout)),
            self._safe_async_call(async_check_email_hackcheck(normalized_email, self.timeout)),
            self._safe_async_call(async_check_email_xposedornot(
                normalized_email, self.xposedornot_api_key, self.timeout
            )),
        ]
        
        results = await asyncio.gather(*tasks)
        valid_results = [r for r in results if r is not None]
        
        if valid_results:
            merged = merge_breach_results(valid_results)
            self._last_source = merged.get("source")
            self._last_check_time = datetime.now()
            return merged
        
        raise NetworkError("All breach database sources unavailable")
    
    async def _safe_async_call(self, coro) -> Optional[Dict[str, Any]]:
        """Safely execute async call, returning None on error."""
        try:
            return await coro
        except Exception as e:
            logger.warning(f"Async check failed: {e}")
            return None
    
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
