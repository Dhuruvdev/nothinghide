"""Multi-source data gathering with intelligent source management.

Provides abstracted data sources for breach intelligence with:
- Unified interface for different APIs
- Source health tracking
- Automatic failover
- Priority-based source selection
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any, Set, Callable

import httpx

from ..config import USER_AGENT, REQUEST_TIMEOUT, ASYNC_TIMEOUT
from ..exceptions import NetworkError, APIError, RateLimitError

logger = logging.getLogger(__name__)


class SourceStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass
class SourceResult:
    source_name: str
    breached: bool
    breaches: List[Dict[str, Any]] = field(default_factory=list)
    breach_count: int = 0
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    response_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class SourceHealth:
    status: SourceStatus = SourceStatus.UNKNOWN
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    rate_limit_reset: Optional[datetime] = None
    avg_response_time_ms: float = 0.0
    success_rate: float = 1.0
    total_requests: int = 0
    successful_requests: int = 0
    
    def record_success(self, response_time_ms: float):
        self.last_success = datetime.now()
        self.consecutive_failures = 0
        self.total_requests += 1
        self.successful_requests += 1
        self._update_avg_response_time(response_time_ms)
        self._update_success_rate()
        self._update_status()
    
    def record_failure(self, is_rate_limit: bool = False, retry_after: Optional[int] = None):
        self.last_failure = datetime.now()
        self.consecutive_failures += 1
        self.total_requests += 1
        self._update_success_rate()
        
        if is_rate_limit:
            if retry_after:
                self.rate_limit_reset = datetime.now() + timedelta(seconds=retry_after)
            else:
                self.rate_limit_reset = datetime.now() + timedelta(seconds=60)
            self.status = SourceStatus.RATE_LIMITED
        else:
            self._update_status()
    
    def _update_avg_response_time(self, new_time: float):
        if self.avg_response_time_ms == 0:
            self.avg_response_time_ms = new_time
        else:
            self.avg_response_time_ms = (self.avg_response_time_ms * 0.8) + (new_time * 0.2)
    
    def _update_success_rate(self):
        if self.total_requests > 0:
            self.success_rate = self.successful_requests / self.total_requests
    
    def _update_status(self):
        if self.rate_limit_reset and datetime.now() < self.rate_limit_reset:
            self.status = SourceStatus.RATE_LIMITED
        elif self.consecutive_failures >= 5:
            self.status = SourceStatus.UNAVAILABLE
        elif self.consecutive_failures >= 2 or self.success_rate < 0.7:
            self.status = SourceStatus.DEGRADED
        else:
            self.status = SourceStatus.HEALTHY
    
    def is_available(self) -> bool:
        if self.status == SourceStatus.RATE_LIMITED:
            if self.rate_limit_reset and datetime.now() >= self.rate_limit_reset:
                self.status = SourceStatus.HEALTHY
                self.rate_limit_reset = None
                return True
            return False
        return self.status not in [SourceStatus.UNAVAILABLE]


class DataSource(ABC):
    
    def __init__(
        self,
        name: str,
        priority: int = 10,
        timeout: float = REQUEST_TIMEOUT,
        requires_api_key: bool = False,
        api_key: Optional[str] = None,
    ):
        self.name = name
        self.priority = priority
        self.timeout = timeout
        self.requires_api_key = requires_api_key
        self.api_key = api_key
        self.health = SourceHealth()
    
    @abstractmethod
    async def fetch(self, email: str) -> SourceResult:
        pass
    
    def is_available(self) -> bool:
        if self.requires_api_key and not self.api_key:
            return False
        return self.health.is_available()
    
    def get_priority_score(self) -> float:
        base_score = self.priority
        if self.health.status == SourceStatus.HEALTHY:
            base_score *= 1.0
        elif self.health.status == SourceStatus.DEGRADED:
            base_score *= 0.5
        else:
            base_score *= 0.1
        
        response_penalty = min(self.health.avg_response_time_ms / 5000, 0.5)
        base_score *= (1 - response_penalty)
        
        base_score *= self.health.success_rate
        
        return base_score


class LeakCheckSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        super().__init__(
            name="LeakCheck",
            priority=100,
            timeout=timeout,
            requires_api_key=False,
        )
        self.api_url = "https://leakcheck.io/api/public?check={email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json",
                    },
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 404:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    self.health.record_success(response_time)
                    
                    if data.get("success") and data.get("found", 0) > 0:
                        breaches = []
                        seen: Set[str] = set()
                        
                        for result in data.get("result", []):
                            for source in result.get("sources", []):
                                source_name = str(source).lower()
                                if source_name not in seen:
                                    seen.add(source_name)
                                    breaches.append({
                                        "name": source,
                                        "date": result.get("last_breach"),
                                        "data_classes": ["Credentials", "Email"],
                                        "source_api": self.name,
                                    })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data=data,
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data,
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"LeakCheck error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


class HackCheckSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        super().__init__(
            name="HackCheck",
            priority=90,
            timeout=timeout,
            requires_api_key=False,
        )
        self.api_url = "https://hackcheck.woventeams.com/api/v4/breachedaccount/{email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 404:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    self.health.record_success(response_time)
                    
                    if isinstance(data, list) and len(data) > 0:
                        breaches = []
                        for breach in data:
                            breaches.append({
                                "name": breach.get("Title", breach.get("Name", "Unknown")),
                                "date": breach.get("BreachDate"),
                                "data_classes": breach.get("DataClasses", ["Unknown"]),
                                "source_api": self.name,
                            })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data={"breaches": data},
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data if isinstance(data, dict) else {},
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"HackCheck error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


class XposedOrNotSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT, api_key: Optional[str] = None):
        super().__init__(
            name="XposedOrNot",
            priority=95,
            timeout=timeout,
            requires_api_key=False,
            api_key=api_key,
        )
        self.api_url = "https://api.xposedornot.com/v1/check-email/{email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 404:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    self.health.record_success(response_time)
                    
                    breaches_data = data.get("breaches") or data.get("ExposedBreaches", {}).get("breaches_details", [])
                    
                    if breaches_data:
                        breaches = []
                        for item in breaches_data:
                            if isinstance(item, str):
                                breaches.append({
                                    "name": item,
                                    "source_api": self.name,
                                })
                            else:
                                breaches.append({
                                    "name": item.get("breach", item.get("name", "Unknown")),
                                    "date": item.get("xposed_date"),
                                    "data_classes": item.get("xposed_data", ["Unknown"]),
                                    "source_api": self.name,
                                })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data=data,
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data,
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"XposedOrNot error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


class XposedOrNotAnalyticsSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        super().__init__(
            name="XposedOrNot Analytics",
            priority=85,
            timeout=timeout,
            requires_api_key=False,
        )
        self.api_url = "https://api.xposedornot.com/v1/breach-analytics/{email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 404:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    self.health.record_success(response_time)
                    
                    exposed_breaches = data.get("ExposedBreaches", {})
                    breaches_details = exposed_breaches.get("breaches_details", [])
                    
                    if breaches_details:
                        breaches = []
                        for item in breaches_details:
                            data_classes = item.get("xposed_data", "").split(";") if item.get("xposed_data") else ["Unknown"]
                            data_classes = [d.strip() for d in data_classes if d.strip()]
                            
                            breaches.append({
                                "name": item.get("breach", "Unknown"),
                                "date": item.get("xposed_date"),
                                "data_classes": data_classes if data_classes else ["Unknown"],
                                "description": item.get("details"),
                                "records_exposed": item.get("xposed_records"),
                                "source_api": self.name,
                            })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data=data,
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data,
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"XposedOrNot Analytics error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


class EmailRepSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        super().__init__(
            name="EmailRep",
            priority=75,
            timeout=timeout,
            requires_api_key=False,
        )
        self.api_url = "https://emailrep.io/{email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json",
                    },
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 404:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    self.health.record_success(response_time)
                    
                    details = data.get("details", {})
                    credentials_leaked = details.get("credentials_leaked", False)
                    data_breach = details.get("data_breach", False)
                    
                    if credentials_leaked or data_breach:
                        breaches = []
                        if credentials_leaked:
                            breaches.append({
                                "name": "Credential Leak Detected",
                                "data_classes": ["Credentials"],
                                "source_api": self.name,
                                "reputation": data.get("reputation", "unknown"),
                            })
                        if data_breach:
                            breaches.append({
                                "name": "Data Breach Detected",
                                "data_classes": ["Email", "Personal Data"],
                                "source_api": self.name,
                                "reputation": data.get("reputation", "unknown"),
                            })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data=data,
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data,
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"EmailRep error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


class DeXposeSource(DataSource):
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        super().__init__(
            name="DeXpose",
            priority=70,
            timeout=timeout,
            requires_api_key=False,
        )
        self.api_url = "https://www.dexpose.io/api/check/{email}"
    
    async def fetch(self, email: str) -> SourceResult:
        url = self.api_url.format(email=email)
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json",
                    },
                )
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 429:
                    self.health.record_failure(is_rate_limit=True)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        error="Rate limited",
                        response_time_ms=response_time,
                    )
                
                if response.status_code in [404, 400]:
                    self.health.record_success(response_time)
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        response_time_ms=response_time,
                    )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                    except:
                        self.health.record_success(response_time)
                        return SourceResult(
                            source_name=self.name,
                            breached=False,
                            breach_count=0,
                            breaches=[],
                            response_time_ms=response_time,
                        )
                    
                    self.health.record_success(response_time)
                    
                    is_exposed = data.get("exposed", False) or data.get("breached", False)
                    
                    if is_exposed:
                        breaches = []
                        breach_list = data.get("breaches", data.get("results", []))
                        
                        for breach in breach_list:
                            if isinstance(breach, str):
                                breaches.append({
                                    "name": breach,
                                    "source_api": self.name,
                                })
                            else:
                                breaches.append({
                                    "name": breach.get("name", breach.get("source", "Unknown")),
                                    "date": breach.get("date"),
                                    "data_classes": breach.get("data_types", ["Unknown"]),
                                    "source_api": self.name,
                                })
                        
                        if not breaches:
                            breaches.append({
                                "name": "DeXpose Exposure Detected",
                                "source_api": self.name,
                            })
                        
                        return SourceResult(
                            source_name=self.name,
                            breached=True,
                            breaches=breaches,
                            breach_count=len(breaches),
                            raw_data=data,
                            response_time_ms=response_time,
                        )
                    
                    return SourceResult(
                        source_name=self.name,
                        breached=False,
                        breach_count=0,
                        breaches=[],
                        raw_data=data,
                        response_time_ms=response_time,
                    )
                
                self.health.record_failure()
                return SourceResult(
                    source_name=self.name,
                    breached=False,
                    error=f"API returned status {response.status_code}",
                    response_time_ms=response_time,
                )
                
        except httpx.TimeoutException:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            return SourceResult(
                source_name=self.name,
                breached=False,
                error="Request timed out",
                response_time_ms=response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.warning(f"DeXpose error: {e}")
            return SourceResult(
                source_name=self.name,
                breached=False,
                error=str(e),
                response_time_ms=response_time,
            )


def get_all_sources(
    timeout: float = ASYNC_TIMEOUT,
    xposedornot_api_key: Optional[str] = None,
) -> List[DataSource]:
    return [
        LeakCheckSource(timeout=timeout),
        HackCheckSource(timeout=timeout),
        XposedOrNotSource(timeout=timeout, api_key=xposedornot_api_key),
        XposedOrNotAnalyticsSource(timeout=timeout),
        EmailRepSource(timeout=timeout),
        DeXposeSource(timeout=timeout),
    ]
