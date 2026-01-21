"""Adaptive rate limiting for multi-source API requests.

Provides intelligent rate limiting that:
- Tracks per-source rate limits
- Automatically backs off on 429 responses
- Distributes requests across sources
- Prevents cascade failures
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class RateLimitState:
    requests_made: int = 0
    window_start: datetime = field(default_factory=datetime.now)
    window_seconds: int = 60
    max_requests_per_window: int = 100
    backoff_until: Optional[datetime] = None
    current_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    
    def can_make_request(self) -> bool:
        now = datetime.now()
        
        if self.backoff_until and now < self.backoff_until:
            return False
        
        if (now - self.window_start).total_seconds() >= self.window_seconds:
            self.requests_made = 0
            self.window_start = now
        
        return self.requests_made < self.max_requests_per_window
    
    def record_request(self):
        self.requests_made += 1
    
    def record_rate_limit(self, retry_after: Optional[int] = None):
        if retry_after:
            self.backoff_until = datetime.now() + timedelta(seconds=retry_after)
            self.current_backoff_seconds = retry_after
        else:
            self.current_backoff_seconds = min(
                self.current_backoff_seconds * 2,
                self.max_backoff_seconds
            )
            self.backoff_until = datetime.now() + timedelta(seconds=self.current_backoff_seconds)
        
        logger.info(f"Rate limited, backing off for {self.current_backoff_seconds}s")
    
    def record_success(self):
        self.current_backoff_seconds = max(1.0, self.current_backoff_seconds * 0.5)
        self.backoff_until = None
    
    def time_until_available(self) -> float:
        if self.backoff_until:
            remaining = (self.backoff_until - datetime.now()).total_seconds()
            if remaining > 0:
                return remaining
        
        if self.requests_made >= self.max_requests_per_window:
            elapsed = (datetime.now() - self.window_start).total_seconds()
            return max(0, self.window_seconds - elapsed)
        
        return 0


class AdaptiveRateLimiter:
    
    def __init__(
        self,
        default_requests_per_minute: int = 60,
        default_window_seconds: int = 60,
        global_max_concurrent: int = 10,
    ):
        self.default_requests_per_minute = default_requests_per_minute
        self.default_window_seconds = default_window_seconds
        self.global_max_concurrent = global_max_concurrent
        
        self._source_limits: Dict[str, RateLimitState] = {}
        self._concurrent_requests: int = 0
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(global_max_concurrent)
    
    def _get_or_create_state(self, source_name: str) -> RateLimitState:
        if source_name not in self._source_limits:
            self._source_limits[source_name] = RateLimitState(
                max_requests_per_window=self.default_requests_per_minute,
                window_seconds=self.default_window_seconds,
            )
        return self._source_limits[source_name]
    
    async def acquire(self, source_name: str) -> bool:
        state = self._get_or_create_state(source_name)
        
        wait_time = state.time_until_available()
        if wait_time > 0:
            logger.debug(f"Waiting {wait_time:.1f}s for {source_name} rate limit")
            await asyncio.sleep(wait_time)
        
        await self._semaphore.acquire()
        
        async with self._lock:
            if state.can_make_request():
                state.record_request()
                self._concurrent_requests += 1
                return True
            else:
                self._semaphore.release()
                return False
    
    def release(self, source_name: str, success: bool = True, rate_limited: bool = False, retry_after: Optional[int] = None):
        state = self._get_or_create_state(source_name)
        
        if rate_limited:
            state.record_rate_limit(retry_after)
        elif success:
            state.record_success()
        
        self._concurrent_requests -= 1
        self._semaphore.release()
    
    def get_available_sources(self, source_names: Set[str]) -> Set[str]:
        available = set()
        for name in source_names:
            state = self._get_or_create_state(name)
            if state.can_make_request():
                available.add(name)
        return available
    
    def get_source_stats(self, source_name: str) -> Dict:
        state = self._get_or_create_state(source_name)
        return {
            "requests_made": state.requests_made,
            "can_request": state.can_make_request(),
            "backoff_seconds": state.current_backoff_seconds,
            "time_until_available": state.time_until_available(),
        }
    
    async def wait_for_any_available(self, source_names: Set[str], timeout: float = 30.0) -> Optional[str]:
        start = time.time()
        
        while time.time() - start < timeout:
            available = self.get_available_sources(source_names)
            if available:
                min_wait = float('inf')
                best_source = None
                for name in available:
                    state = self._get_or_create_state(name)
                    wait = state.time_until_available()
                    if wait < min_wait:
                        min_wait = wait
                        best_source = name
                return best_source
            
            await asyncio.sleep(0.1)
        
        return None


class RetryStrategy:
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        import random
        
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            delay *= (0.5 + random.random())
        
        return delay
    
    def should_retry(self, attempt: int, error: Optional[Exception] = None) -> bool:
        if attempt >= self.max_retries:
            return False
        
        if error:
            error_type = type(error).__name__
            non_retryable = ["ValidationError", "AuthenticationError"]
            if error_type in non_retryable:
                return False
        
        return True
