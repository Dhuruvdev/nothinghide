"""Custom exceptions for NothingHide library."""

from typing import Optional


class NothingHideError(Exception):
    """Base exception for all NothingHide errors."""
    
    def __init__(self, message: str, details: Optional[str] = None):
        self.message = message
        self.details = details
        super().__init__(self.message)
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


class ValidationError(NothingHideError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None):
        self.field = field
        super().__init__(message, details=f"field={field}" if field else None)


class NetworkError(NothingHideError):
    """Raised when network operations fail."""
    
    def __init__(
        self, 
        message: str, 
        url: Optional[str] = None,
        status_code: Optional[int] = None
    ):
        self.url = url
        self.status_code = status_code
        details = []
        if url:
            details.append(f"url={url}")
        if status_code:
            details.append(f"status={status_code}")
        super().__init__(message, details=", ".join(details) if details else None)


class APIError(NothingHideError):
    """Raised when API returns an error response."""
    
    def __init__(
        self,
        message: str,
        api_name: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None
    ):
        self.api_name = api_name
        self.status_code = status_code
        self.response_body = response_body
        details = f"api={api_name}"
        if status_code:
            details += f", status={status_code}"
        super().__init__(message, details=details)


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded."""
    
    def __init__(
        self,
        api_name: str,
        retry_after: Optional[int] = None
    ):
        self.retry_after = retry_after
        message = f"Rate limit exceeded for {api_name}"
        if retry_after:
            message += f". Retry after {retry_after} seconds."
        super().__init__(message, api_name=api_name)


class TimeoutError(NetworkError):
    """Raised when a request times out."""
    
    def __init__(self, url: Optional[str] = None, timeout: Optional[float] = None):
        self.timeout = timeout
        message = "Request timed out"
        if timeout:
            message += f" after {timeout}s"
        super().__init__(message, url=url)
