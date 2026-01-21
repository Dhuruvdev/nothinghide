from typing import Dict, Any, Optional
import re
from pydantic import BaseModel

class SignalResult(BaseModel):
    type: str
    confidence: float
    query: str

class NHSignal:
    """NH-Signal: Input Classification & Validation."""
    
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    USERNAME_PATTERN = r'^[a-zA-Z0-9._-]{3,32}$'
    URL_PATTERN = r'^https?://[^\s/$.?#].[^\s]*$'

    def classify(self, query: str) -> SignalResult:
        query = query.strip()
        
        # Check Email
        if re.match(self.EMAIL_PATTERN, query):
            return SignalResult(type="email", confidence=1.0, query=query)
            
        # Check Image URL
        if re.match(self.URL_PATTERN, query):
            if any(query.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.webp', '.gif']):
                return SignalResult(type="image", confidence=0.95, query=query)
            return SignalResult(type="url", confidence=0.8, query=query)
            
        # Check Username
        if re.match(self.USERNAME_PATTERN, query):
            return SignalResult(type="username", confidence=0.85, query=query)
            
        return SignalResult(type="unknown", confidence=0.0, query=query)
