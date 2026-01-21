from typing import Dict, Any, List, Optional
from pydantic import BaseModel
import asyncio

class SignalResult(BaseModel):
    type: str
    confidence: float
    query: str

class NHSignal:
    """NH-Signal: Input Classification & Validation."""
    import re
    
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    USERNAME_PATTERN = r'^[a-zA-Z0-9._-]{3,32}$'
    URL_PATTERN = r'^https?://[^\s/$.?#].[^\s]*$'

    def classify(self, query: str) -> SignalResult:
        import re
        query = query.strip()
        if re.match(self.EMAIL_PATTERN, query):
            return SignalResult(type="email", confidence=1.0, query=query)
        if re.match(self.URL_PATTERN, query):
            if any(query.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.webp', '.gif']):
                return SignalResult(type="image", confidence=0.95, query=query)
            return SignalResult(type="url", confidence=0.8, query=query)
        if re.match(self.USERNAME_PATTERN, query):
            return SignalResult(type="username", confidence=0.85, query=query)
        return SignalResult(type="unknown", confidence=0.0, query=query)

class NHChain:
    """NH-Chain: Orchestration Engine for streaming progress."""
    def __init__(self):
        self.signal_processor = NHSignal()

    async def process(self, query: str):
        # 1. Classification
        classification = self.signal_processor.classify(query)
        yield f"event: input_classified\ndata: Input classified as {classification.type}\n\n"
        await asyncio.sleep(0.5)

        # 2. Module Execution
        yield "event: processing\ndata: Querying public datasets\n\n"
        await asyncio.sleep(0.8)
        yield "event: processing\ndata: Aggregating exposure signals\n\n"
        await asyncio.sleep(0.5)

        # 3. Final Verdict
        yield "event: completed\ndata: Finalizing intelligence report\n\n"
