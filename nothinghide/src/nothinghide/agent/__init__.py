"""Advanced Agent System for Intelligent Breach Detection.

This module provides an intelligent, multi-source agent architecture
for comprehensive email breach detection with advanced capabilities:

- Multi-source parallel intelligence gathering
- Intelligent retry with exponential backoff
- Smart rate limiting and source switching
- Data correlation and deduplication engine
- Domain reputation analysis
- Paste site monitoring
"""

from .orchestrator import BreachIntelligenceAgent, AgentConfig
from .sources import DataSource, SourceResult, SourceStatus
from .correlation import CorrelationEngine, CorrelatedResult
from .rate_limiter import AdaptiveRateLimiter
from .domain import DomainChecker, PasteMonitor, ThreatIntelligence, DomainInfo

__all__ = [
    "BreachIntelligenceAgent",
    "AgentConfig",
    "DataSource",
    "SourceResult",
    "SourceStatus",
    "CorrelationEngine",
    "CorrelatedResult",
    "AdaptiveRateLimiter",
    "DomainChecker",
    "PasteMonitor",
    "ThreatIntelligence",
    "DomainInfo",
]
