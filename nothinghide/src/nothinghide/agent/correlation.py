"""Data correlation engine for cross-referencing breach results.

Provides intelligent aggregation and correlation of breach data
from multiple sources with:
- Deduplication by breach name/date
- Confidence scoring based on source agreement
- Data enrichment from multiple sources
- Unified breach timeline
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
import re

from .sources import SourceResult

logger = logging.getLogger(__name__)


def normalize_breach_name(name: str) -> str:
    if not name:
        return ""
    normalized = name.lower().strip()
    normalized = re.sub(r'[^a-z0-9]', '', normalized)
    return normalized


def extract_year(date_str: Optional[str]) -> Optional[int]:
    if not date_str:
        return None
    
    try:
        match = re.search(r'(19|20)\d{2}', str(date_str))
        if match:
            return int(match.group())
    except:
        pass
    return None


@dataclass
class CorrelatedBreach:
    name: str
    normalized_name: str
    date: Optional[str] = None
    year: Optional[int] = None
    data_classes: List[str] = field(default_factory=list)
    description: Optional[str] = None
    records_exposed: Optional[int] = None
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def merge_from(self, other: Dict[str, Any], source: str):
        if source not in self.sources:
            self.sources.append(source)
        
        if not self.date and other.get("date"):
            self.date = other["date"]
            self.year = extract_year(other["date"])
        
        if other.get("data_classes"):
            for dc in other["data_classes"]:
                if dc not in self.data_classes:
                    self.data_classes.append(dc)
        
        if not self.description and other.get("description"):
            self.description = other["description"]
        
        if not self.records_exposed and other.get("records_exposed"):
            self.records_exposed = other["records_exposed"]
        
        self.confidence = min(1.0, len(self.sources) / 3)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "date": self.date,
            "year": self.year,
            "data_classes": self.data_classes,
            "description": self.description,
            "records_exposed": self.records_exposed,
            "sources": self.sources,
            "confidence": self.confidence,
        }


@dataclass
class CorrelatedResult:
    email: str
    breached: bool
    breach_count: int
    breaches: List[CorrelatedBreach]
    sources_queried: List[str]
    sources_succeeded: List[str]
    sources_failed: List[str]
    total_response_time_ms: float
    average_confidence: float
    risk_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "breached": self.breached,
            "breach_count": self.breach_count,
            "breaches": [b.to_dict() for b in self.breaches],
            "sources_queried": self.sources_queried,
            "sources_succeeded": self.sources_succeeded,
            "sources_failed": self.sources_failed,
            "total_response_time_ms": self.total_response_time_ms,
            "average_confidence": self.average_confidence,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp.isoformat(),
        }


class CorrelationEngine:
    
    def __init__(
        self,
        min_confidence_threshold: float = 0.3,
        deduplicate_threshold: float = 0.8,
    ):
        self.min_confidence_threshold = min_confidence_threshold
        self.deduplicate_threshold = deduplicate_threshold
        self._known_aliases: Dict[str, str] = {
            "adobe": "adobe",
            "adobesystems": "adobe",
            "linkedin": "linkedin",
            "linkedincom": "linkedin",
            "dropbox": "dropbox",
            "dropboxcom": "dropbox",
        }
    
    def correlate(self, results: List[SourceResult], email: str) -> CorrelatedResult:
        correlated_breaches: Dict[str, CorrelatedBreach] = {}
        sources_queried = []
        sources_succeeded = []
        sources_failed = []
        total_response_time = 0.0
        
        for result in results:
            sources_queried.append(result.source_name)
            total_response_time += result.response_time_ms
            
            if result.success:
                sources_succeeded.append(result.source_name)
                
                for breach in result.breaches:
                    name = breach.get("name", "Unknown")
                    normalized = self._normalize_with_aliases(name)
                    
                    if normalized in correlated_breaches:
                        correlated_breaches[normalized].merge_from(breach, result.source_name)
                    else:
                        cb = CorrelatedBreach(
                            name=name,
                            normalized_name=normalized,
                            date=breach.get("date"),
                            year=extract_year(breach.get("date")),
                            data_classes=breach.get("data_classes", ["Unknown"]),
                            description=breach.get("description"),
                            records_exposed=breach.get("records_exposed"),
                            sources=[result.source_name],
                            confidence=0.33,
                        )
                        correlated_breaches[normalized] = cb
            else:
                sources_failed.append(result.source_name)
        
        breaches_list = list(correlated_breaches.values())
        
        breaches_list.sort(key=lambda b: (b.year or 0, b.name), reverse=True)
        
        average_confidence = 0.0
        if breaches_list:
            average_confidence = sum(b.confidence for b in breaches_list) / len(breaches_list)
        
        is_breached = len(breaches_list) > 0
        
        risk_score = self._calculate_risk_score(breaches_list, sources_succeeded)
        
        return CorrelatedResult(
            email=email,
            breached=is_breached,
            breach_count=len(breaches_list),
            breaches=breaches_list,
            sources_queried=sources_queried,
            sources_succeeded=sources_succeeded,
            sources_failed=sources_failed,
            total_response_time_ms=total_response_time,
            average_confidence=average_confidence,
            risk_score=risk_score,
        )
    
    def _normalize_with_aliases(self, name: str) -> str:
        normalized = normalize_breach_name(name)
        return self._known_aliases.get(normalized, normalized)
    
    def correlate_identity(self, correlated_result: CorrelatedResult, password_results: Optional[Dict] = None) -> Dict[str, Any]:
        """Perform advanced identity correlation between email breaches and password exposure."""
        correlations = []
        risk_score = self._calculate_risk_score(correlated_result.breaches, correlated_result.sources_succeeded)
        
        # Extract all categories
        categories = set()
        for breach in correlated_result.breaches:
            if breach.data_classes:
                for dc in breach.data_classes:
                    categories.add(dc.lower())
        
        # Cross-reference with password exposure
        if "passwords" in categories and password_results and password_results.get('exposed'):
            correlations.append("CRITICAL: Password exposed in known breaches and matches current exposure check.")
            risk_score = min(100.0, risk_score + 40.0)
            
        if any(c in categories for c in ["banking", "financial", "credit cards"]):
            correlations.append("HIGH: Financial data exposure detected in identity cluster.")
            risk_score = min(100.0, risk_score + 20.0)
            
        # Identity risk scoring based on breach age
        current_year = datetime.now().year
        for breach in correlated_result.breaches:
            if breach.year and current_year - breach.year <= 1:
                correlations.append(f"URGENT: Recent data breach detected ({breach.name}, {breach.year}).")
                risk_score = min(100.0, risk_score + 15.0)

        return {
            "correlations": correlations,
            "risk_score": risk_score,
            "categories": list(categories),
            "identity_verified": True if correlated_result.breach_count > 0 else False
        }

    def _calculate_risk_score(
        self,
        breaches: List[CorrelatedBreach],
        sources_succeeded: List[str]
    ) -> float:
        if not breaches:
            return 0.0
        
        score = 0.0
        
        score += min(len(breaches) * 5, 40)
        
        current_year = datetime.now().year
        recent_breaches = sum(1 for b in breaches if b.year and current_year - b.year <= 2)
        score += recent_breaches * 15
        
        sensitive_data = {"password", "passwords", "financial", "credit card", "ssn", "health"}
        for breach in breaches:
            for dc in breach.data_classes:
                if dc.lower() in sensitive_data:
                    score += 10
                    break
        
        high_confidence = sum(1 for b in breaches if b.confidence >= 0.5)
        score += high_confidence * 5
        
        return min(100.0, score)


class IntelligenceAggregator:
    
    def __init__(self):
        self.correlation_engine = CorrelationEngine()
        self._domain_cache: Dict[str, Dict[str, Any]] = {}
    
    def aggregate_intelligence(
        self,
        email_results: List[SourceResult],
        domain_info: Optional[Dict[str, Any]] = None,
        paste_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        email = ""
        if email_results:
            for r in email_results:
                if r.raw_data and "email" in str(r.raw_data):
                    break
        
        correlated = self.correlation_engine.correlate(email_results, email)
        
        intelligence = {
            "breach_data": correlated.to_dict(),
            "domain_intelligence": domain_info or {},
            "paste_intelligence": paste_info or {},
            "threat_indicators": self._extract_threat_indicators(correlated),
            "recommendations": self._generate_recommendations(correlated),
        }
        
        return intelligence
    
    def _extract_threat_indicators(self, result: CorrelatedResult) -> List[Dict[str, Any]]:
        indicators = []
        
        if result.breach_count > 5:
            indicators.append({
                "type": "high_exposure",
                "severity": "high",
                "description": f"Email found in {result.breach_count} breaches",
            })
        
        current_year = datetime.now().year
        for breach in result.breaches:
            if breach.year and current_year - breach.year <= 1:
                indicators.append({
                    "type": "recent_breach",
                    "severity": "critical",
                    "description": f"Recent breach: {breach.name} ({breach.year})",
                    "breach_name": breach.name,
                })
        
        sensitive_types = {"password", "passwords", "financial", "credit card"}
        for breach in result.breaches:
            for dc in breach.data_classes:
                if dc.lower() in sensitive_types:
                    indicators.append({
                        "type": "sensitive_data",
                        "severity": "high",
                        "description": f"Sensitive data exposed: {dc}",
                        "breach_name": breach.name,
                    })
                    break
        
        return indicators
    
    def _generate_recommendations(self, result: CorrelatedResult) -> List[str]:
        recommendations = []
        
        if result.breached:
            recommendations.append("Change passwords for all accounts associated with this email")
            recommendations.append("Enable two-factor authentication where available")
            
            password_exposed = any(
                "password" in str(b.data_classes).lower()
                for b in result.breaches
            )
            if password_exposed:
                recommendations.append("URGENT: Your password was exposed. Change it immediately on all sites")
            
            if result.breach_count > 3:
                recommendations.append("Consider using a password manager for unique passwords")
                recommendations.append("Monitor your accounts for suspicious activity")
            
            if result.risk_score >= 50:
                recommendations.append("Consider credit monitoring if financial data was exposed")
                recommendations.append("Be vigilant for phishing attempts targeting this email")
        else:
            recommendations.append("No breaches found - continue practicing good security hygiene")
            recommendations.append("Regularly check for new breaches")
        
        return recommendations
