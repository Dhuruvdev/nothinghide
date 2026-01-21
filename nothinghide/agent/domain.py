"""Domain reputation and intelligence gathering.

Provides domain-level threat intelligence including:
- MX record validation
- Domain age estimation
- Reputation scoring
- Associated breach history
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
import socket
import re

import httpx

from ..config import USER_AGENT, ASYNC_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class DomainInfo:
    domain: str
    valid: bool = False
    mx_records: List[str] = field(default_factory=list)
    has_email_service: bool = False
    is_disposable: bool = False
    is_free_provider: bool = False
    reputation_score: float = 0.0
    risk_indicators: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "valid": self.valid,
            "mx_records": self.mx_records,
            "has_email_service": self.has_email_service,
            "is_disposable": self.is_disposable,
            "is_free_provider": self.is_free_provider,
            "reputation_score": self.reputation_score,
            "risk_indicators": self.risk_indicators,
            "checked_at": self.checked_at.isoformat(),
        }


DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "guerrillamail.com", "mailinator.com",
    "throwaway.email", "temp-mail.org", "fakeinbox.com", "getnada.com",
    "maildrop.cc", "dispostable.com", "mailnesia.com", "mintemail.com",
    "yopmail.com", "trashmail.com", "sharklasers.com", "spam4.me",
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com", "zoho.com", "gmx.com",
    "yandex.com", "live.com", "msn.com", "me.com", "inbox.com",
}


def extract_domain(email: str) -> Optional[str]:
    if "@" not in email:
        return None
    return email.split("@")[-1].lower().strip()


class DomainChecker:
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        self.timeout = timeout
    
    async def check_domain(self, email_or_domain: str) -> DomainInfo:
        if "@" in email_or_domain:
            domain = extract_domain(email_or_domain)
        else:
            domain = email_or_domain.lower().strip()
        
        if not domain:
            return DomainInfo(domain=email_or_domain, valid=False)
        
        info = DomainInfo(domain=domain)
        
        info.is_disposable = domain in DISPOSABLE_DOMAINS
        info.is_free_provider = domain in FREE_EMAIL_PROVIDERS
        
        try:
            mx_records = await self._get_mx_records(domain)
            info.mx_records = mx_records
            info.has_email_service = len(mx_records) > 0
            info.valid = len(mx_records) > 0
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            info.valid = await self._check_domain_exists(domain)
        
        info.reputation_score = self._calculate_reputation(info)
        info.risk_indicators = self._identify_risks(info)
        
        return info
    
    async def _get_mx_records(self, domain: str) -> List[str]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            answers = resolver.resolve(domain, 'MX')
            return [str(rdata.exchange).rstrip('.') for rdata in answers]
        except ImportError:
            return await self._fallback_mx_check(domain)
        except Exception:
            return []
    
    async def _fallback_mx_check(self, domain: str) -> List[str]:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname(domain)
            )
            return [domain] if result else []
        except:
            return []
    
    async def _check_domain_exists(self, domain: str) -> bool:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname(domain)
            )
            return result is not None
        except:
            return False
    
    def _calculate_reputation(self, info: DomainInfo) -> float:
        score = 50.0
        
        if info.is_disposable:
            score -= 40
        
        if info.is_free_provider:
            score -= 5
        
        if info.has_email_service:
            score += 20
        
        if len(info.mx_records) > 1:
            score += 10
        
        return max(0, min(100, score))
    
    def _identify_risks(self, info: DomainInfo) -> List[str]:
        risks = []
        
        if info.is_disposable:
            risks.append("DISPOSABLE_EMAIL: Temporary email domain detected")
        
        if not info.has_email_service:
            risks.append("NO_MX_RECORDS: Domain cannot receive email")
        
        if info.reputation_score < 30:
            risks.append("LOW_REPUTATION: Domain has poor reputation score")
        
        return risks


class PasteMonitor:
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        self.timeout = timeout
    
    async def check_paste_exposure(self, email: str) -> Dict[str, Any]:
        result = {
            "email": email,
            "pastes_found": 0,
            "paste_sources": [],
            "last_paste_date": None,
            "checked_at": datetime.now().isoformat(),
        }
        
        try:
            xon_result = await self._check_xposedornot_pastes(email)
            if xon_result:
                result["pastes_found"] = xon_result.get("pastes_count", 0)
                result["paste_sources"] = xon_result.get("paste_sources", [])
        except Exception as e:
            logger.warning(f"Paste check failed: {e}")
        
        return result
    
    async def _check_xposedornot_pastes(self, email: str) -> Optional[Dict[str, Any]]:
        url = f"https://api.xposedornot.com/v1/paste/{email}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                )
                
                if response.status_code == 200:
                    data = response.json()
                    paste_summary = data.get("PasteSummary", {})
                    
                    return {
                        "pastes_count": paste_summary.get("count", 0),
                        "paste_sources": paste_summary.get("sites", []),
                    }
                
                return None
                
        except Exception as e:
            logger.warning(f"XposedOrNot paste check error: {e}")
            return None


class ThreatIntelligence:
    
    def __init__(self, timeout: float = ASYNC_TIMEOUT):
        self.timeout = timeout
        self.domain_checker = DomainChecker(timeout)
        self.paste_monitor = PasteMonitor(timeout)
    
    async def gather_intelligence(
        self,
        email: str,
        include_domain: bool = True,
        include_pastes: bool = True,
    ) -> Dict[str, Any]:
        intelligence: Dict[str, Any] = {
            "email": email,
            "gathered_at": datetime.now().isoformat(),
        }
        
        tasks = []
        
        if include_domain:
            tasks.append(("domain", self.domain_checker.check_domain(email)))
        
        if include_pastes:
            tasks.append(("pastes", self.paste_monitor.check_paste_exposure(email)))
        
        if tasks:
            results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
            
            for i, (name, _) in enumerate(tasks):
                result = results[i]
                if isinstance(result, BaseException):
                    intelligence[name] = {"error": str(result)}
                elif isinstance(result, DomainInfo):
                    intelligence[name] = result.to_dict()
                elif isinstance(result, dict):
                    intelligence[name] = result
                else:
                    intelligence[name] = {"data": str(result)}
        
        intelligence["threat_score"] = self._calculate_threat_score(intelligence)
        
        return intelligence
    
    def _calculate_threat_score(self, intelligence: Dict[str, Any]) -> float:
        score = 0.0
        
        domain_info = intelligence.get("domain", {})
        if isinstance(domain_info, dict):
            if domain_info.get("is_disposable"):
                score += 30
            
            reputation = domain_info.get("reputation_score", 50)
            score += (50 - reputation) * 0.5
        
        paste_info = intelligence.get("pastes", {})
        if isinstance(paste_info, dict):
            pastes_found = paste_info.get("pastes_found", 0)
            score += min(pastes_found * 5, 30)
        
        return min(100, score)
