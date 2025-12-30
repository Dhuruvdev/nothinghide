import hashlib
import time
import hmac
import ipaddress
import asyncio
from typing import Optional, Dict, List
from fastapi import Request, Response, HTTPException
from pydantic import BaseModel
import datetime
import httpx

class CookieCookedSystem:
    """
    Advanced Session Intelligence & Protection System
    Authentic detection using cryptographic verification and behavioral scoring.
    """
    
    def __init__(self, secret_key: str = "cooked_secret_2025"):
        self.secret_key = secret_key
        self.risk_threshold_revoke = 75
        self.risk_threshold_stepup = 40

    def get_client_fingerprint(self, request: Request) -> str:
        """
        Generates a high-entropy session fingerprint.
        Uses non-sensitive headers to maintain privacy.
        """
        headers = request.headers
        fingerprint_data = "|".join([
            headers.get("user-agent", "unknown"),
            headers.get("accept-language", "unknown"),
            headers.get("sec-ch-ua-platform", "unknown"),
            headers.get("sec-ch-ua", "unknown")
        ])
        return hmac.new(
            self.secret_key.encode(),
            fingerprint_data.encode(),
            hashlib.sha256
        ).hexdigest()

    async def get_ip_intel(self, ip: str) -> Dict:
        """
        Fetches authentic IP and ASN intelligence.
        In production, this would use Greip, Silent Push, or IP-API.
        """
        if ip in ["127.0.0.1", "localhost", "unknown"]:
            return {"asn": "AS0", "org": "Local Network", "reputation": "benign"}
            
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,as,proxy,hosting")
                if resp.status_code == 200:
                    data = resp.json()
                    is_proxy = data.get("proxy", False)
                    is_hosting = data.get("hosting", False)
                    reputation = "malicious" if is_proxy or is_hosting else "benign"
                    return {
                        "asn": data.get("as", "unknown"),
                        "city": data.get("city", "unknown"),
                        "reputation": reputation,
                        "is_proxy": is_proxy
                    }
        except:
            pass
        return {"asn": "unknown", "reputation": "unknown"}

    async def analyze_risk(self, request: Request, session_data: Dict) -> Dict:
        """
        Performs multi-vector risk analysis including Geo-velocity, ASN reputation,
        and device-bound session binding indicators.
        """
        current_ip = request.client.host if request.client else "127.0.0.1"
        current_fingerprint = self.get_client_fingerprint(request)
        
        score = 0
        indicators = []

        # 1. Cryptographic Fingerprint Check
        if session_data.get("hashed_fingerprint") != current_fingerprint:
            score += 55  # Increased weight for device mismatch
            indicators.append("Device signature mismatch (potential session hijacking)")

        # 2. IP Reputation & Network Logic
        intel = await self.get_ip_intel(current_ip)
        if intel.get("reputation") == "malicious":
            score += 60
            indicators.append(f"High-risk network detected ({intel.get('asn')})")
        
        if session_data.get("last_ip") != current_ip:
            try:
                old_net = ipaddress.ip_network(f"{session_data['last_ip']}/24", strict=False)
                new_ip = ipaddress.ip_address(current_ip)
                if new_ip not in old_net:
                    score += 40 # Impossible travel / large network jump
                    indicators.append("Significant network location shift detected")
            except:
                score += 20

        # 3. Behavioral Anomaly (Request Rate & Timing)
        last_request = session_data.get("last_request_time", 0)
        now = time.time()
        if last_request > 0:
            time_diff = now - last_request
            if time_diff < 0.1: # Tighter threshold for automated tools
                score += 35
                indicators.append("Sub-second automated request pattern (Infostealer behavior)")

        # 4. Browser Environment Integrity
        # Detect Headless or modified environments
        ua = request.headers.get("user-agent", "").lower()
        if "headless" in ua or "selenium" in ua or "puppeteer" in ua:
            score += 80
            indicators.append("Automated browser environment detected")

        # 5. Cookie Consent Pattern Analysis
        # Detect high-risk 'Accept All' behavioral patterns often used in automated harvesting
        if session_data.get("cookie_consent_behavior") == "aggressive_accept":
            score += 25
            indicators.append("Aggressive cookie acceptance pattern (Risk: Data harvesting)")

        return {
            "score": min(100, score),
            "indicators": indicators,
            "intel": intel,
            "action": self._determine_action(score)
        }

    def _determine_action(self, score: int) -> str:
        if score >= self.risk_threshold_revoke: return "REVOKE"
        if score >= self.risk_threshold_stepup: return "STEP_UP"
        return "ALLOW"

async def cookie_cooked_middleware(request: Request, call_next):
    system = CookieCookedSystem()
    session_id = request.cookies.get("session_id")
    
    if session_id:
        # Fetching current session state (Mocked for speed)
        mock_session = {
            "hashed_fingerprint": "...", 
            "last_ip": "1.2.3.4",
            "last_request_time": request.app.state.last_req if hasattr(request.app.state, 'last_req') else 0
        }
        
        analysis = await system.analyze_risk(request, mock_session)
        request.app.state.last_req = time.time()
        
        if analysis["action"] == "REVOKE":
            return Response(content="Security Alert: Session terminated due to high risk score.", status_code=403)
            
    return await call_next(request)
