import time
import json
import hashlib
import hmac
import os
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

SECRET_KEY = os.getenv("SECURITY_SECRET_KEY", "nothinghide-super-secret-key-1337")

class NCaptcha:
    """Advanced security engine for anti-bot and anti-DDoS protection."""
    
    @staticmethod
    def generate_token(data: Dict[str, Any], expiry: int = 3600) -> str:
        payload = {
            "data": data,
            "exp": int(time.time()) + expiry
        }
        payload_json = json.dumps(payload, sort_keys=True)
        signature = hmac.new(SECRET_KEY.encode(), payload_json.encode(), hashlib.sha256).hexdigest()
        return f"{payload_json}.{signature}"

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            payload_json, signature = parts
            expected_signature = hmac.new(SECRET_KEY.encode(), payload_json.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                return None
            payload = json.loads(payload_json)
            if payload["exp"] < time.time():
                return None
            return payload["data"]
        except Exception:
            return None

    @staticmethod
    def calculate_risk(biometrics: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        signals = []
        
        # 1. Advanced Timing Analysis
        hesitation = biometrics.get("hesitation_time", 0)
        if hesitation < 0.3: 
            score += 25
            signals.append("impossible_timing")
            
        # 2. Behavioral Velocity & Jitter
        mouse_moves = biometrics.get("mouse_moves", 0)
        if mouse_moves > 0 and mouse_moves < 10:
            score += 15
            signals.append("low_entropy_movement")
            
        # 3. Environment Integrity
        ua = fingerprint.get("user_agent", "").lower()
        if any(bot in ua for bot in ["headless", "selenium", "puppeteer", "playwright"]):
            score += 80
            signals.append("automation_framework_detected")
            
        if fingerprint.get("webdriver", False):
            score += 70
            signals.append("webdriver_active")

        # 4. Consistency Checks
        if fingerprint.get("timezone_mismatch", False):
            score += 30
            signals.append("network_location_inconsistency")

        # Result mapping
        risk_level = "LOW"
        if score >= 65: risk_level = "HIGH"
        elif score >= 35: risk_level = "MEDIUM"
        
        return {
            "risk": risk_level,
            "score": score,
            "signals": signals,
            "ts": time.time()
        }

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rate limiting simplified for now
        # IP Reputation could be added here
        response = await call_next(request)
        return response
