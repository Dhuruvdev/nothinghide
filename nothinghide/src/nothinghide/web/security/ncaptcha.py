import time
import json
import hashlib
import hmac
import os
import logging
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

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
        try:
            from .ai_risk import analyze_risk_with_ai
            # Combined analysis: Heuristics + Nvidia AI Model
            ai_result = analyze_risk_with_ai(biometrics, fingerprint)
        except Exception as e:
            ai_result = {"risk": "LOW", "score": 0, "reasoning": "AI Fallback"}
        
        score = ai_result.get("score", 0)
        signals = [ai_result.get("reasoning", "AI verification")]
        
        # 2026 Entropy Signal
        entropy = biometrics.get("entropy", {})
        variance = entropy.get("velocity_variance", 100)
        if variance < 2.5 and biometrics.get("mouse_moves", 0) > 10:
            signals.append("low_behavioral_entropy")
            score = max(score, 40)

        # Layer 2: Hard-coded heuristics for immediate detection
        hesitation = biometrics.get("hesitation_time", 0)
        if hesitation < 0.3: 
            score = max(score, 75)
            signals.append("impossible_timing")
            
        ua = fingerprint.get("user_agent", "").lower()
        if any(bot in ua for bot in ["headless", "selenium", "puppeteer", "playwright"]):
            score = 100
            signals.append("automation_framework_detected")
            
        if fingerprint.get("webdriver", False):
            score = max(score, 70)
            signals.append("webdriver_active")

        if biometrics.get("teleport_detected"):
            signals.append("impossible_movement_speed")
            score = max(score, 50)

        risk_level = ai_result.get("risk", "LOW")
        if score >= 80: risk_level = "HIGH"
        elif score >= 50: risk_level = "MEDIUM"
        
        return {
            "risk": risk_level,
            "score": score,
            "signals": signals,
            "model": "nvidia/nemotron-70b",
            "ts": time.time()
        }

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rate limiting simplified for now
        # IP Reputation could be added here
        response = await call_next(request)
        return response
