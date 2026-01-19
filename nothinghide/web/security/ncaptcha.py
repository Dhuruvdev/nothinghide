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
    def calculate_risk(biometrics: Dict[str, Any], fingerprint: Dict[str, Any]) -> str:
        score = 0
        
        # 1. Behavior checks
        if biometrics.get("mouse_moves", 0) < 5: score += 20
        if biometrics.get("scroll_events", 0) < 2: score += 10
        if biometrics.get("paste_detected", False): score += 30
        if biometrics.get("hesitation_time", 0) < 0.5: score += 15
        
        # 2. Fingerprint checks
        if fingerprint.get("timezone_mismatch", False): score += 25
        if "headless" in fingerprint.get("user_agent", "").lower(): score += 50
        if not fingerprint.get("webgl_renderer"): score += 20
        
        if score >= 60: return "HIGH"
        if score >= 30: return "MEDIUM"
        return "LOW"

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rate limiting simplified for now
        # IP Reputation could be added here
        response = await call_next(request)
        return response
