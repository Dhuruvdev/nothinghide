import hashlib
import time
from typing import Optional, Dict
from fastapi import Request, Response, HTTPException
from pydantic import BaseModel
import datetime

class SessionMetadata(BaseModel):
    id: str
    user_id: str
    hashed_fingerprint: str
    last_ip: str
    risk_score: int = 0
    expires_at: datetime.datetime

class CookieCookedSystem:
    """
    Cookie Cooked Protection System (Python/FastAPI)
    Prevents, detects, and reacts to cookie hijacking.
    """
    
    def __init__(self, db_session=None):
        self.db = db_session # Placeholder for real DB
        self.risk_threshold_revoke = 70
        self.risk_threshold_stepup = 30

    def generate_fingerprint(self, request: Request) -> str:
        """Creates a privacy-preserving hash of the device fingerprint."""
        user_agent = request.headers.get("user-agent", "")
        accept_lang = request.headers.get("accept-language", "")
        # In a real app, combine more stable entropy sources
        raw_data = f"{user_agent}|{accept_lang}"
        return hashlib.sha256(raw_data.encode()).hexdigest()

    async def check_session(self, request: Request, session_data: Dict) -> Dict:
        """
        Analyzes session for anomalies and updates risk score.
        """
        current_fingerprint = self.generate_fingerprint(request)
        current_ip = request.client.host if request.client else "unknown"
        
        risk_score = 0
        reasons = []

        # 1. Fingerprint Mismatch Detection
        if session_data.get("hashed_fingerprint") != current_fingerprint:
            risk_score += 45
            reasons.append("Device fingerprint mismatch")

        # 2. IP/Network Anomaly (Basic Travel/Proxy Check)
        if session_data.get("last_ip") != current_ip:
            risk_score += 25
            reasons.append("IP address change detected")

        # 3. Behavioral / Rate Logic (Simplified)
        # In production, check request frequency and sequence patterns here
        
        return {
            "score": risk_score,
            "reasons": reasons,
            "action": self._determine_action(risk_score)
        }

    def _determine_action(self, score: int) -> str:
        if score >= self.risk_threshold_revoke:
            return "REVOKE"
        elif score >= self.risk_threshold_stepup:
            return "STEP_UP"
        return "ALLOW"

# Middleware Implementation Example
async def cookie_cooked_middleware(request: Request, call_next):
    # This is a conceptual implementation for FastAPI
    system = CookieCookedSystem()
    session_id = request.cookies.get("session_id")
    
    if session_id:
        # 1. Fetch session from DB (Mocked)
        mock_session = {
            "hashed_fingerprint": "...", 
            "last_ip": "1.2.3.4",
            "risk_score": 0
        }
        
        analysis = await system.check_session(request, mock_session)
        
        if analysis["action"] == "REVOKE":
            response = Response(content="Session revoked for security", status_code=403)
            response.delete_cookie("session_id")
            return response
            
        if analysis["action"] == "STEP_UP":
            # In a real app, you would set a flag or redirect
            pass

    response = await call_next(request)
    return response
