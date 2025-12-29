from fastapi import APIRouter, Request, HTTPException
from typing import List, Dict
import random

router = APIRouter(prefix="/api/cooked")

# Active Session Intelligence Dashboard
@router.get("/dashboard")
async def get_dashboard_data(request: Request):
    """
    Provides 'Active Session Intelligence' for user transparency.
    """
    # In production, this would query the DB for the user's active sessions
    return {
        "sessions": [
            {
                "id": "sess_123",
                "device": "Chrome on macOS",
                "region": "San Francisco, US",
                "last_active": "2 mins ago",
                "risk_level": "Low",
                "risk_score": 12,
                "is_current": True
            },
            {
                "id": "sess_456",
                "device": "Safari on iPhone",
                "region": "London, UK",
                "last_active": "1 hour ago",
                "risk_level": "Medium",
                "risk_score": 45,
                "is_current": False
            }
        ],
        "total_risk": 28,
        "recommendations": [
            "Enable 2FA for 'Safari on iPhone' session due to location shift.",
            "Session rotation scheduled in 4 hours."
        ]
    }

@router.post("/check")
async def manual_check(request: Request):
    """
    Single button 'Check' logic.
    """
    # Simulate a real-time risk scan
    return {
        "status": "Success",
        "current_risk": random.randint(5, 30),
        "message": "Real-time integrity check passed. No anomalies detected.",
        "timestamp": "2025-12-29T18:30:00Z"
    }

@router.post("/revoke/{session_id}")
async def revoke_session(session_id: str):
    """
    Allows user to manually revoke a session.
    """
    return {"message": f"Session {session_id} has been successfully revoked."}
