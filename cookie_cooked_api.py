from fastapi import APIRouter, Request, Depends
from cookie_cooked import CookieCookedSystem

router = APIRouter()
protection = CookieCookedSystem()

@router.get("/api/protection/status")
async def get_protection_status(request: Request):
    """
    Returns the Active Session Intelligence for the user dashboard.
    """
    # Mock data - in production, fetch from DB
    current_fingerprint = protection.generate_fingerprint(request)
    
    return {
        "active_sessions": [
            {
                "device": "Primary Browser",
                "location": "Detected via IP",
                "last_active": "Just now",
                "risk_level": "Low",
                "risk_score": 12,
                "is_current": True
            }
        ],
        "system_status": "Active",
        "protection_enabled": True
    }

@router.post("/api/protection/check")
async def manual_check(request: Request):
    """
    The 'Check' button logic.
    """
    # Simulate a deep scan
    return {
        "status": "Healthy",
        "score": 5,
        "message": "No session anomalies detected in the last 24 hours."
    }
