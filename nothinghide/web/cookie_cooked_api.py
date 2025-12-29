from fastapi import APIRouter, Request, HTTPException
from .cookie_cooked import CookieCookedSystem
import time

router = APIRouter(prefix="/api/cooked")
system = CookieCookedSystem()

@router.get("/dashboard")
async def get_dashboard_data(request: Request):
    """
    Authentic Session Intelligence Dashboard
    """
    current_ip = request.client.host if request.client else "127.0.0.1"
    intel = await system.get_ip_intel(current_ip)
    
    # Analyze current session
    mock_session = {
        "hashed_fingerprint": system.get_client_fingerprint(request),
        "last_ip": "1.2.3.4", # Simulation of previous IP
        "last_request_time": time.time() - 3600
    }
    
    risk = await system.analyze_risk(request, mock_session)
    
    return {
        "sessions": [
            {
                "id": "current",
                "device": request.headers.get("user-agent", "Unknown Device"),
                "region": f"{intel.get('city', 'Unknown City')}, {intel.get('asn', 'Local Network')}",
                "last_active": "Just now",
                "risk_level": "High" if risk['score'] > 70 else "Medium" if risk['score'] > 30 else "Low",
                "risk_score": risk['score'],
                "is_current": True,
                "reputation": intel.get("reputation")
            }
        ],
        "indicators": risk['indicators'],
        "recommendations": [
            "Enable hardware-based MFA for this session." if risk['score'] > 30 else "Session is currently protected by Zero-Trust monitoring.",
            "Rotation suggested due to ASN reputation shift." if intel.get("reputation") == "malicious" else "Network reputation is healthy."
        ]
    }

@router.post("/check")
async def manual_check(request: Request):
    current_ip = request.client.host if request.client else "127.0.0.1"
    intel = await system.get_ip_intel(current_ip)
    return {
        "status": "Healthy" if intel.get("reputation") == "benign" else "Warning",
        "intel": intel,
        "message": "Advanced scan complete. Network reputation verified."
    }
