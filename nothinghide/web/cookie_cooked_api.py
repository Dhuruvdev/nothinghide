from fastapi import APIRouter, Request, HTTPException
import datetime
from typing import List, Dict
import random
from .cookie_cooked import CookieCookedSystem

router = APIRouter(prefix="/api/cooked")
system = CookieCookedSystem()

TRACKED_SITES = []

@router.post("/track")
async def track_cookie_usage(data: Dict):
    """
    Advanced Algorithm: Cross-domain cookie usage tracking.
    Stores metadata about which websites are using the user's cookies.
    """
    site = data.get("site")
    if site and site not in [s['url'] for s in TRACKED_SITES]:
        TRACKED_SITES.append({
            "url": site,
            "detected_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk": "High" if not data.get("data", {}).get("securityFlags", {}).get("httpOnly") else "Low"
        })
    return {"status": "indexed"}

@router.get("/dashboard")
async def get_dashboard_data(request: Request):
    """
    Enhanced Dashboard: Displays all websites where cookies are used.
    """
    current_ip = request.client.host if request.client else "127.0.0.1"
    intel = await system.get_ip_intel(current_ip)
    
    return {
        "sessions": [
            {
                "id": "current",
                "device": request.headers.get("user-agent", "Unknown Device"),
                "region": f"{intel.get('city', 'Unknown City')}, {intel.get('asn', 'Local Network')}",
                "last_active": "Just now",
                "risk_score": 15,
                "is_current": True
            }
        ],
        "tracked_websites": TRACKED_SITES,
        "total_sites_monitored": len(TRACKED_SITES),
        "recommendations": [
            "Review tracking cookies from third-party domains.",
            "Use the 'Revoke' feature for insecure session identifiers."
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
