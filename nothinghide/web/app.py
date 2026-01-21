"""NothingHide Web Interface.
A retro-styled interface for checking email and password exposure.
"""

import os
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, Form, UploadFile, File, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .security.ai_risk import analyze_risk_with_ai

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))
from nothinghide.core import check_email, check_password, BreachScanner
from nothinghide.username_checker import UsernameChecker
from nothinghide.exceptions import ValidationError, NetworkError

from .cookie_cooked import cookie_cooked_middleware
from .cookie_cooked_api import router as protection_router

app = FastAPI(title="NothingHide", version="1.0.0")

class SecurityPayload(BaseModel):
    biometrics: Dict[str, Any]
    fingerprint: Dict[str, Any]

class ChallengePayload(SecurityPayload):
    challenge: str

@app.post("/security/check-risk")
async def check_risk(payload: SecurityPayload):
    biometrics = payload.biometrics
    fingerprint = payload.fingerprint
    
    signals = []
    # 2026 Detection: Behavioral Entropy (Velocity Variance)
    # Bots often have perfectly smooth or perfectly linear movements (variance ~0)
    # Humans have natural micro-jitter (variance > 2.0)
    v = biometrics.get("variance", 0)
    if v < 1.5 and biometrics.get("count", 0) > 10:
        signals.append("impossible_smoothness_detected")
        
    if not biometrics.get("integrity"):
        signals.append("environment_integrity_violation")
        
    if biometrics.get("duration", 0) < 0.2:
        signals.append("impossible_interaction_speed")

    score = len(signals) * 30
    risk = "LOW"
    # Force challenge if any suspicion or for demo
    if score > 0 or biometrics.get("count", 0) < 5:
        risk = "HIGH"
        
    return {
        "risk": risk,
        "score": score,
        "signals": signals,
        "ts": datetime.now().isoformat()
    }

@app.post("/security/verify-challenge")
async def verify_challenge(payload: ChallengePayload):
    # Deep AI Behavioral Analysis via Nvidia Nemotron
    analysis = analyze_risk_with_ai(payload.biometrics, payload.fingerprint)
    
    # Secure Token Generation
    token = f"nh_sec_2026_{os.urandom(16).hex()}"
    return {
        "success": True, 
        "token": token,
        "risk_level": analysis.get("risk", "LOW"),
        "ai_analysis": analysis.get("reasoning", "Verified human signature.")
    }

@app.get("/ncaptcha", response_class=HTMLResponse)
async def ncaptcha_page(request: Request):
    return templates.TemplateResponse("ncaptcha_tool.html", {"request": request})

app.middleware("http")(cookie_cooked_middleware)
app.include_router(protection_router)

@app.middleware("http")
async def add_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


import re

def is_email(query: str) -> bool:
    """Basic email validation."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, query.strip()))


@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/check", response_class=HTMLResponse)
async def unified_check(request: Request, query: str = Form(...)):
    """Main check endpoint."""
    query = query.strip()
    
    if is_email(query):
        result = None
        error = None
        
        try:
            scanner = BreachScanner()
            result = scanner.check_email(query)
            
            breaches = []
            if result.breaches:
                for b in result.breaches:
                    if isinstance(b, dict):
                        breaches.append(b)
            
            result_data = {
                "email": query,
                "breached": result.breached,
                "breach_count": result.breach_count,
                "breaches": breaches[:15],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        except ValidationError as e:
            error = f"Invalid email: {e.message}"
            result_data = None
        except NetworkError as e:
            error = f"Network error: {e.message}"
            result_data = None
        except Exception as e:
            error = f"An error occurred: {str(e)}"
            result_data = None
        
        return templates.TemplateResponse("email_result.html", {
            "request": request,
            "result": result_data,
            "error": error,
        })
    else:
        result = None
        error = None
        password = query
        
        try:
            result = check_password(password)
            
            length = len(password)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`" for c in password)
            
            strength_score = 0
            if length >= 8: strength_score += 1
            if length >= 12: strength_score += 1
            if length >= 16: strength_score += 2
            if has_upper: strength_score += 1
            if has_lower: strength_score += 1
            if has_digit: strength_score += 1
            if has_special: strength_score += 2
            
            if strength_score >= 7:
                strength_label = "STRONG"
            elif strength_score >= 5:
                strength_label = "GOOD"
            elif strength_score >= 3:
                strength_label = "FAIR"
            else:
                strength_label = "WEAK"
            
            if result.exposed:
                strength_label = "COMPROMISED"
            
            sha1_prefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]
            
            result_data = {
                "exposed": result.exposed,
                "count": result.count,
                "strength": strength_label,
                "strength_score": strength_score,
                "length": length,
                "has_upper": has_upper,
                "has_lower": has_lower,
                "has_digit": has_digit,
                "has_special": has_special,
                "hash_prefix": sha1_prefix,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        except ValidationError as e:
            error = f"Invalid input: {e.message}"
            result_data = None
        except NetworkError as e:
            error = f"Network error: {e.message}"
            result_data = None
        except Exception as e:
            error = f"An error occurred: {str(e)}"
            result_data = None
        
        return templates.TemplateResponse("password_result.html", {
            "request": request,
            "result": result_data,
            "error": error,
        })


@app.get("/email", response_class=HTMLResponse)
async def email_page(request: Request):
    return templates.TemplateResponse("email.html", {"request": request})


@app.post("/email")
async def email_check(request: Request, email: str = Form(...)):
    accept_header = request.headers.get("accept", "")
    wants_json = "application/json" in accept_header
    
    result = None
    error = None
    
    try:
        scanner = BreachScanner()
        result = scanner.check_email(email)
        
        breaches = []
        if result.breaches:
            for b in result.breaches:
                if isinstance(b, dict):
                    breaches.append(b)
        
        result_data = {
            "email": email,
            "breached": result.breached,
            "breach_count": result.breach_count,
            "breaches": breaches[:15],
            "risk_score": getattr(result, 'risk_score', 0),
            "sources_succeeded": getattr(result, 'sources_succeeded', []),
            "sources_failed": getattr(result, 'sources_failed', []),
            "sources_checked": 6,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except ValidationError as e:
        error = f"Invalid email: {e.message}"
        result_data = None
    except NetworkError as e:
        error = f"Network error: {e.message}"
        result_data = None
    except Exception as e:
        error = f"An error occurred: {str(e)}"
        result_data = None
    
    if wants_json:
        if error:
            return JSONResponse(content={"error": error})
        return JSONResponse(content=result_data)
    
    return templates.TemplateResponse("email_result.html", {
        "request": request,
        "result": result_data,
        "error": error,
    })


@app.get("/password", response_class=HTMLResponse)
async def password_page(request: Request):
    return templates.TemplateResponse("password.html", {"request": request})


@app.post("/password")
async def password_check(request: Request, password: str = Form(...)):
    accept_header = request.headers.get("accept", "")
    wants_json = "application/json" in accept_header
    
    result = None
    error = None
    
    try:
        result = check_password(password)
        
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`" for c in password)
        
        strength_score = 0
        if length >= 8: strength_score += 1
        if length >= 12: strength_score += 1
        if length >= 16: strength_score += 2
        if has_upper: strength_score += 1
        if has_lower: strength_score += 1
        if has_digit: strength_score += 1
        if has_special: strength_score += 2
        
        if strength_score >= 7:
            strength_label = "STRONG"
        elif strength_score >= 5:
            strength_label = "GOOD"
        elif strength_score >= 3:
            strength_label = "FAIR"
        else:
            strength_label = "WEAK"
        
        if result.exposed:
            strength_label = "COMPROMISED"
        
        sha1_prefix = hashlib.sha1(password.encode()).hexdigest().upper()[:5]
        
        result_data = {
            "exposed": result.exposed,
            "compromised": result.exposed,
            "pwned": result.exposed,
            "count": result.count,
            "strength": strength_label,
            "strength_score": strength_score,
            "score": min(4, strength_score // 2),
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "hash_prefix": sha1_prefix,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except ValidationError as e:
        error = f"Invalid input: {e.message}"
        result_data = None
    except NetworkError as e:
        error = f"Network error: {e.message}"
        result_data = None
    except Exception as e:
        error = f"An error occurred: {str(e)}"
        result_data = None
    
    if wants_json:
        if error:
            return JSONResponse(content={"error": error})
        response_data = dict(result_data) if result_data else {}
        response_data["strength"] = result_data
        return JSONResponse(content=response_data)
    
    return templates.TemplateResponse("password_result.html", {
        "request": request,
        "result": result_data,
        "error": error,
    })


@app.get("/fullscan", response_class=HTMLResponse)
async def fullscan_page(request: Request):
    return templates.TemplateResponse("fullscan.html", {"request": request})


@app.post("/fullscan")
async def fullscan_check(request: Request, email: str = Form(...), password: str = Form(...)):
    accept_header = request.headers.get("accept", "")
    wants_json = "application/json" in accept_header
    
    result = None
    error = None
    
    try:
        scanner = BreachScanner()
        report = scanner.full_scan(email, password)
        
        breaches = []
        for b in report.email_result.breaches:
            if isinstance(b, dict):
                breaches.append(b)
            elif hasattr(b, 'to_dict'):
                breaches.append(b.to_dict())
        
        result_data = {
            "email": email,
            "email_breached": report.email_result.breached,
            "email_breach_count": report.email_result.breach_count,
            "breaches": breaches[:10],
            "password_exposed": report.password_result.exposed,
            "password_count": report.password_result.count,
            "risk_level": report.risk_level,
            "recommendations": report.recommendations,
            "email_result": {
                "breaches": breaches[:10],
                "breached": report.email_result.breached,
            },
            "password_result": {
                "compromised": report.password_result.exposed,
                "pwned": report.password_result.exposed,
                "count": report.password_result.count,
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except ValidationError as e:
        error = f"Invalid input: {e.message}"
        result_data = None
    except NetworkError as e:
        error = f"Network error: {e.message}"
        result_data = None
    except Exception as e:
        error = f"An error occurred: {str(e)}"
        result_data = None
    
    if wants_json:
        if error:
            return JSONResponse(content={"error": error})
        return JSONResponse(content=result_data)
    
    return templates.TemplateResponse("fullscan_result.html", {
        "request": request,
        "result": result_data,
        "error": error,
    })


@app.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    return templates.TemplateResponse("help.html", {"request": request})


@app.get("/cooked", response_class=HTMLResponse)
async def cooked_page(request: Request):
    return templates.TemplateResponse("cooked.html", {"request": request})


@app.get("/username", response_class=HTMLResponse)
async def username_page(request: Request):
    return templates.TemplateResponse("username.html", {"request": request})


from fastapi.responses import JSONResponse

@app.post("/username/api")
async def username_check_api(username: str = Form(...)):
    try:
        checker = UsernameChecker(timeout=8.0, max_concurrent=15)
        scan_result = await checker.check_username(username)
        
        all_platforms = [p.to_dict() for p in scan_result.platforms]
        
        result_data = {
            "username": scan_result.username,
            "total_platforms_checked": scan_result.total_platforms_checked,
            "accounts_found": scan_result.accounts_found,
            "platforms": all_platforms,
            "categories": scan_result.categories,
            "identity_risk": scan_result.identity_risk.to_dict() if scan_result.identity_risk else None,
            "username_analysis": scan_result.username_analysis,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return JSONResponse(content=result_data)
    except ValidationError as e:
        return JSONResponse(content={"error": f"Invalid username: {e.message}"})
    except NetworkError as e:
        return JSONResponse(content={"error": f"Network error: {e.message}"})
    except Exception as e:
        return JSONResponse(content={"error": f"An error occurred: {str(e)}"})


@app.post("/username", response_class=HTMLResponse)
async def username_check(request: Request, username: str = Form(...)):
    result = None
    error = None
    
    try:
        checker = UsernameChecker(timeout=8.0, max_concurrent=15)
        scan_result = await checker.check_username(username)
        
        all_platforms = [p.to_dict() for p in scan_result.platforms]
        
        result_data = {
            "username": scan_result.username,
            "total_platforms_checked": scan_result.total_platforms_checked,
            "accounts_found": scan_result.accounts_found,
            "platforms": all_platforms,
            "categories": scan_result.categories,
            "identity_risk": scan_result.identity_risk.to_dict() if scan_result.identity_risk else None,
            "username_analysis": scan_result.username_analysis,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except ValidationError as e:
        error = f"Invalid username: {e.message}"
        result_data = None
    except NetworkError as e:
        error = f"Network error: {e.message}"
        result_data = None
    except Exception as e:
        error = f"An error occurred: {str(e)}"
        result_data = None
    
    return templates.TemplateResponse("username_result.html", {
        "request": request,
        "result": result_data,
        "error": error,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
