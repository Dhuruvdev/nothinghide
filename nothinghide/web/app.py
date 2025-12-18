"""NothingHide Web Interface - FastAPI Application.

A retro-styled web interface for checking email and password exposure
using public breach databases.
"""

import os
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))
from web.ai_agents import MultiAgentAnalyzer

from nothinghide.core import check_email, check_password, BreachScanner
from nothinghide.agent import BreachIntelligenceAgent
from nothinghide.username_checker import UsernameChecker
from nothinghide.exceptions import ValidationError, NetworkError

app = FastAPI(title="NothingHide", version="1.0.0")

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
    """Check if the query looks like an email address."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, query.strip()))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/terminal", response_class=HTMLResponse)
async def terminal(request: Request):
    """CLI-style terminal interface - lightweight client-side rendering."""
    return templates.TemplateResponse("terminal.html", {"request": request})


@app.post("/check", response_class=HTMLResponse)
async def unified_check(request: Request, query: str = Form(...)):
    """Unified check endpoint - detects if input is email or password and routes accordingly."""
    query = query.strip()
    
    if is_email(query):
        result = None
        error = None
        
        try:
            agent = BreachIntelligenceAgent()
            result = await agent.check_email(query)
            
            breaches = []
            if result.breaches:
                for b in result.breaches:
                    if hasattr(b, 'to_dict'):
                        breaches.append(b.to_dict())
                    elif isinstance(b, dict):
                        breaches.append(b)
            
            result_data = {
                "email": query,
                "breached": result.breached,
                "breach_count": result.breach_count,
                "breaches": breaches[:15],
                "risk_score": getattr(result, 'risk_score', 0),
                "sources_succeeded": getattr(result, 'sources_succeeded', []),
                "sources_failed": getattr(result, 'sources_failed', []),
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
        agent = BreachIntelligenceAgent()
        result = await agent.check_email(email)
        
        breaches = []
        if result.breaches:
            for b in result.breaches:
                if hasattr(b, 'to_dict'):
                    breaches.append(b.to_dict())
                elif isinstance(b, dict):
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


@app.get("/ai-analysis", response_class=HTMLResponse)
async def ai_analysis_page(request: Request):
    """Advanced multi-agent AI analysis for deepfake and AI-generated content detection."""
    return templates.TemplateResponse("ai_analysis.html", {"request": request})


@app.post("/ai-analysis", response_class=HTMLResponse)
async def ai_analysis_check(request: Request, image: UploadFile = File(...)):
    """Process image through multiple AI agents for comprehensive analysis."""
    result = None
    error = None
    
    try:
        if not image.content_type or not image.content_type.startswith('image/'):
            error = "Please upload a valid image file (JPEG, PNG, etc.)"
        else:
            image_bytes = await image.read()
            
            if len(image_bytes) > 10 * 1024 * 1024:
                error = "Image too large. Please upload an image under 10MB."
            else:
                analyzer = MultiAgentAnalyzer()
                analysis_result = await analyzer.analyze(image_bytes)
                result = analysis_result.to_dict()
                
    except Exception as e:
        error = f"Analysis error: {str(e)}"
    
    return templates.TemplateResponse("ai_analysis_result.html", {
        "request": request,
        "result": result,
        "error": error,
    })


@app.post("/ai-analysis/api")
async def ai_analysis_api(image: UploadFile = File(...)):
    """API endpoint for AI analysis - returns JSON."""
    try:
        if not image.content_type or not image.content_type.startswith('image/'):
            return JSONResponse(content={"error": "Please upload a valid image file"})
        
        image_bytes = await image.read()
        
        if len(image_bytes) > 10 * 1024 * 1024:
            return JSONResponse(content={"error": "Image too large (max 10MB)"})
        
        analyzer = MultiAgentAnalyzer()
        analysis_result = await analyzer.analyze(image_bytes)
        return JSONResponse(content=analysis_result.to_dict())
        
    except Exception as e:
        return JSONResponse(content={"error": str(e)})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
