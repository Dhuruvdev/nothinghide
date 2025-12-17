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

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nothinghide.core import check_email, check_password, BreachScanner
from nothinghide.agent import BreachIntelligenceAgent
from nothinghide.username_checker import UsernameChecker
from nothinghide.exceptions import ValidationError, NetworkError

app = FastAPI(title="NothingHide", version="1.0.0")

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


@app.post("/email", response_class=HTMLResponse)
async def email_check(request: Request, email: str = Form(...)):
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


@app.get("/password", response_class=HTMLResponse)
async def password_page(request: Request):
    return templates.TemplateResponse("password.html", {"request": request})


@app.post("/password", response_class=HTMLResponse)
async def password_check(request: Request, password: str = Form(...)):
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


@app.get("/fullscan", response_class=HTMLResponse)
async def fullscan_page(request: Request):
    return templates.TemplateResponse("fullscan.html", {"request": request})


@app.post("/fullscan", response_class=HTMLResponse)
async def fullscan_check(request: Request, email: str = Form(...), password: str = Form(...)):
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
