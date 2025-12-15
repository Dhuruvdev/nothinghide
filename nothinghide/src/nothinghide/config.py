"""Configuration constants for NothingHide library."""

import os
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

VERSION = "1.0.0"
APP_NAME = "nothinghide"

HACKCHECK_API = "https://hackcheck.woventeams.com/api/v4/breachedaccount/{email}"
XPOSEDORNOT_API = "https://api.xposedornot.com/v1/check-email/{email}"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range/{prefix}"
BREACH_DIRECTORY_API = "https://breachdirectory.p.rapidapi.com/"

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
XPOSEDORNOT_API_KEY = os.getenv("XPOSEDORNOT_API_KEY", "")

REQUEST_TIMEOUT = 15.0
ASYNC_TIMEOUT = 10.0
MAX_RETRIES = 3
RETRY_DELAY = 1.0

USER_AGENT = f"NothingHide/{VERSION} (Security Exposure Intelligence Library)"

EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1
EXIT_NETWORK_ERROR = 2
EXIT_INTERNAL_ERROR = 3

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

RISK_LEVELS = {
    RISK_LOW: {
        "label": "Low Risk",
        "color": "green",
        "description": "No significant exposure detected",
    },
    RISK_MEDIUM: {
        "label": "Medium Risk",
        "color": "yellow",
        "description": "Some exposure detected, action recommended",
    },
    RISK_HIGH: {
        "label": "High Risk",
        "color": "orange",
        "description": "Significant exposure detected, immediate action required",
    },
    RISK_CRITICAL: {
        "label": "Critical Risk",
        "color": "red",
        "description": "Severe exposure detected, urgent action required",
    },
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "timeout": REQUEST_TIMEOUT,
    "max_retries": MAX_RETRIES,
    "retry_delay": RETRY_DELAY,
    "user_agent": USER_AGENT,
    "enable_padding": True,
    "verify_ssl": True,
}

API_PROVIDERS = {
    "hackcheck": {
        "name": "HackCheck",
        "url": HACKCHECK_API,
        "requires_key": False,
        "rate_limit": None,
        "priority": 1,
    },
    "xposedornot": {
        "name": "XposedOrNot",
        "url": XPOSEDORNOT_API,
        "requires_key": False,
        "rate_limit": None,
        "priority": 2,
    },
    "hibp_passwords": {
        "name": "Have I Been Pwned",
        "url": HIBP_PASSWORD_API,
        "requires_key": False,
        "rate_limit": None,
        "priority": 1,
    },
}
