"""Configuration constants and API endpoints.

This module contains all configuration values for the NothingHide CLI tool.
All API endpoints use publicly available, lawful sources only.
"""

import os
from dotenv import load_dotenv

load_dotenv()

VERSION = "1.0.0"
APP_NAME = "nothinghide"

HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range/{prefix}"

XPOSEDORNOT_API = "https://api.xposedornot.com/v1/check-email/{email}"

HACKCHECK_API = "https://hackcheck.woventeams.com/api/v4/breachedaccount/{email}"

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

REQUEST_TIMEOUT = 10.0

USER_AGENT = f"NothingHide-CLI/{VERSION} (Security Research Tool)"

EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1
EXIT_NETWORK_ERROR = 2
EXIT_INTERNAL_ERROR = 3

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
