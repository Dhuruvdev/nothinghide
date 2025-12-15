# NothingHide CLI

## Overview

NothingHide is a professional, pip-installable Python library for breach detection with advanced real-time capabilities. Check email and password exposure using lawful public sources with k-anonymity for privacy.

## Project Structure

```
nothinghide/
├── src/nothinghide/
│   ├── __init__.py         # Package exports and version
│   ├── core.py             # High-level API (check_email, check_password, BreachScanner)
│   ├── email_checker.py    # Email breach checking (HackCheck/XposedOrNot APIs)
│   ├── password_checker.py # Password exposure check (HIBP k-anonymity)
│   ├── cli.py              # Typer CLI entry point with all commands
│   ├── branding.py         # Terminal UI styling and components
│   ├── config.py           # API endpoints and constants
│   ├── exceptions.py       # Custom exception hierarchy
│   └── utils.py            # Validators, formatters, helpers
├── pyproject.toml          # Package configuration (PyPI-ready)
├── start.sh                # Startup script with dependency checks
└── README.md               # Usage documentation
```

## Tech Stack

- **Python 3.10+**
- **typer** - CLI framework
- **httpx** - HTTP client with async support
- **rich** - Terminal formatting
- **python-dotenv** - Environment handling
- **email-validator** - Email validation

## Installation

```bash
pip install nothinghide
```

Or from source:
```bash
cd nothinghide
pip install -e .
```

## Library Usage

```python
from nothinghide import check_email, check_password, BreachScanner

# Check email for breaches
result = check_email("user@example.com")
print(f"Breached: {result.breached}, Count: {result.breach_count}")

# Check password (uses k-anonymity - password never transmitted)
result = check_password("mypassword123")
print(f"Exposed: {result.exposed}, Count: {result.count}")

# Full identity scan
scanner = BreachScanner()
report = scanner.full_scan("user@example.com", "password123")
print(f"Risk: {report.risk_level}")
```

## CLI Commands

- `nothinghide` - Interactive menu
- `nothinghide email <email>` - Check email against breach databases
- `nothinghide password` - Check password exposure (secure input)
- `nothinghide scan <email>` - Combined email + password check with risk level
- `nothinghide --version` - Show version

## APIs Used

- **HackCheck API** (free, no auth) - Primary email breach source
- **XposedOrNot API** (free) - Fallback email breach source
- **Have I Been Pwned Pwned Passwords** (free) - Password exposure with k-anonymity

## Exit Codes

- 0 = Success
- 1 = User input/validation error
- 2 = Network/API failure
- 3 = Internal error

## Security Principles

- Never stores user data
- Never logs passwords or hashes
- Uses k-anonymity (only 5-char hash prefix sent)
- Queries only lawful public sources
