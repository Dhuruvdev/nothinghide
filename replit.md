# NothingHide CLI

## Overview

NothingHide is a professional, pip-installable Python CLI security tool that helps users check public exposure risk of their email and password using verifiable, lawful sources only.

## Project Structure

```
nothinghide/
├── app/
│   ├── __init__.py        # Package init, version
│   ├── main.py            # Typer CLI entry point with all commands
│   ├── email_check.py     # Email breach checking (HackCheck/XposedOrNot APIs)
│   ├── password_check.py  # Password exposure check (HIBP k-anonymity)
│   ├── scan.py            # Combined identity scan with risk assessment
│   ├── utils.py           # Validators, formatters, helpers
│   └── config.py          # API endpoints and constants
├── pyproject.toml         # Package configuration
├── README.md              # Usage documentation
└── .env.example           # Environment variable template
```

## Tech Stack

- **Python 3.11+**
- **typer** - CLI framework
- **httpx** - HTTP client
- **rich** - Terminal formatting
- **python-dotenv** - Environment handling
- **email-validator** - Email validation

## Commands

- `nothinghide email <email>` - Check email against breach databases
- `nothinghide password` - Check password exposure (secure input)
- `nothinghide scan <email>` - Combined email + password check with risk level
- `nothinghide --help` - Show help
- `nothinghide --version` - Show version

## APIs Used

- **HackCheck API** (free, no auth) - Primary email breach source
- **XposedOrNot API** (free) - Fallback email breach source
- **Have I Been Pwned Pwned Passwords** (free) - Password exposure with k-anonymity

## Installation

```bash
cd nothinghide
pip install -e .
```

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
