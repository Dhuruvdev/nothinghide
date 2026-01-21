# NothingHide

**Security Exposure Intelligence** - A professional Python library and CLI for checking email and password exposure in public data breaches using lawful, publicly available sources.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Email Breach Check**: Query public breach databases (HackCheck, XposedOrNot)
- **Password Exposure Check**: Uses k-anonymity protocol (Have I Been Pwned)
- **Full Identity Scan**: Combined email + password check with risk assessment
- **Async Support**: Built-in async API for concurrent checks
- **Privacy-First**: Passwords are NEVER transmitted - only SHA-1 hash prefixes

## Installation

```bash
pip install nothinghide
```

Or install from source:

```bash
git clone https://github.com/nothinghide/nothinghide.git
cd nothinghide
pip install -e .
```

## Quick Start

### As a Library

```python
from nothinghide import check_email, check_password, BreachScanner

# Check email for breaches
result = check_email("user@example.com")
if result.breached:
    print(f"Found in {result.breach_count} breaches!")
    for breach in result.breaches:
        print(f"  - {breach['name']} ({breach['year']})")

# Check password exposure (password is NEVER transmitted)
result = check_password("mypassword123")
if result.exposed:
    print(f"Password seen {result.count:,} times in breaches!")
    print(f"Strength: {result.strength}")

# Full identity scan
scanner = BreachScanner()
report = scanner.full_scan("user@example.com", "mypassword123")
print(f"Risk Level: {report.risk_level}")
for rec in report.recommendations:
    print(f"  - {rec}")
```

### Async API

```python
import asyncio
from nothinghide import async_check_email, async_check_password

async def main():
    # Check multiple emails concurrently
    email_result = await async_check_email("user@example.com")
    password_result = await async_check_password("password123")
    
    print(f"Email breached: {email_result.breached}")
    print(f"Password exposed: {password_result.exposed}")

asyncio.run(main())
```

### Command Line Interface

```bash
# Interactive menu
nothinghide

# Direct commands
nothinghide email user@example.com
nothinghide password
nothinghide scan user@example.com

# Domain scanning (checks common email patterns)
nothinghide domain example.com

# Bulk check from file
nothinghide bulk emails.csv --format json

# Export results
nothinghide domain example.com --export report.json

# Configuration
nothinghide config --show
nothinghide config --set timeout 30
```

### Startup Script

```bash
cd nothinghide
./start.sh              # Full startup with checks
./start.sh --quick      # Quick start
./start.sh --check      # Verify setup only
./start.sh --install    # Install/update package
```

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `check_email(email)` | Check email for breaches |
| `check_password(password)` | Check password exposure |
| `async_check_email(email)` | Async email check |
| `async_check_password(password)` | Async password check |

### Classes

| Class | Description |
|-------|-------------|
| `BreachScanner` | Full identity scanner with risk assessment |
| `EmailChecker` | Advanced email checker with multiple sources |
| `PasswordChecker` | Password checker with strength analysis |
| `BreachResult` | Email check result dataclass |
| `PasswordResult` | Password check result dataclass |
| `ScanReport` | Full scan report with recommendations |

### Result Objects

**BreachResult:**
```python
result.email        # Email checked
result.breached     # True if found in breaches
result.breach_count # Number of breaches
result.breaches     # List of breach details
result.source       # API source used
```

**PasswordResult:**
```python
result.exposed      # True if password found
result.count        # Times seen in breaches
result.strength     # WEAK/FAIR/GOOD/STRONG/COMPROMISED
result.feedback     # List of improvement suggestions
```

## Security Guarantees

### Password Privacy (k-Anonymity)

1. Password is hashed locally using SHA-1
2. Only first 5 characters of hash are sent to API
3. API returns all matching suffixes (hundreds of results)
4. Comparison happens locally - full hash never transmitted
5. No one (including the API) can determine your password

### Data Handling

- **No Storage**: User data is never stored or logged
- **No Transmission**: Passwords never leave your machine
- **Public Sources**: Only lawful, publicly available databases
- **Open Source**: Verify exactly what the code does

## Data Sources

| Type | Source | Method |
|------|--------|--------|
| Email | HackCheck | REST API (primary) |
| Email | XposedOrNot | REST API (fallback) |
| Password | Have I Been Pwned | k-anonymity API |

## Error Handling

```python
from nothinghide import check_email, ValidationError, NetworkError

try:
    result = check_email("invalid-email")
except ValidationError as e:
    print(f"Invalid input: {e.message}")
except NetworkError as e:
    print(f"Network error: {e.message}")
```

## Configuration

```python
from nothinghide import EmailChecker, PasswordChecker

# Custom timeout
email_checker = EmailChecker(timeout=30.0)
password_checker = PasswordChecker(timeout=30.0, enable_padding=True)

# With optional API key
email_checker = EmailChecker(xposedornot_api_key="your-key")
```

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | User input or validation error |
| 2 | Network or API failure |
| 3 | Unexpected internal error |

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/nothinghide

# Linting
ruff check src/
```

## Legal Disclaimer

NothingHide queries only publicly available breach databases. Results reflect data that is already public. This tool:

- Is intended for personal security awareness only
- Should not be used to check credentials you do not own
- Makes no guarantees about the completeness of breach data
- Is not a substitute for professional security auditing

Use responsibly and in accordance with applicable laws.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please read our contributing guidelines first.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.
