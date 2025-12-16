# NothingHide CLI

## Overview

NothingHide is a professional, pip-installable Python library for breach detection with advanced real-time capabilities. It features an intelligent multi-source agent system that queries 6+ breach databases in parallel with automatic failover, rate limiting, and data correlation.

## Key Features

- **Multi-Source Intelligence**: Queries 6+ breach APIs simultaneously
- **Intelligent Agent System**: Automatic retry, failover, and source health monitoring
- **Data Correlation Engine**: Deduplicates and cross-references breach results
- **Smart Rate Limiting**: Adaptive rate limiting prevents API throttling
- **Domain Reputation**: Checks domain validity and reputation
- **Paste Site Monitoring**: Detects email exposure in paste sites
- **k-Anonymity Password Checking**: Password never transmitted

## Project Structure

```
nothinghide/
├── src/nothinghide/
│   ├── __init__.py         # Package exports and version
│   ├── core.py             # High-level API (check_email, check_password, BreachScanner)
│   ├── email_checker.py    # Email breach checking (legacy API)
│   ├── password_checker.py # Password exposure check (HIBP k-anonymity)
│   ├── cli.py              # Typer CLI entry point with all commands
│   ├── branding.py         # Terminal UI styling and components
│   ├── config.py           # API endpoints and constants
│   ├── exceptions.py       # Custom exception hierarchy
│   ├── utils.py            # Validators, formatters, helpers
│   └── agent/              # Advanced Agent System
│       ├── __init__.py     # Agent exports
│       ├── orchestrator.py # Main BreachIntelligenceAgent
│       ├── sources.py      # Multi-source data fetchers (6+ APIs)
│       ├── correlation.py  # Data correlation and deduplication
│       ├── rate_limiter.py # Adaptive rate limiting
│       └── domain.py       # Domain reputation & paste monitoring
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

### Basic API
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

### Advanced Agent API (Recommended)
```python
from nothinghide import BreachIntelligenceAgent, AgentConfig

# Configure agent
config = AgentConfig(
    timeout=15.0,
    max_concurrent_sources=6,
    enable_correlation=True,
)

# Create agent
agent = BreachIntelligenceAgent(config)

# Synchronous check
result = agent.check_email_sync("user@example.com")
print(f"Breached: {result.breached}")
print(f"Breach Count: {result.breach_count}")
print(f"Risk Score: {result.risk_score}")
print(f"Sources Used: {result.sources_succeeded}")

# Async check
import asyncio
result = asyncio.run(agent.check_email("user@example.com"))

# Full intelligence gathering
intel = agent.get_full_intelligence("user@example.com")
print(intel["breach_data"])
print(intel["recommendations"])

# Check source health
status = agent.get_source_status()
for source, info in status.items():
    print(f"{source}: {info['health']['status']}")
```

## CLI Commands

- `nothinghide` - Interactive menu
- `nothinghide email <email>` - Check email against breach databases
- `nothinghide password` - Check password exposure (secure input)
- `nothinghide scan <email>` - Combined email + password check with risk level
- `nothinghide --version` - Show version

## Data Sources (6+ APIs)

### Email Breach Sources
- **LeakCheck Public API** - 7B+ records
- **HackCheck API** - Free breach lookup
- **XposedOrNot API** - Community breach database
- **XposedOrNot Analytics** - Detailed breach analytics
- **EmailRep.io** - Email reputation and leak detection
- **DeXpose** - Dark web exposure detection

### Password Source
- **Have I Been Pwned Pwned Passwords** - k-anonymity protocol

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
- All breach data from publicly available APIs

## Recent Changes

- **Dec 2024**: Added Advanced Agent System with multi-source intelligence
- **Dec 2024**: Implemented data correlation engine for result deduplication
- **Dec 2024**: Added domain reputation and paste site monitoring
- **Dec 2024**: Upgraded CLI to use parallel multi-source querying
