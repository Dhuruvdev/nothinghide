# NothingHide

A professional security tool for checking public exposure of email addresses and passwords using lawful, publicly available sources only.

## What NothingHide Does

- **Email Breach Check**: Queries public breach databases to see if your email appears in known data breaches
- **Password Exposure Check**: Uses k-anonymity to safely check if a password has been compromised
- **Identity Scan**: Combines both checks and provides a risk assessment with actionable recommendations

## What NothingHide Does NOT Do

- Does NOT access dark web or illegal sources
- Does NOT store your email, password, or any personal data
- Does NOT transmit your actual password over the network
- Does NOT make claims beyond what public data sources provide
- Does NOT exaggerate or use fear-based language

## Installation

```bash
# Install from source
cd nothinghide
pip install -e .

# Verify installation
nothinghide --version
```

## Quick Start

The easiest way to start NothingHide is using the startup script:

```bash
cd nothinghide
./start.sh
```

### Startup Script Options

| Option | Description |
|--------|-------------|
| `--help, -h` | Show help message |
| `--quick, -q` | Quick start (skip detailed checks) |
| `--check` | Run checks only, don't start CLI |
| `--install` | Install/update dependencies |
| `--clean` | Clean up cache files |
| `--skip-network` | Skip network connectivity check |

Examples:
```bash
./start.sh                  # Full startup with all checks
./start.sh --quick          # Quick startup (faster)
./start.sh --check          # Just verify everything is set up
./start.sh --install        # Update all dependencies
```

## Usage

### Interactive Menu

When you start NothingHide, you'll see a numbered menu:

```
  [1]  Email Check      - Check if your email appears in data breaches
  [2]  Password Check   - Check if your password has been exposed
  [3]  Full Scan        - Complete identity scan (email + password)
  [4]  Help             - Show detailed help information
  [5]  Exit             - Exit NothingHide
```

Simply enter a number (1-5) to select an option.

### Command Line Mode

You can also use direct commands:

```bash
# Check email for breaches
nothinghide email user@example.com

# Check password exposure
nothinghide password

# Run complete identity scan
nothinghide scan user@example.com

# Get help
nothinghide --help
```

## Privacy Guarantee

1. **No Data Storage**: Your email and password are never stored anywhere
2. **K-Anonymity for Passwords**: Only the first 5 characters of your password's SHA-1 hash are sent to the API. The full comparison happens locally on your machine
3. **No Logging**: User inputs are never logged or written to disk
4. **Open Source**: You can verify exactly what the code does

## Data Sources

- **Email Breaches**: HackCheck API (primary), XposedOrNot API (fallback)
- **Password Exposure**: Have I Been Pwned Pwned Passwords API (free, uses k-anonymity)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | User input or validation error |
| 2 | Network or API failure |
| 3 | Unexpected internal error |

## Legal Disclaimer

NothingHide queries only publicly available breach databases. Results reflect data that is already public. This tool:

- Is intended for personal security awareness only
- Should not be used to check credentials you do not own
- Makes no guarantees about the completeness or accuracy of breach data
- Is not a substitute for professional security auditing

Use responsibly and in accordance with applicable laws.

## License

MIT License - See LICENSE file for details.
