# NothingHide - Project Synopsis

## 1. Introduction

NothingHide is a command-line security tool that helps users check if their email addresses or passwords have been exposed in data breaches. In today's digital world, data breaches are very common. Hackers steal millions of user records from websites and leak them online. This tool helps people find out if their personal information is at risk.

## 2. Problem Statement

Every year, billions of user accounts are compromised in data breaches. Most people don't know if their email or password has been leaked. Using the same password across multiple websites makes the problem worse. There is a need for a simple tool that can:
- Check if an email has been found in known data breaches
- Check if a password has been exposed (without revealing the password)
- Work on both Windows and Linux computers
- Be easy to use for non-technical users

## 3. Objectives

1. Create a user-friendly command-line tool for breach detection
2. Use only lawful, publicly available data sources
3. Implement secure password checking using k-anonymity
4. Support cross-platform operation (Windows and Linux)
5. Provide clear risk assessments and recommendations

## 4. Features

### 4.1 Email Breach Check
- Checks email against 6+ breach databases simultaneously
- Shows which breaches the email was found in
- Displays breach dates and compromised data types

### 4.2 Password Check
- Uses k-anonymity protocol (password is never transmitted)
- Only sends first 5 characters of hash to the API
- Shows how many times the password appeared in breaches

### 4.3 Domain Scanning
- Scans entire domains for breach exposure
- Checks common email patterns (info@, admin@, contact@, etc.)
- Useful for organizations to assess their exposure

### 4.4 Bulk Processing
- Import email lists from CSV or TXT files
- Process multiple emails with progress tracking
- Built-in rate limiting to prevent API bans

### 4.5 Export Reports
- Export results to JSON, CSV, or HTML formats
- Generate professional security reports
- Easy sharing and documentation

## 5. Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| CLI Framework | Typer |
| HTTP Client | httpx |
| Terminal UI | Rich |
| Configuration | python-dotenv |

## 6. How It Works

### Email Checking
1. User enters an email address
2. Tool queries multiple breach databases in parallel
3. Results are combined and deduplicated
4. Risk level is calculated based on breach count

### Password Checking (k-Anonymity)
1. Password is hashed using SHA-1 locally
2. Only first 5 characters of hash are sent to API
3. API returns all matching hash suffixes
4. Comparison happens locally on user's computer
5. Full password hash is never transmitted

## 7. Data Sources

- LeakCheck Public API (7B+ records)
- HackCheck API
- XposedOrNot API
- EmailRep.io
- DeXpose
- Have I Been Pwned (for passwords)

## 8. Security Principles

1. **No Storage** - User data is never saved
2. **No Logging** - Passwords are never logged
3. **Privacy First** - k-anonymity protects passwords
4. **Open Source** - Code can be verified by anyone
5. **Lawful Sources** - Only public databases are used

## 9. Installation and Usage

```bash
# Install
pip install nothinghide

# Check email
nothinghide email user@example.com

# Check password (secure prompt)
nothinghide password

# Full scan
nothinghide scan user@example.com

# Domain scan
nothinghide domain example.com

# Bulk check
nothinghide bulk emails.csv
```

## 10. Limitations

- Depends on third-party API availability
- Cannot detect breaches not in public databases
- Rate limits may slow bulk operations
- Internet connection required

## 11. Future Scope

- Add more data sources
- Implement breach notifications
- Create a web interface
- Add browser extension
- Support for phone number checking

## 12. Conclusion

NothingHide is a practical security tool that helps users protect their online identity. By checking emails and passwords against known breach databases, users can take action before hackers exploit their compromised credentials. The tool follows privacy-first principles and uses only lawful data sources, making it safe and legal to use.

## 13. References

1. Have I Been Pwned - https://haveibeenpwned.com
2. k-Anonymity Protocol - Wikipedia
3. Python Documentation - https://docs.python.org
4. Typer Documentation - https://typer.tiangolo.com
5. Rich Documentation - https://rich.readthedocs.io

---

**Prepared by:** [Student Name]  
**Class:** 12th  
**Subject:** Computer Science Project  
**Year:** 2024-25
