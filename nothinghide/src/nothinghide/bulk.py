"""Bulk operations for NothingHide - CSV/TXT import and batch processing."""

import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Callable
from dataclasses import dataclass
import re

from .exceptions import ValidationError


@dataclass
class BulkItem:
    """A single item for bulk processing."""
    value: str
    item_type: str
    line_number: int
    source_file: str


def read_email_list(filepath: Path) -> Generator[BulkItem, None, None]:
    """Read email addresses from a file (CSV or TXT).
    
    Supports:
    - Plain text files (one email per line)
    - CSV files (first column or 'email' column)
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        raise ValidationError(f"File not found: {filepath}")
    
    suffix = filepath.suffix.lower()
    
    if suffix == ".csv":
        yield from _read_csv_emails(filepath)
    else:
        yield from _read_txt_emails(filepath)


def _read_txt_emails(filepath: Path) -> Generator[BulkItem, None, None]:
    """Read emails from plain text file."""
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            email = line.strip()
            if email and not email.startswith("#"):
                if _is_valid_email(email):
                    yield BulkItem(
                        value=email,
                        item_type="email",
                        line_number=line_num,
                        source_file=str(filepath)
                    )


def _read_csv_emails(filepath: Path) -> Generator[BulkItem, None, None]:
    """Read emails from CSV file."""
    with open(filepath, "r", encoding="utf-8", newline="") as f:
        try:
            reader = csv.DictReader(f)
            email_column = None
            
            if reader.fieldnames:
                for col in reader.fieldnames:
                    if col.lower() in ("email", "e-mail", "email_address", "emailaddress"):
                        email_column = col
                        break
                
                if email_column is None and reader.fieldnames:
                    email_column = reader.fieldnames[0]
            
            for line_num, row in enumerate(reader, 2):
                if email_column and email_column in row:
                    email = row[email_column].strip()
                    if email and _is_valid_email(email):
                        yield BulkItem(
                            value=email,
                            item_type="email",
                            line_number=line_num,
                            source_file=str(filepath)
                        )
        except csv.Error:
            with open(filepath, "r", encoding="utf-8") as f2:
                for line_num, line in enumerate(f2, 1):
                    email = line.strip()
                    if email and _is_valid_email(email):
                        yield BulkItem(
                            value=email,
                            item_type="email",
                            line_number=line_num,
                            source_file=str(filepath)
                        )


def _is_valid_email(email: str) -> bool:
    """Basic email validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


@dataclass
class BulkResult:
    """Result of a bulk operation."""
    total: int
    processed: int
    success: int
    failed: int
    results: List[Dict[str, Any]]
    errors: List[Dict[str, Any]]


def process_bulk(
    items: List[BulkItem],
    processor: Callable[[str], Dict[str, Any]],
    progress_callback: Optional[Callable[[int, int, str], None]] = None
) -> BulkResult:
    """Process items in bulk.
    
    Args:
        items: List of items to process
        processor: Function to process each item
        progress_callback: Optional callback(current, total, item) for progress
    
    Returns:
        BulkResult with all results and errors
    """
    results = []
    errors = []
    total = len(items)
    
    for i, item in enumerate(items):
        if progress_callback:
            progress_callback(i + 1, total, item.value)
        
        try:
            result = processor(item.value)
            results.append({
                "item": item.value,
                "line": item.line_number,
                "result": result
            })
        except Exception as e:
            errors.append({
                "item": item.value,
                "line": item.line_number,
                "error": str(e)
            })
    
    return BulkResult(
        total=total,
        processed=len(results) + len(errors),
        success=len(results),
        failed=len(errors),
        results=results,
        errors=errors
    )
