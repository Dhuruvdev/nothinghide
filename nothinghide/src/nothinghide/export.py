"""Export functionality for NothingHide reports."""

import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

from .platform import get_data_dir


def get_export_dir() -> Path:
    """Get the default export directory."""
    export_dir = get_data_dir() / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir


def generate_filename(prefix: str, ext: str) -> str:
    """Generate a timestamped filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{ext}"


def export_json(data: Dict[str, Any], filepath: Optional[Path] = None) -> Path:
    """Export results to JSON file."""
    if filepath is None:
        filepath = get_export_dir() / generate_filename("nothinghide_report", "json")
    
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    
    return filepath


def export_csv(data: List[Dict[str, Any]], filepath: Optional[Path] = None) -> Path:
    """Export results to CSV file."""
    if filepath is None:
        filepath = get_export_dir() / generate_filename("nothinghide_report", "csv")
    
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    if not data:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("")
        return filepath
    
    fieldnames = list(data[0].keys())
    
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    
    return filepath


def export_html(data: Dict[str, Any], filepath: Optional[Path] = None) -> Path:
    """Export results to HTML report."""
    if filepath is None:
        filepath = get_export_dir() / generate_filename("nothinghide_report", "html")
    
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NothingHide Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ 
            color: #00ff88;
            font-size: 2rem;
            margin-bottom: 0.5rem;
            font-family: monospace;
        }}
        .subtitle {{ color: #666; margin-bottom: 2rem; }}
        .section {{ 
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .section h2 {{ 
            color: #00d4ff;
            font-size: 1.2rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
        }}
        .status {{ 
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9rem;
        }}
        .status.exposed {{ background: #ff4444; color: white; }}
        .status.clear {{ background: #00ff88; color: black; }}
        .status.unknown {{ background: #666; color: white; }}
        table {{ 
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{ 
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{ color: #888; font-weight: normal; text-transform: uppercase; font-size: 0.8rem; }}
        .footer {{ 
            text-align: center;
            color: #666;
            margin-top: 2rem;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>NothingHide Report</h1>
        <p class="subtitle">Generated: {timestamp}</p>
        
        <div class="section">
            <h2>Summary</h2>
            <pre>{json.dumps(data, indent=2, default=str)}</pre>
        </div>
        
        <div class="footer">
            <p>NothingHide - Breach Exposure Intelligence</p>
            <p>100% lawful sources - No data stored</p>
        </div>
    </div>
</body>
</html>"""
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    
    return filepath


def format_output(data: Any, output_format: str = "table") -> str:
    """Format data for console output."""
    if output_format == "json":
        return json.dumps(data, indent=2, default=str)
    elif output_format == "csv":
        if isinstance(data, list):
            if not data:
                return ""
            if isinstance(data[0], dict):
                fieldnames = list(data[0].keys())
                lines = [",".join(fieldnames)]
                for row in data:
                    if isinstance(row, dict):
                        lines.append(",".join(str(row.get(k, "")) for k in fieldnames))
                return "\n".join(lines)
            return "\n".join(str(item) for item in data)
        elif isinstance(data, dict):
            lines = ["key,value"]
            for k, v in data.items():
                lines.append(f"{k},{v}")
            return "\n".join(lines)
        else:
            return str(data)
    else:
        return str(data)
