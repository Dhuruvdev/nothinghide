"""NothingHide - Main entry point for the web interface."""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "nothinghide"))
sys.path.insert(0, str(project_root / "nothinghide" / "src"))

import uvicorn


def main():
    """Run the NothingHide web interface."""
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    
    print(f"Starting NothingHide Web Interface on http://{host}:{port}")
    uvicorn.run("web.app:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    main()
