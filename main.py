import os
import sys
import uvicorn
from pathlib import Path

# Add the source directory to the path so 'nothinghide' package is findable during development
src_path = Path(__file__).parent / "nothinghide" / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    # Import the app inside the main block
    from nothinghide.web.app import app
    
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
