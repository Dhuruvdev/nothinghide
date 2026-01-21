import os
import sys
import uvicorn
from pathlib import Path

# Add the source directory to the path
src_path = Path(__file__).parent / "nothinghide" / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    # Import the app inside the main block to avoid issues with multiprocess reloading
    from nothinghide.web.app import app
    
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
