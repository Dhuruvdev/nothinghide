
import os
import sys
from pathlib import Path

# Add 'src' to sys.path
src_path = Path(__file__).parent / "nothinghide" / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    from nothinghide.web.app import app
    import uvicorn
    
    # Force Nothinghide.in as the production domain reference if needed in logic
    os.environ["PRODUCTION_DOMAIN"] = "Nothinghide.in"
    
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
