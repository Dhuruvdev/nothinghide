import os
import sys
import uvicorn
from pathlib import Path

# Fix the path to include the 'src' directory so 'nothinghide' is importable
current_dir = Path(__file__).parent
src_path = current_dir / "nothinghide" / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    from nothinghide.web.app import app
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
