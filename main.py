import os
import sys
from pathlib import Path

# Add 'src' to sys.path so the nothinghide package is importable
src_path = Path(__file__).parent / "nothinghide" / "src"
sys.path.insert(0, str(src_path))

os.environ.setdefault("PRODUCTION_DOMAIN", "Nothinghide.in")

# Top-level app export required by Vercel's FastAPI detection
from nothinghide.web.app import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)
