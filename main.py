import os
import subprocess
import sys
from pathlib import Path

def main():
    print("Starting NothingHide Web Server...")
    # Change directory to the workspace root if not already there
    os.chdir(Path(__file__).parent)
    
    # Path to the uvicorn command
    # In Replit, uvicorn should be available in the path after installation
    command = [
        sys.executable, "-m", "uvicorn", 
        "nothinghide.web.app:app", 
        "--host", "0.0.0.0", 
        "--port", "5000"
    ]
    
    print(f"Executing: {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Server exited with error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
