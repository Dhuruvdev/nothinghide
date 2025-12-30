#!/bin/bash
# NothingHide Standalone Setup Script
# Automatically configures the environment and starts the web interface.

echo "🛡️ Initializing NothingHide Standalone..."

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found. Please install it."
    exit 1
fi

# Install dependencies
echo "📦 Installing core dependencies..."
pip install -e . -q

# Create static asset directory if it doesn't exist
mkdir -p nothinghide/web/static

# Check for extension package
if [ ! -f "nothinghide/web/static/extension.zip" ]; then
    echo "🏗️ Building security extension package..."
    if command -v zip &> /dev/null; then
        cd nothinghide/web/static && zip -r extension.zip manifest.json background.js popup.html content.js &> /dev/null && cd ../../..
    else
        echo "⚠️ Warning: 'zip' utility not found. Extension package skipped."
    fi
fi

echo "🚀 Starting NothingHide Web Interface on http://0.0.0.0:5000"
python -m uvicorn nothinghide.web.app:app --host 0.0.0.0 --port 5000 --reload
