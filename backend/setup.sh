#!/bin/bash

echo "===== Secure Job Platform - Setup Script ====="
echo ""

# Step 1: Create virtual environment
echo "[1/5] Creating virtual environment..."
python3 -m venv ../fcs-project
source ../fcs-project/bin/activate

# Step 2: Install dependencies
echo "[2/5] Installing dependencies..."
pip install -r requirements.txt

# Step 3: Generate SSL certificates
echo "[3/5] Generating SSL certificates..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform"

# Step 4: Create uploads folder
echo "[4/5] Creating uploads folder..."
mkdir -p uploads

# Step 5: Database will auto-create on first run
echo "[5/5] Setup complete!"
echo ""
echo "To start the server, run:"
echo "  source ../fcs-project/bin/activate"
echo "  uvicorn main:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload"
echo ""
echo "Then visit: https://127.0.0.1:8000/docs"