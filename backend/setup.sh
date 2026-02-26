#!/bin/bash
echo "===== FortKnox Secure Setup ====="

# 1. Create virtual environment
echo "[1/5] Creating Python Virtual Environment..."
python3 -m venv ../fcs-project
source ../fcs-project/bin/activate

# 2. Install Backend Dependencies
echo "[2/5] Installing Python libraries (FastAPI, SQLAlchemy, psycopg2, cryptography, pypdf)..."
pip install --upgrade pip
pip install -r requirements.txt

# 3. Generate Security Certificates (HTTPS)
echo "[3/5] Generating RSA-4096 SSL Certificates..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform"

# 4. Initialize Storage
echo "[4/5] Creating secure upload directory..."
mkdir -p uploads

# 5. Database Verification
echo "[5/5] Setup complete. Database tables will be initialized on first run."
echo ""
echo "To start the Backend:"
echo "source ../fcs-project/bin/activate"
echo "uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload"