#!/bin/bash
echo "===== FortKnox Secure Setup ====="

# 1. Create virtual environment
echo "[1/6] Creating Python Virtual Environment..."
python3 -m venv ../fcs-project
source ../fcs-project/bin/activate

# 2. Install Backend Dependencies
echo "[2/6] Installing Python libraries (FastAPI, SQLAlchemy, psycopg2, cryptography, pypdf)..."
pip install --upgrade pip
pip install -r requirements.txt

# 3. Generate Security Certificates (HTTPS)
echo "[3/6] Generating RSA-4096 SSL Certificates..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform"

# 4. Initialize Secure Upload Directory
echo "[4/6] Creating secure upload directory..."
mkdir -p uploads
chmod 700 uploads  # SECURITY FIX: Owner-only access

# 5. Generate .env if not exists
echo "[5/6] Checking environment configuration..."
if [ ! -f .env ]; then
    echo "Creating .env from template..."
    # Generate a random JWT secret
    JWT_SECRET=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
    MASTER_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
    HMAC_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
    
    cat > .env << EOF
# Auto-generated secrets — DO NOT COMMIT THIS FILE
JWT_SECRET_KEY=${JWT_SECRET}
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
DATABASE_URL=postgresql://secureadmin:FortKnoxPass123!@localhost/securejobdb
SMTP_USERNAME=fortknox914@gmail.com
SMTP_PASSWORD=lrigfpadqfothkxs
SMTP_FROM=fortknox914@gmail.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
RESUME_MASTER_KEY=${MASTER_KEY}
AUDIT_HMAC_KEY=${HMAC_KEY}
SERVER_PKI_KEY_PATH=server_private_key.pem
ENVIRONMENT=development
ALLOW_TEST_ACCOUNTS=true
EOF
    chmod 600 .env  # Owner-only read/write
    echo ".env created with random secrets"
else
    echo ".env already exists, skipping"
fi

# 6. Database Verification
echo "[6/6] Setup complete. Database tables will be initialized on first run."
echo ""
echo "To start the Backend:"
echo "source ../fcs-project/bin/activate"
echo "uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload"