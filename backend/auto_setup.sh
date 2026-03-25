#!/bin/bash
# ======================================================
# FortKnox Automated Setup Script for Teammates
# Run this after cloning from GitHub.
# It handles EVERYTHING except manual SSL cert acceptance.
# ======================================================

set -e

echo "======================================================"
echo "   FortKnox Secure Platform -- Automated Setup"
echo "======================================================"
echo ""

# Get the project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$SCRIPT_DIR"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
VENV_DIR="$PROJECT_ROOT/fcs-project"

echo "Project root: $PROJECT_ROOT"
echo "Backend dir:  $BACKEND_DIR"
echo "Frontend dir: $FRONTEND_DIR"
echo ""

# ============================================================
# STEP 1: Check Prerequisites
# ============================================================
echo "------------------------------------------------------"
echo "STEP 1: Checking prerequisites..."
echo "------------------------------------------------------"

MISSING=""

if command -v python3 &> /dev/null; then
    PY_VER=$(python3 --version 2>&1)
    echo "  [OK] $PY_VER"
else
    echo "  [MISSING] Python3 not found"
    MISSING="$MISSING python3"
fi

if command -v pip3 &> /dev/null || python3 -m pip --version &> /dev/null; then
    echo "  [OK] pip3 available"
else
    echo "  [MISSING] pip3 not found"
    MISSING="$MISSING python3-pip"
fi

if command -v psql &> /dev/null; then
    PSQL_VER=$(psql --version 2>&1)
    echo "  [OK] $PSQL_VER"
else
    echo "  [MISSING] PostgreSQL not found"
    MISSING="$MISSING postgresql"
fi

if command -v node &> /dev/null; then
    NODE_VER=$(node --version 2>&1)
    echo "  [OK] Node.js $NODE_VER"
else
    echo "  [MISSING] Node.js not found"
    MISSING="$MISSING nodejs"
fi

if command -v npm &> /dev/null; then
    NPM_VER=$(npm --version 2>&1)
    echo "  [OK] npm $NPM_VER"
else
    echo "  [MISSING] npm not found"
    MISSING="$MISSING npm"
fi

if command -v openssl &> /dev/null; then
    echo "  [OK] OpenSSL available"
else
    echo "  [MISSING] OpenSSL not found"
    MISSING="$MISSING openssl"
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "[ERROR] Missing prerequisites. Install with:"
    echo "   sudo apt update && sudo apt install -y $MISSING python3-venv"
    echo ""
    read -p "Try installing now? (yes/no): " install_now
    if [ "$install_now" = "yes" ]; then
        sudo apt update && sudo apt install -y $MISSING python3-venv
    else
        echo "Please install missing software and re-run this script."
        exit 1
    fi
fi

echo ""

# ============================================================
# STEP 2: Create Python Virtual Environment
# ============================================================
echo "------------------------------------------------------"
echo "STEP 2: Creating Python virtual environment..."
echo "------------------------------------------------------"

if [ -d "$VENV_DIR" ]; then
    echo "  Virtual environment already exists at $VENV_DIR"
else
    python3 -m venv "$VENV_DIR"
    echo "  [OK] Created virtual environment at $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo "  [OK] Virtual environment activated"

# ============================================================
# STEP 3: Install Python Dependencies
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 3: Installing Python dependencies..."
echo "------------------------------------------------------"

cd "$BACKEND_DIR"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "  [OK] All Python packages installed"

# ============================================================
# STEP 4: Generate SSL Certificates
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 4: Generating SSL certificates..."
echo "------------------------------------------------------"

if [ -f "$BACKEND_DIR/key.pem" ] && [ -f "$BACKEND_DIR/cert.pem" ]; then
    echo "  SSL certificates already exist. Skipping."
else
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$BACKEND_DIR/key.pem" \
        -out "$BACKEND_DIR/cert.pem" \
        -sha256 -days 365 -nodes \
        -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform" \
        2>/dev/null
    echo "  [OK] SSL certificates generated (key.pem, cert.pem)"
fi

# ============================================================
# STEP 5: Create .env File
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 5: Setting up environment configuration..."
echo "------------------------------------------------------"

if [ -f "$BACKEND_DIR/.env" ]; then
    echo "  .env file already exists. Skipping."
else
    JWT_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
    MASTER_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
    HMAC_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")

    cat > "$BACKEND_DIR/.env" << EOF
# Auto-generated by setup script -- DO NOT COMMIT
JWT_SECRET_KEY=${JWT_KEY}
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
API_PREFIX=/api/v1
EOF
    chmod 600 "$BACKEND_DIR/.env"
    echo "  [OK] .env created with random secrets"
fi

# ============================================================
# STEP 6: Create Upload Directory
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 6: Creating secure upload directory..."
echo "------------------------------------------------------"

mkdir -p "$BACKEND_DIR/uploads"
chmod 700 "$BACKEND_DIR/uploads"
echo "  [OK] uploads/ directory ready (permissions: 700)"

# ============================================================
# STEP 7: Setup PostgreSQL Database
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 7: Setting up PostgreSQL database..."
echo "------------------------------------------------------"

echo "  Checking if PostgreSQL is running..."
if sudo systemctl is-active --quiet postgresql 2>/dev/null; then
    echo "  [OK] PostgreSQL is running"
else
    echo "  Starting PostgreSQL..."
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    echo "  [OK] PostgreSQL started"
fi

echo ""
echo "  Creating database user and database..."
echo "  (You may need to enter your sudo password)"
echo ""

USER_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='secureadmin'" 2>/dev/null || echo "0")
if [ "$USER_EXISTS" = "1" ]; then
    echo "  Database user 'secureadmin' already exists"
else
    sudo -u postgres psql -c "CREATE USER secureadmin WITH PASSWORD 'FortKnoxPass123!';" 2>/dev/null
    echo "  [OK] Created database user 'secureadmin'"
fi

DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='securejobdb'" 2>/dev/null || echo "0")
if [ "$DB_EXISTS" = "1" ]; then
    echo "  Database 'securejobdb' already exists"
    read -p "  Drop and recreate? (yes/no): " recreate_db
    if [ "$recreate_db" = "yes" ]; then
        sudo -u postgres psql -c "DROP DATABASE securejobdb;" 2>/dev/null
        sudo -u postgres psql -c "CREATE DATABASE securejobdb OWNER secureadmin;" 2>/dev/null
        echo "  [OK] Database recreated"
    fi
else
    sudo -u postgres psql -c "CREATE DATABASE securejobdb OWNER secureadmin;" 2>/dev/null
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE securejobdb TO secureadmin;" 2>/dev/null
    echo "  [OK] Created database 'securejobdb'"
fi

# ============================================================
# STEP 8: Create Database Tables
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 8: Creating database tables..."
echo "------------------------------------------------------"

cd "$BACKEND_DIR"
python3 -c "
from dotenv import load_dotenv
load_dotenv()
from app.database import engine
from app import models
models.Base.metadata.create_all(bind=engine)
print('  [OK] All database tables created')
"

# ============================================================
# STEP 9: Create Superadmin Account
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 9: Superadmin account setup..."
echo "------------------------------------------------------"

read -p "Create/update superadmin account? (yes/no): " create_sa
if [ "$create_sa" = "yes" ]; then
    read -p "  Superadmin email: " SA_EMAIL
    read -sp "  Superadmin password: " SA_PASS
    echo ""
    read -p "  Superadmin full name: " SA_NAME
    python3 create_superadmin.py "$SA_EMAIL" "$SA_PASS" "$SA_NAME"
fi

# ============================================================
# STEP 10: Install Frontend Dependencies
# ============================================================
echo ""
echo "------------------------------------------------------"
echo "STEP 10: Installing frontend dependencies..."
echo "------------------------------------------------------"

cd "$FRONTEND_DIR"
npm install --silent 2>/dev/null
echo "  [OK] Frontend dependencies installed"

# ============================================================
# DONE!
# ============================================================
echo ""
echo "======================================================"
echo "   SETUP COMPLETE!"
echo "======================================================"
echo ""
echo "What was set up:"
echo "   - Python virtual environment (../fcs-project)"
echo "   - All Python packages from requirements.txt"
echo "   - SSL certificates (key.pem, cert.pem)"
echo "   - Environment file (.env) with random secrets"
echo "   - Secure upload directory"
echo "   - PostgreSQL database (securejobdb)"
echo "   - All database tables"
echo "   - Frontend Node.js dependencies"
echo ""
echo "To start the project:"
echo ""
echo "   Terminal 1 (Backend):"
echo "     cd $BACKEND_DIR"
echo "     source ../fcs-project/bin/activate"
echo "     uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload"
echo ""
echo "   Terminal 2 (Frontend):"
echo "     cd $FRONTEND_DIR"
echo "     npm start"
echo ""
echo "IMPORTANT: Before using the frontend, open https://127.0.0.1:8000"
echo "   in your browser and accept the self-signed certificate!"
echo ""
echo "API Docs: https://127.0.0.1:8000/docs"
echo "Frontend: http://localhost:3000"
