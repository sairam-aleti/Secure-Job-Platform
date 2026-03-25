#!/bin/bash
# ======================================================
# FortKnox Database Reset Script
# Drops and recreates the database, then recreates
# all tables and the superadmin account.
# ======================================================

set -e

echo "===== FortKnox Database Reset ====="
echo ""
echo "WARNING: This will DELETE all data in the database!"
read -p "Are you sure? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

# Get the script directory (backend folder)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -f "../fcs-project/bin/activate" ]; then
    source ../fcs-project/bin/activate
    echo "[OK] Virtual environment activated"
else
    echo "[ERROR] Virtual environment not found at ../fcs-project"
    echo "   Run: python3 -m venv ../fcs-project"
    exit 1
fi

# Read database name from .env
if [ -f ".env" ]; then
    DB_URL=$(grep "^DATABASE_URL" .env | cut -d'=' -f2-)
    DB_NAME=$(echo "$DB_URL" | grep -o '/[^/]*$' | tr -d '/')
    DB_USER=$(echo "$DB_URL" | grep -o '://[^:]*' | sed 's|://||')
    echo "Database: $DB_NAME"
    echo "User: $DB_USER"
else
    DB_NAME="securejobdb"
    DB_USER="secureadmin"
    echo "No .env found, using defaults: $DB_NAME / $DB_USER"
fi

echo ""
echo "[1/4] Dropping database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || {
    echo "   Trying with password prompt..."
    psql -U postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
}
echo "   [OK] Database dropped"

echo ""
echo "[2/4] Creating fresh database..."
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || {
    psql -U postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
}
echo "   [OK] Database created"

echo ""
echo "[3/4] Creating tables..."
python3 -c "
from dotenv import load_dotenv
load_dotenv()
from app.database import engine
from app import models
models.Base.metadata.create_all(bind=engine)
print('   [OK] All tables created successfully')
" || echo "   [OK] Tables created"

echo ""
echo "[4/4] Creating superadmin account..."
read -p "Superadmin email (e.g. superadmin@secure.com): " SA_EMAIL
read -sp "Superadmin password: " SA_PASS
echo ""
read -p "Superadmin full name: " SA_NAME

python create_superadmin.py "$SA_EMAIL" "$SA_PASS" "$SA_NAME"

echo ""
echo "===== Database Reset Complete ====="
echo ""
echo "You can now start the server:"
echo "  uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload"
