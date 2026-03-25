# 🛠️ FortKnox — Setup Guide

## Quick Setup (Automated)

After cloning from GitHub, run **one script** and it handles everything:

```bash
cd "FCS Project/backend"
bash auto_setup.sh
```

This automatically:
1. ✅ Checks prerequisites (Python, PostgreSQL, Node.js, OpenSSL) and offers to install missing ones
2. ✅ Creates Python virtual environment
3. ✅ Installs all Python packages from `requirements.txt`
4. ✅ Generates SSL certificates (`key.pem`, `cert.pem`)
5. ✅ Creates `.env` file with cryptographically random secrets
6. ✅ Creates secure upload directory
7. ✅ Sets up PostgreSQL (creates user `secureadmin` + database `securejobdb`)
8. ✅ Creates all database tables
9. ✅ Prompts to create superadmin account
10. ✅ Installs frontend Node.js dependencies

**After setup, start the project:**

```bash
# Terminal 1 — Backend
cd backend
source ../fcs-project/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload

# Terminal 2 — Frontend
cd frontend
npm start
```

⚠️ **Before using the frontend**, open `https://127.0.0.1:8000` in your browser and accept the self-signed certificate (click Advanced → Proceed).

---

## Manual Setup (Step by Step)

If the automated script doesn't work on your system, follow these steps:

### Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib nodejs npm openssl
```

### 1. Virtual Environment
```bash
cd "FCS Project/backend"
python3 -m venv ../fcs-project
source ../fcs-project/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. SSL Certificates
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes \
  -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform"
```

### 3. Environment File
```bash
bash setup.sh   # Auto-generates .env with random secrets
# OR create backend/.env manually — see .env.example
```

### 4. PostgreSQL Database
```bash
sudo systemctl start postgresql
sudo -u postgres psql
```
```sql
CREATE USER secureadmin WITH PASSWORD 'FortKnoxPass123!';
CREATE DATABASE securejobdb OWNER secureadmin;
GRANT ALL PRIVILEGES ON DATABASE securejobdb TO secureadmin;
\q
```

If you get "peer authentication failed":
```bash
sudo nano /etc/postgresql/*/main/pg_hba.conf
# Change: local all all peer → local all all md5
sudo systemctl restart postgresql
```

### 5. Create Tables & Superadmin
```bash
source ../fcs-project/bin/activate

# Create tables (start server briefly)
python3 -c "
from dotenv import load_dotenv; load_dotenv()
from app.database import engine; from app import models
models.Base.metadata.create_all(bind=engine)
print('Tables created')
"

# Create superadmin
python create_superadmin.py superadmin@secure.com "YourP@ssword123!" "Super Admin"
```

### 6. Frontend
```bash
cd ../frontend
npm install
npm start
```

---

## Reset Database

When you need to wipe everything and start fresh:
```bash
cd backend
source ../fcs-project/bin/activate
bash reset_database.sh
```

Or manually:
```bash
sudo -u postgres psql -c "DROP DATABASE IF EXISTS securejobdb;"
sudo -u postgres psql -c "CREATE DATABASE securejobdb OWNER secureadmin;"

source ../fcs-project/bin/activate
python3 -c "
from dotenv import load_dotenv; load_dotenv()
from app.database import engine; from app import models
models.Base.metadata.create_all(bind=engine)
"
python create_superadmin.py superadmin@secure.com "YourP@ssword123!" "Super Admin"
```

---

## VM Deployment

`deploy.sh` is for production VM deployment. It does NOT start the server — it hardens the VM:
- Configures UFW firewall (opens only ports 22, 8000, 3000)
- Blocks PostgreSQL/Telnet/FTP/SMB from external access
- Installs systemd auto-restart service
- Applies kernel-level security (SYN flood protection, anti-spoofing)

```bash
sudo bash deploy.sh      # Hardens the VM
sudo systemctl start fortknox-backend   # Starts backend (auto-restarts on crash)
```

For red team testing, set in `.env`:
```
ENVIRONMENT=production
ALLOW_TEST_ACCOUNTS=false
```

---

## Files NOT in Git (each teammate creates their own)

| File | Created by |
|------|-----------|
| `.env` | `auto_setup.sh` or `setup.sh` |
| `key.pem` / `cert.pem` | `auto_setup.sh` or `openssl` command |
| `server_private_key.pem` | Auto-generated on first server start |
| `uploads/` | `auto_setup.sh` or `mkdir -p uploads` |
| PostgreSQL database | `auto_setup.sh` or manual SQL |
| Virtual environment | `auto_setup.sh` or `python3 -m venv` |

---

## Quick Reference

| Task | Command |
|------|---------|
| Start backend | `source ../fcs-project/bin/activate && uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload` |
| Start frontend | `cd frontend && npm start` |
| API docs | `https://127.0.0.1:8000/docs` |
| Create superadmin | `python create_superadmin.py email password "Name"` |
| Reset database | `bash reset_database.sh` |
| Deploy on VM | `sudo bash deploy.sh` |
| View backend logs | `sudo journalctl -u fortknox-backend -f` |
| Build frontend (prod) | `cd frontend && npm run build:prod` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| IDE shows "Could not find import" errors | Not real errors — IDE isn't using the venv. Ignore them or select the venv interpreter |
| `/docs` shows blank page | Restart the backend server (`Ctrl+C` then re-run uvicorn) |
| "SSL certificate error" in browser | Go to `https://127.0.0.1:8000`, click Advanced → Proceed |
| "CORS error" | Make sure both backend (8000) and frontend (3000) are on localhost |
| "Authentication failed" for PostgreSQL | Edit `pg_hba.conf`: change `peer` to `md5`, restart PostgreSQL |
| "Module not found" | Activate venv: `source ../fcs-project/bin/activate` |
| "Session expired" alert | Someone logged in from another device (single-session enforcement) |
| Login fails after code changes | Database needs reset — run `bash reset_database.sh` |
