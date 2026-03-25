# 🛠️ FortKnox — Complete Setup Guide

**For Teammates**: This guide walks you through setting up the project from scratch after cloning from GitHub.

---

## Prerequisites

You need these installed on your laptop **before** starting:

| Software | Version | Install Command (Ubuntu/Debian) |
|----------|---------|-------------------------------|
| Python | 3.12+ | `sudo apt install python3 python3-pip python3-venv` |
| PostgreSQL | 14+ | `sudo apt install postgresql postgresql-contrib` |
| Node.js | 18+ | `sudo apt install nodejs npm` |
| OpenSSL | any | `sudo apt install openssl` (usually pre-installed) |
| Git | any | `sudo apt install git` |

**Verify installations:**
```bash
python3 --version   # Should show 3.12.x
psql --version      # Should show 14.x+
node --version      # Should show v18.x+
npm --version       # Should show 9.x+
openssl version     # Should show OpenSSL 3.x
```

---

## Step 1: Clone the Repository

```bash
cd ~/Desktop
git clone <your-github-repo-url> "FCS Project"
cd "FCS Project"
```

---

## Step 2: Database Setup

### 2.1 Start PostgreSQL
```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql  # Auto-start on boot
```

### 2.2 Create Database User and Database
```bash
# Switch to postgres user and open PostgreSQL shell
sudo -u postgres psql
```

In the PostgreSQL shell, run these commands **exactly**:
```sql
-- Create the database user
CREATE USER secureadmin WITH PASSWORD 'FortKnoxPass123!';

-- Create the database
CREATE DATABASE securejobdb OWNER secureadmin;

-- Grant all privileges
GRANT ALL PRIVILEGES ON DATABASE securejobdb TO secureadmin;

-- Exit
\q
```

### 2.3 Verify Database Connection
```bash
psql -U secureadmin -d securejobdb -h localhost
# Enter password: FortKnoxPass123!
# If you see the psql prompt, it works. Type \q to exit.
```

**If you get a "peer authentication failed" error**, edit PostgreSQL config:
```bash
sudo nano /etc/postgresql/*/main/pg_hba.conf
```
Find the line with `local all all peer` and change `peer` to `md5`:
```
local   all   all   md5
```
Then restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

---

## Step 3: Backend Setup

### 3.1 Create Virtual Environment
```bash
cd backend
python3 -m venv ../fcs-project
source ../fcs-project/bin/activate
```

**You should see `(fcs-project)` in your terminal prompt.** All Python commands below must be run with this venv active.

### 3.2 Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 Generate SSL Certificates
Each teammate needs their own SSL certificate (these are **NOT** committed to git):
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -sha256 -days 365 -nodes \
  -subj "/C=IN/ST=Delhi/L=NewDelhi/O=IIITD/CN=SecureJobPlatform"
```

This creates two files:
- `key.pem` — Private key (keep secret)
- `cert.pem` — Public certificate

### 3.4 Create the `.env` File
The `.env` file contains all secrets and is **NOT committed to git**. Each teammate must create their own.

**Option A: Auto-generate (recommended)**
```bash
bash setup.sh
```
This creates `.env` with random secrets automatically.

**Option B: Manual creation**
Create `backend/.env` with this content:
```env
# JWT Authentication
JWT_SECRET_KEY=<paste-a-random-32-byte-base64-string>
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30

# Database (match what you created in Step 2)
DATABASE_URL=postgresql://secureadmin:FortKnoxPass123!@localhost/securejobdb

# SMTP Email (for OTP) — use the shared team credentials
SMTP_USERNAME=fortknox914@gmail.com
SMTP_PASSWORD=lrigfpadqfothkxs
SMTP_FROM=fortknox914@gmail.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587

# Encryption Keys
RESUME_MASTER_KEY=<paste-a-random-32-byte-base64-string>
AUDIT_HMAC_KEY=<paste-a-random-32-byte-base64-string>

# Server PKI Key
SERVER_PKI_KEY_PATH=server_private_key.pem

# Environment
ENVIRONMENT=development
ALLOW_TEST_ACCOUNTS=true

# API Path Prefix
API_PREFIX=/api/v1
```

**Generate random keys with:**
```bash
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```
Run this 3 times and paste each output into `JWT_SECRET_KEY`, `RESUME_MASTER_KEY`, and `AUDIT_HMAC_KEY`.

### 3.5 Create Upload Directory
```bash
mkdir -p uploads
chmod 700 uploads
```

### 3.6 Initialize Database Tables
Start the server once to auto-create all tables:
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 \
  --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```
Wait until you see `Application startup complete`, then press `Ctrl+C` to stop.

### 3.7 Create Superadmin Account
```bash
python create_superadmin.py your-email@iiitd.ac.in "YourStr0ngP@ss123!" "Your Name"
```
Replace with your actual email and a strong password. This account has full admin powers.

### 3.8 Start the Backend Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 \
  --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload
```

**Keep this terminal open.** The server runs on `https://127.0.0.1:8000`.

---

## Step 4: Frontend Setup

### 4.1 Install Node Dependencies
Open a **new terminal**:
```bash
cd ~/Desktop/FCS\ Project/frontend
npm install
```

### 4.2 Accept Self-Signed Certificate
Before starting the frontend, open your browser and go to:
```
https://127.0.0.1:8000
```
You'll see a security warning. Click **"Advanced"** → **"Proceed to 127.0.0.1 (unsafe)"**.

This tells your browser to trust the self-signed certificate. **You must do this or API calls will fail.**

### 4.3 Start the Frontend
```bash
npm start
```

The app opens at `http://localhost:3000`.

---

## Step 5: Verify Everything Works

1. Open `http://localhost:3000` in your browser
2. Click **Register** → Create an account (use an `@iiitd.ac.in` email or set `ALLOW_TEST_ACCOUNTS=true`)
3. Check your email for the OTP
4. Enter the OTP to verify your account
5. Log in with your credentials
6. You should see the Dashboard

---

## How to Recreate the Database

If you need to completely reset the database (e.g., after model changes):

```bash
# 1. Drop and recreate the database
sudo -u postgres psql -c "DROP DATABASE IF EXISTS securejobdb;"
sudo -u postgres psql -c "CREATE DATABASE securejobdb OWNER secureadmin;"

# 2. Start the backend to auto-create tables
cd ~/Desktop/FCS\ Project/backend
source ../fcs-project/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000 \
  --ssl-keyfile=key.pem --ssl-certfile=cert.pem

# 3. Stop (Ctrl+C), then recreate superadmin
python create_superadmin.py admin@iiitd.ac.in "YourStr0ngP@ss123!" "Admin Name"

# 4. Restart the server
uvicorn main:app --host 127.0.0.1 --port 8000 \
  --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload
```

---

## VM Deployment (Production)

When deploying on the college VM for testing:

### 1. Set Production Mode
Edit `backend/.env`:
```env
ENVIRONMENT=production
ALLOW_TEST_ACCOUNTS=false
API_PREFIX=/api/v1/fk9x2m
```

### 2. Run the Deployment Script
```bash
cd ~/Desktop/FCS\ Project/backend
sudo bash deploy.sh
```

This automatically:
- Configures UFW firewall (opens only ports 22, 8000, 3000)
- Blocks PostgreSQL, Telnet, FTP, SMB external access
- Installs systemd auto-restart service
- Applies kernel-level security (SYN flood, anti-spoofing, ICMP disabled)
- Sets secure file permissions

### 3. Start Services
```bash
# Backend (auto-restarts on crash)
sudo systemctl start fortknox-backend
sudo systemctl status fortknox-backend

# Frontend (production build — no source maps)
cd ~/Desktop/FCS\ Project/frontend
npm run build:prod
npx serve -s build -l 3000
```

### 4. Check Logs
```bash
sudo journalctl -u fortknox-backend -f
```

---

## Troubleshooting

### "Could not find import" errors in IDE
These are **not real errors**. Your IDE's Python analyzer isn't using the virtual environment. The file `pyrightconfig.json` should fix this. If not:
1. In VS Code: `Ctrl+Shift+P` → "Python: Select Interpreter" → Choose `../fcs-project/bin/python3`
2. Or ignore them — the code runs correctly in the venv

### "SSL certificate error" in browser
Go to `https://127.0.0.1:8000` and accept the self-signed certificate.

### "CORS error" in browser console
Make sure both backend (port 8000) and frontend (port 3000) are running on `localhost`.

### "Authentication failed" for PostgreSQL
Edit `/etc/postgresql/*/main/pg_hba.conf`: change `peer` to `md5`, then `sudo systemctl restart postgresql`.

### "Module not found" when running Python
Make sure you activated the virtual environment: `source ../fcs-project/bin/activate`

### Database "table already exists" errors
This is normal if tables already exist. The app handles this gracefully.

### "Session expired" alert
This means you (or someone else) logged in from another device. Only one session per user is allowed.

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| Start backend | `source ../fcs-project/bin/activate && uvicorn main:app --host 127.0.0.1 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem --reload` |
| Start frontend | `cd frontend && npm start` |
| Create superadmin | `python create_superadmin.py email password "Name"` |
| Reset database | `sudo -u postgres psql -c "DROP DATABASE securejobdb;" && sudo -u postgres psql -c "CREATE DATABASE securejobdb OWNER secureadmin;"` |
| Deploy on VM | `sudo bash deploy.sh` |
| Check backend status | `sudo systemctl status fortknox-backend` |
| View backend logs | `sudo journalctl -u fortknox-backend -f` |
| Build frontend (prod) | `cd frontend && npm run build:prod` |

---

## Files You Need to Create Yourself (NOT in Git)

These files are in `.gitignore` and each teammate must generate their own:

| File | How to Create | Location |
|------|--------------|----------|
| `.env` | Run `bash setup.sh` or create manually (see Step 3.4) | `backend/.env` |
| `key.pem` | Run `openssl req ...` command (see Step 3.3) | `backend/key.pem` |
| `cert.pem` | Created alongside `key.pem` | `backend/cert.pem` |
| `server_private_key.pem` | Auto-generated on first server start | `backend/server_private_key.pem` |
| `uploads/` directory | `mkdir -p uploads && chmod 700 uploads` | `backend/uploads/` |
| PostgreSQL database | Follow Step 2 | System-level |
| Virtual environment | `python3 -m venv ../fcs-project` | `../fcs-project/` |
