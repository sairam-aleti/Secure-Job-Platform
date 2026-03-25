# 🔒 FortKnox — Complete Security Report

**Project**: Secure Job Search & Professional Networking Platform  
**Course**: CSE 345/545 Foundations of Computer Security  
**Date**: March 2026

---

## 1. Project Architecture

```
backend/
├── main.py               # FastAPI server — ALL API endpoints, middleware, security
├── app/
│   ├── auth.py           # JWT authentication, single-session, fingerprint, superadmin
│   ├── database.py       # PostgreSQL connection (env-driven)
│   ├── encryption.py     # AES-256-GCM file encryption + envelope encryption
│   ├── models.py         # SQLAlchemy ORM models (10 tables)
│   ├── otp.py            # TOTP generation, expiry, lockout
│   ├── parser.py         # PDF text extraction (for skill matching)
│   ├── schemas.py        # Pydantic validation schemas
│   └── security.py       # Argon2id password hashing
├── .env                  # All secrets (NEVER committed)
├── setup.sh              # Initial setup (venv, deps, certs, .env generation)
├── deploy.sh             # Production deployment (firewall, systemd, kernel hardening)
├── create_superadmin.py  # CLI utility for superadmin creation
├── fortknox-backend.service  # Systemd auto-restart service
└── pyrightconfig.json    # IDE type checker config

frontend/
├── public/index.html     # Anti-DevTools defenses (F12, view-source, right-click blocked)
├── src/
│   ├── services/
│   │   ├── api.js        # Axios HTTP client, session-conflict auto-logout
│   │   └── cryptoService.js  # RSA key gen, hybrid AES+RSA E2EE, PBKDF2 key derivation
│   ├── pages/
│   │   ├── Login.js      # Derives PBKDF2 key from password (never stores raw password)
│   │   ├── Dashboard.js  # E2EE key setup using derived key
│   │   ├── Chat.js       # E2EE messaging using derived key
│   │   ├── Admin.js      # Admin panel (suspend/delete queued for superadmin)
│   │   ├── Register.js   # User registration (admin role allowed, needs approval)
│   │   ├── VerifyOTP.js  # OTP verification
│   │   ├── Profile.js    # User profile management
│   │   ├── Network.js    # Connection management
│   │   ├── JobBoard.js   # Job listings with skill matching
│   │   ├── PostJob.js    # Job posting (recruiter only)
│   │   ├── Apply.js      # Job application
│   │   └── ...           # Other pages
│   └── components/
│       └── VirtualKeyboard.js  # On-screen keyboard (anti-keylogger)
```

---

## 2. Security Measures by Attack Category

### A. SQL Injection ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Parameterized queries | SQLAlchemy ORM — all queries use bound parameters, never string concatenation | `main.py` (all endpoints) |
| LIKE escape | Special characters `%` and `_` escaped before LIKE queries | `main.py` line 180, `escape_like()` |
| Input validation | Max lengths on all string fields, regex patterns for names | `schemas.py` |

### B. Cross-Site Scripting (XSS) ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'` — blocks inline scripts and external sources | `main.py` middleware |
| X-XSS-Protection | `1; mode=block` — browser XSS filter enabled | `main.py` middleware |
| X-Content-Type-Options | `nosniff` — prevents MIME-type sniffing | `main.py` middleware |
| Input sanitization | Name regex validation `^[a-zA-Z\s.\-']+$`, max_length on all fields | `schemas.py` |
| React auto-escaping | React JSX auto-escapes rendered content by default | All frontend pages |

### C. Cross-Site Request Forgery (CSRF) ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Bearer token auth | All state-changing requests require `Authorization: Bearer <JWT>` header — CSRF attacks can't add custom headers | `auth.py` |
| SameSite implicit | Tokens in localStorage (not cookies) — CSRF only exploits cookies | `api.js` |
| Restricted CORS | Only `localhost:3000` allowed, credentials require exact origin match | `main.py` CORS config |

### D. Insecure Direct Object Reference (IDOR) ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Ownership verification | Resume download checks `resume.user_id == current_user.id` | `main.py /download-resume` |
| Company ownership | Job posting requires `company.recruiter_id == user.id` | `main.py /jobs` |
| Connection validation | Messages require accepted connection or application relationship | `main.py /messages` |
| Role-based access | Admin endpoints require `require_admin`, superadmin endpoints require `require_superadmin` | `auth.py` |

### E. Broken Authentication ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Argon2id hashing | Industry-leading password hash algorithm (memory-hard, time-hard) | `security.py` |
| Password strength | Min 12 chars, uppercase, digit, special char required | `schemas.py` |
| JWT with short expiry | 30-minute expiry, HS256 signed with 256-bit secret | `auth.py` |
| Single session | One active session per user — new login invalidates previous | `auth.py`, `main.py /login` |
| Account lockout | 5 failed OTP attempts → 20-minute lockout | `otp.py`, `main.py` |
| OTP expiry | 2-minute OTP validity window | `otp.py` |
| DB role cross-check | Every authenticated request verifies user role/status against database | `auth.py get_current_user` |

### F. Broken Access Control ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Admin registration restricted | Admin can register but destructive actions need superadmin approval | `schemas.py`, `main.py` |
| Superadmin queue | Suspend/delete/activate queued for superadmin approval | `main.py /admin/request-action` |
| Superadmin CLI only | Superadmin cannot be created via API — only via `create_superadmin.py` | `create_superadmin.py` |
| Field whitelisting | Profile update only allows specific fields (not role, email, etc.) | `main.py /profile PUT` |
| Privacy settings | Profile fields have individual privacy controls | `models.py`, `main.py` |

### G. Insecure File Uploads ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| File type validation | Only `.pdf` and `.docx` allowed (extension + magic byte check) | `main.py /upload-resume` |
| Magic byte verification | Checks `%PDF` or `PK\x03\x04` file headers | `main.py validate_file_content()` |
| 10MB size limit | Rejects files larger than 10MB | `main.py /upload-resume` |
| AES-256-GCM encryption | All uploaded resumes encrypted at rest | `encryption.py` |
| Server-side filename | Stored with UUID filename, original name sanitized | `main.py` |
| Content-Disposition sanitization | Path traversal characters stripped from download headers | `main.py sanitize_filename()` |

### H. Path Traversal ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| `os.path.basename()` | Strips directory components from filenames | `main.py sanitize_filename()` |
| Regex sanitization | `[^\w\s\-\.]` replaced with underscores | `main.py sanitize_filename()` |
| Length limit | Filename truncated to 200 characters | `main.py sanitize_filename()` |

### I. Weak Cryptography ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| AES-256-GCM | Resume encryption at rest (authenticated encryption) | `encryption.py` |
| RSA-2048 OAEP | Public key encryption for E2EE messages | `cryptoService.js` |
| Hybrid encryption | AES-256-CBC + RSA-OAEP key wrapping (no message size limit) | `cryptoService.js` |
| PBKDF2 key derivation | 100,000 iterations, random 16-byte salt, SHA-256 | `cryptoService.js` |
| Envelope encryption | Per-file AES keys encrypted with master key (AESGCM) | `encryption.py` |
| HMAC-SHA256 audit chain | Tamper-evident audit log hash chain | `main.py create_audit_log()` |
| PKI signatures | Server signs resume uploads with RSA-PSS | `main.py` |
| Persistent PKI key | Server key saved to PEM file, survives restarts | `main.py _load_or_generate_server_key()` |

### J. Hardcoded Secrets ✅ PROTECTED

| Secret | Source | Location |
|--------|--------|----------|
| JWT_SECRET_KEY | `.env` file | `auth.py` |
| DATABASE_URL | `.env` file | `database.py` |
| SMTP credentials | `.env` file | `main.py` |
| RESUME_MASTER_KEY | `.env` file | `encryption.py` |
| AUDIT_HMAC_KEY | `.env` file | `main.py` |
| All secrets | `.gitignore` prevents commit | `.gitignore` |

### K. Encryption at Rest (Resumes) ✅ PROTECTED

| Layer | Implementation |
|-------|---------------|
| File encryption | AES-256-GCM per-file with random key + nonce |
| Key protection | Per-file key envelope-encrypted with RESUME_MASTER_KEY |
| Master key | Stored in `.env`, never in database |
| Signature | RSA-PSS signature for integrity verification |

### L. Missing HTTPS ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| HTTPS enforcement | Server runs with `--ssl-keyfile=key.pem --ssl-certfile=cert.pem` | `setup.sh`, `fortknox-backend.service` |
| HSTS header | `Strict-Transport-Security: max-age=31536000; includeSubDomains` | `main.py` middleware |
| RSA-4096 certificate | Self-signed cert generated during setup | `setup.sh` |

### M. OTP Flaws ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| No reuse | `is_used = True` set after verification | `main.py /verify-otp` |
| 2-minute expiry | Time-based validation against creation timestamp | `otp.py is_otp_expired()` |
| Rate limiting | 5 attempts per 15 minutes on OTP send | `main.py /send-otp` |
| Account lockout | 5 failed attempts → 20-minute lock | `main.py /verify-otp`, `otp.py` |

### N. Session Hijacking / Fixation ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Single session | JTI stored in DB, only one active session per user | `auth.py`, `main.py /login` |
| Fingerprint binding | User-Agent + Accept-Language hash stored per session | `auth.py compute_fingerprint()` |
| Short JWT expiry | 30-minute token lifetime | `auth.py` |
| Session-conflict logout | Frontend detects 401 "Session expired" → forced logout | `api.js` interceptor |
| No raw password storage | Only PBKDF2-derived key in sessionStorage | `Login.js` |

### O. CORS / Same-Origin Policy ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Restricted origins | Only `localhost:3000` allowed | `main.py` CORS config |
| Restricted methods | Only GET, POST, PUT, DELETE | `main.py` CORS config |
| Restricted headers | Only Content-Type and Authorization | `main.py` CORS config |
| CSP header | `default-src 'self'; script-src 'self'; connect-src 'self' https://127.0.0.1:8000` | `main.py` middleware |
| X-Frame-Options | `DENY` — prevents clickjacking | `main.py` middleware |

### P. Debug Endpoints ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Swagger disabled in prod | `docs_url=None` when `ENVIRONMENT=production` | `main.py` |
| ReDoc disabled in prod | `redoc_url=None` when `ENVIRONMENT=production` | `main.py` |
| OpenAPI disabled in prod | `openapi_url=None` when `ENVIRONMENT=production` | `main.py` |
| No print statements | All replaced with `logging` module | `parser.py`, `main.py` |

### Q. DoS Protection ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Rate limiting (login) | 10 requests/minute per IP | `main.py /login` |
| Rate limiting (register) | 10 requests/minute per IP | `main.py /register` |
| Rate limiting (OTP) | 5 requests/15 minutes per IP | `main.py /send-otp` |
| File size limit | 10MB max upload | `main.py /upload-resume` |
| SYN flood protection | `tcp_syncookies = 1` kernel setting | `deploy.sh` |
| UFW firewall | Default deny, only 3 ports open | `deploy.sh` |
| Systemd auto-restart | Restarts within 5 seconds of crash | `fortknox-backend.service` |

### R. Server Fingerprinting ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| Server header | Replaced with `"FortKnox"` (hides FastAPI/Uvicorn) | `main.py` middleware |
| X-Powered-By | Removed | `main.py` middleware |
| ICMP disabled | `icmp_echo_ignore_all = 1` | `deploy.sh` kernel config |
| API obfuscation | Configurable `API_PREFIX` env var | `main.py` |

### S. Anti-Red-Team Defenses ✅ PROTECTED

| Defense | Implementation | Location |
|---------|---------------|----------|
| DevTools blocked | F12, Ctrl+Shift+I/J/C, Ctrl+U disabled | `index.html` |
| Right-click disabled | Context menu blocked | `index.html` |
| Debugger detection | Timing-based detection shows security warning | `index.html` |
| Source maps removed | `build:prod` script strips source maps | `package.json` |
| Virtual keyboard | Anti-keylogger input option | `VirtualKeyboard.js` |
| Request tracing | X-Request-ID on all responses | `main.py` middleware |

---

## 3. File-by-File Description

### Backend Files

| File | Purpose | Key Security Features |
|------|---------|----------------------|
| `main.py` | Core API server (all 40+ endpoints) | Rate limiting, security headers, CORS, HMAC audit logs, PKI signatures, envelope encryption, magic byte validation, brute-force protection, connection validation, company ownership check, single-session login, API prefix, server de-fingerprinting |
| `auth.py` | JWT authentication & authorization | Token creation with JTI, single-session enforcement, browser fingerprint binding, `get_current_user` with DB cross-check, `require_admin`, `require_superadmin` |
| `database.py` | Database connection | PostgreSQL URL from env var with fallback |
| `encryption.py` | File encryption | AES-256-GCM encrypt/decrypt, 12-byte nonce, envelope encryption with master key |
| `models.py` | Database schema (10 tables) | User, OTP, Resume, Company, Job, Application, Message, AuditLog, Connection, ProfileView, AdminActionQueue. ForeignKey constraints with ON DELETE CASCADE |
| `otp.py` | OTP management | TOTP generation (pyotp), 2-minute expiry, 5-attempt lockout, 20-minute lockout duration |
| `parser.py` | Resume parsing | PDF text extraction using pypdf, logging-based error handling |
| `schemas.py` | Input validation | Pydantic models with max_length, Literal types, email validation, password strength, name regex, admin action queue schemas |
| `security.py` | Password hashing | Argon2id via passlib (memory-hard, GPU-resistant) |
| `.env` | Secrets configuration | JWT key, DB URL, SMTP, encryption keys, HMAC key, environment mode |
| `setup.sh` | Initial setup script | Creates venv, installs deps, generates SSL certs (RSA-4096), auto-generates `.env` with random secrets |
| `deploy.sh` | Production deployment | UFW firewall, kernel hardening, systemd service install, port blocking, file permissions |
| `create_superadmin.py` | Superadmin creation | CLI-only utility, creates/upgrades superadmin accounts |
| `fortknox-backend.service` | Auto-restart | Systemd service with `Restart=always`, sandboxing |

### Frontend Files

| File | Purpose | Key Security Features |
|------|---------|----------------------|
| `index.html` | HTML entry point | Anti-DevTools (F12, Ctrl+U, right-click blocked), debugger detection, text selection/drag disabled |
| `api.js` | HTTP client | Bearer token injection, session-conflict auto-logout (401 detection), admin action queue APIs |
| `cryptoService.js` | E2EE cryptography | RSA-2048 key generation, hybrid AES+RSA encryption, PBKDF2 key derivation (100K iterations, random salt), backward compatibility |
| `Login.js` | Login page | PBKDF2 derived key replaces raw password in sessionStorage |
| `Dashboard.js` | Main dashboard | E2EE key setup using derived key |
| `Chat.js` | E2EE messaging | Private key decryption using derived key, hybrid message encryption/decryption |
| `VirtualKeyboard.js` | On-screen keyboard | Anti-keylogger input |
| `Register.js` | Registration | Role selection (job_seeker, recruiter, admin) |
| `Admin.js` | Admin panel | User listing, suspend/delete/activate (queued for superadmin) |

---

## 4. Compliance with Project Requirements

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| A. User Profiles & Connections | ✅ | Profile CRUD, privacy settings, connection requests |
| B. Company Pages | ✅ | Company creation (recruiter-only), listing |
| C. Job Postings | ✅ | Post, list, recommendations, skill matching |
| D. Resume Management | ✅ | Upload (PDF/DOCX), encrypted storage, download |
| E. Application Tracking | ✅ | Apply, status updates, recruiter view |
| F. OTP Authentication | ✅ | TOTP generation, email delivery, expiry, lockout |
| G. Password Security | ✅ | Argon2id hashing, strength validation, secure reset |
| H. PKI / Digital Signatures | ✅ | Server RSA key, resume signing, E2EE message signing |
| I. End-to-End Encryption | ✅ | RSA-2048 key pairs, hybrid AES+RSA messages |
| J. Audit Logging | ✅ | HMAC-SHA256 hash chain, all critical actions logged |
| K. Access Control | ✅ | Role-based (job_seeker, recruiter, admin, superadmin) |
| L. Encryption at Rest | ✅ | AES-256-GCM + envelope encryption for resumes |
