#!/bin/bash
# ======================================================
# FortKnox VM Deployment Script
# Handles: Firewall, Port Hardening, Service Installation
# Run as root: sudo bash deploy.sh
# ======================================================

set -e
echo "===== FortKnox VM Deployment & Hardening ====="

# --- 1. FIREWALL SETUP (UFW) ---
echo "[1/5] Configuring Firewall..."

# Install UFW if not present
apt-get update -qq && apt-get install -y -qq ufw > /dev/null

# Reset to clean state
ufw --force reset

# Default policies: deny everything incoming, allow outgoing
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (so you don't get locked out)
ufw allow 22/tcp comment 'SSH'

# Allow HTTPS backend (FastAPI on 8000)
ufw allow 8000/tcp comment 'FortKnox Backend HTTPS'

# Allow React frontend dev server
ufw allow 3000/tcp comment 'FortKnox Frontend'

# Allow PostgreSQL ONLY from localhost (block external DB access)
ufw deny 5432/tcp comment 'Block external PostgreSQL'

# Block common attack ports
ufw deny 23/tcp comment 'Block Telnet'
ufw deny 21/tcp comment 'Block FTP'
ufw deny 69/udp comment 'Block TFTP'
ufw deny 135:139/tcp comment 'Block NetBIOS'
ufw deny 445/tcp comment 'Block SMB'

# Enable firewall
ufw --force enable
echo "Firewall configured and enabled."
ufw status verbose

# --- 2. CLOSE OPEN PORTS / DISABLE UNNECESSARY SERVICES ---
echo ""
echo "[2/5] Disabling unnecessary services..."

# Disable services commonly exploited
for svc in telnet vsftpd apache2 nginx cups avahi-daemon; do
    if systemctl is-active --quiet $svc 2>/dev/null; then
        systemctl stop $svc
        systemctl disable $svc
        echo "  Disabled: $svc"
    fi
done

# --- 3. INSTALL SYSTEMD SERVICE (Auto-restart) ---
echo ""
echo "[3/5] Installing FortKnox auto-restart service..."

SERVICE_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_FILE="$SERVICE_DIR/fortknox-backend.service"

if [ -f "$SERVICE_FILE" ]; then
    cp "$SERVICE_FILE" /etc/systemd/system/fortknox-backend.service
    systemctl daemon-reload
    systemctl enable fortknox-backend.service
    echo "  Service installed. Will auto-restart on crash."
    echo "  Start with: sudo systemctl start fortknox-backend"
else
    echo "  WARNING: fortknox-backend.service not found in $SERVICE_DIR"
fi

# --- 4. KERNEL-LEVEL HARDENING ---
echo ""
echo "[4/5] Applying kernel security settings..."

cat >> /etc/sysctl.d/99-fortknox.conf << 'EOF'
# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects (prevent MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Disable ping replies (hides server from scans)
net.ipv4.icmp_echo_ignore_all = 1
EOF

sysctl --system > /dev/null 2>&1
echo "  Kernel hardened (SYN flood protection, anti-spoofing, ICMP disabled)."

# --- 5. FILE PERMISSIONS ---
echo ""
echo "[5/5] Setting secure file permissions..."

if [ -f "$SERVICE_DIR/.env" ]; then
    chmod 600 "$SERVICE_DIR/.env"
    echo "  .env: 600 (owner only)"
fi

if [ -d "$SERVICE_DIR/uploads" ]; then
    chmod 700 "$SERVICE_DIR/uploads"
    echo "  uploads/: 700 (owner only)"
fi

if [ -f "$SERVICE_DIR/server_private_key.pem" ]; then
    chmod 600 "$SERVICE_DIR/server_private_key.pem"
    echo "  server_private_key.pem: 600"
fi

if [ -f "$SERVICE_DIR/key.pem" ]; then
    chmod 600 "$SERVICE_DIR/key.pem"
    echo "  key.pem: 600"
fi

echo ""
echo "===== Deployment Complete ====="
echo ""
echo "Next steps:"
echo "  1. Start backend:  sudo systemctl start fortknox-backend"
echo "  2. Check status:   sudo systemctl status fortknox-backend"
echo "  3. View logs:      sudo journalctl -u fortknox-backend -f"
echo "  4. Start frontend: cd ../frontend && npm start"
echo ""
echo "Firewall status:"
ufw status numbered
