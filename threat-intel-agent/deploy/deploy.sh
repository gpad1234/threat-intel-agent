#!/usr/bin/env bash
#
# deploy.sh — Deploy Threat Intel Agent on Ubuntu
#
# Usage:
#   chmod +x deploy/deploy.sh
#   sudo deploy/deploy.sh
#
set -euo pipefail

APP_DIR="/opt/threat-intel-agent"
APP_USER="threat-intel"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "============================================"
echo "  Deploying Threat Intel Agent"
echo "  Target: DigitalOcean Droplet"
echo "============================================"
echo ""
echo "  ⚠️  SAFETY CHECK: nginx on port 80 will NOT be touched."
echo "  This script only installs the agent — nothing else."
echo ""

# ─── Safety: Verify nginx is running and note it ──────────────────────────
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo "  ✓ nginx detected and running — will not be modified"
    echo "  ✓ Port 80 app is safe"
else
    echo "  ℹ nginx not detected on this host"
fi
echo ""

# ─── 1. Create service user ──────────────────────────────────────────────────
if ! id "$APP_USER" &>/dev/null; then
    echo "[1/7] Creating service user: $APP_USER"
    useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" "$APP_USER"
else
    echo "[1/7] Service user $APP_USER already exists"
fi

# ─── 2. Install system dependencies ──────────────────────────────────────────
echo "[2/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv

# ─── 3. Copy application ─────────────────────────────────────────────────────
echo "[3/7] Copying application to $APP_DIR..."
mkdir -p "$APP_DIR"
cp -r "$SCRIPT_DIR"/* "$APP_DIR/"
cp "$SCRIPT_DIR"/.env.example "$APP_DIR/.env.example"

# Create .env from example if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    echo "  ⚠️  Created .env from example — EDIT $APP_DIR/.env with your API keys!"
fi

# ─── 4. Create virtual environment & install deps ────────────────────────────
echo "[4/7] Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# ─── 5. Create data & reports directories ────────────────────────────────────
echo "[5/8] Creating data directories..."
mkdir -p "$APP_DIR/data" "$APP_DIR/reports"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ─── 6. Grant read-only log access for local monitoring ──────────────────────
echo "[6/8] Granting read-only log access..."
# Add to 'adm' group for /var/log/syslog, auth.log, kern.log
usermod -aG adm "$APP_USER" 2>/dev/null || true
# Ensure nginx log directory is readable (read-only, not write)
if [ -d /var/log/nginx ]; then
    setfacl -m u:"$APP_USER":rx /var/log/nginx 2>/dev/null || \
        chmod o+rx /var/log/nginx 2>/dev/null || true
    setfacl -m u:"$APP_USER":r /var/log/nginx/*.log 2>/dev/null || \
        chmod o+r /var/log/nginx/*.log 2>/dev/null || true
    echo "  ✓ Read-only access to /var/log/nginx/ granted"
fi

# ─── 7. Install systemd service & timer ──────────────────────────────────────
echo "[7/8] Installing systemd service and timer..."
cp "$APP_DIR/deploy/threat-intel-agent.service" /etc/systemd/system/
cp "$APP_DIR/deploy/threat-intel-agent.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable threat-intel-agent.timer

# ─── 8. Post-deploy safety verification ──────────────────────────────────────
echo "[8/8] Safety verification..."

# Confirm nginx is still running after deployment
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo "  ✓ nginx is still running — port 80 app is safe"
else
    echo "  ⚠ nginx was not running before deployment either"
fi

# Confirm nothing is newly listening on port 80
AGENT_ON_80=$(ss -tlnp | grep ":80 " | grep -v nginx || true)
if [ -z "$AGENT_ON_80" ]; then
    echo "  ✓ No new processes on port 80"
else
    echo "  ⚠ WARNING: Unexpected process on port 80: $AGENT_ON_80"
fi

echo ""
echo "============================================"
echo "  Deployment Complete"
echo "============================================"
echo ""
echo "  1. Edit API keys:    sudo nano $APP_DIR/.env"
echo "  2. Test manually:    sudo -u $APP_USER $APP_DIR/venv/bin/python $APP_DIR/main.py --mvp"
echo "  3. Start timer:      sudo systemctl start threat-intel-agent.timer"
echo "  4. Check status:     sudo systemctl status threat-intel-agent.timer"
echo "  5. View reports:     ls $APP_DIR/reports/"
echo "  6. View logs:        journalctl -u threat-intel-agent"
echo ""
echo "  Local log monitoring is ENABLED by default (nginx logs)."
echo "  The agent will read /var/log/nginx/ but never modify nginx."
echo ""
echo "  ⚠️  SAFETY REMINDERS:"
echo "    - nginx on port 80 is PROTECTED — agent will never restart it"
echo "    - Agent runs as $APP_USER with read-only log access"
echo "    - To grant log access: sudo usermod -aG adm $APP_USER"
echo ""
