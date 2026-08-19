#!/usr/bin/env bash
# install.sh — deploy proxy-dashboard to /opt/proxy-dashboard
set -euo pipefail

INSTALL_DIR=/opt/proxy-dashboard
SERVICE_USER=dashboard
SING_BOX_USER=sing-box
SYSTEMCTL=/bin/systemctl

check_root() {
  [[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
}

create_user() {
  id "$SERVICE_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
}

setup_dirs() {
  mkdir -p "$INSTALL_DIR"/{data,app/static}
  mkdir -p /etc/sing-box/rules
  touch /etc/sing-box/rules/proxied.json
  echo '{"version":3,"rules":[]}' > /etc/sing-box/rules/proxied.json
  chown "$SERVICE_USER":$SING_BOX_USER /etc/sing-box/config.json /etc/sing-box/rules/proxied.json 2>/dev/null || true
  chmod 640 /etc/sing-box/config.json /etc/sing-box/rules/proxied.json 2>/dev/null || true
  mkdir -p /var/lib/sing-box
  chown "$SING_BOX_USER":"$SING_BOX_USER" /var/lib/sing-box 2>/dev/null || true
}

copy_files() {
  cp -r app "$INSTALL_DIR/"
  cp requirements.txt "$INSTALL_DIR/"
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
}

install_venv() {
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
}

download_chartjs() {
  local target="$INSTALL_DIR/app/static/chart.min.js"
  if [[ ! -f "$target" ]]; then
    echo "Downloading Chart.js..."
    curl -fsSL "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js" -o "$target" || \
      wget -q "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js" -O "$target" || \
      echo "⚠ Could not download Chart.js — place chart.min.js manually in $INSTALL_DIR/app/static/"
    chown "$SERVICE_USER":"$SERVICE_USER" "$target" 2>/dev/null || true
  fi
}

setup_env() {
  local env_file="$INSTALL_DIR/.env"
  if [[ ! -f "$env_file" ]]; then
    cp .env.example "$env_file"
    chmod 600 "$env_file"
    chown "$SERVICE_USER":"$SERVICE_USER" "$env_file"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  EDIT $env_file before starting the service."
    echo ""
    echo "  1. Set DASHBOARD_SECRET_KEY (random 32+ bytes):"
    echo "     python3 -c \"import secrets; print(secrets.token_hex(32))\""
    echo ""
    echo "  2. Set DASHBOARD_PASSWORD_HASH:"
    echo "     $INSTALL_DIR/venv/bin/python -c \\"
    echo "       \"from argon2 import PasswordHasher; print(PasswordHasher().hash('yourpassword'))\""
    echo ""
    echo "  3. Set CLASH_API_SECRET (match your sing-box config)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  fi
}

install_sudoers() {
  local target=/etc/sudoers.d/dashboard
  cp sudoers/dashboard "$target"
  chmod 440 "$target"
  visudo -c -f "$target" || { echo "sudoers validation failed — removing"; rm "$target"; exit 1; }
  echo "✓ sudoers installed"
}

install_service() {
  cp systemd/proxy-dashboard.service /etc/systemd/system/
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable proxy-dashboard
  echo "✓ Service installed. Start with: systemctl start proxy-dashboard"
}

print_caddy_snippet() {
  echo ""
  echo "Optional Caddy reverse-proxy snippet (proxy.example.com → dashboard):"
  echo ""
  cat <<'EOF'
proxy.example.com {
    basic_auth {
        operator <hash from: caddy hash-password>
    }
    @notme not remote_ip <your.ip.here>
    respond @notme 403
    reverse_proxy 127.0.0.1:8787
}
EOF
  echo ""
  echo "Or use SSH tunnel (most secure, no public exposure):"
  echo "  ssh -N -L 8787:127.0.0.1:8787 user@server"
  echo "  Then open http://localhost:8787"
}

check_root
create_user
setup_dirs
copy_files
install_venv
download_chartjs
setup_env
install_sudoers
install_service
print_caddy_snippet
