#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/iyke-vps-manager"
ETC_DIR="/etc/iyke-vps-manager"
DATA_DIR="/var/lib/iyke-vps-manager"
SERVICE_USER="iyke-vps-manager"
HELPER="/usr/local/sbin/iyke-vps-helper"
REPO_URL="https://github.com/Africhome65/iyke-vps-manager.git"

if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo bash install.sh" >&2; exit 1; fi
if ! command -v apt-get >/dev/null 2>&1; then echo "This installer supports Ubuntu/Debian only." >&2; exit 1; fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git sudo

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g root -m 0755 "$APP_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$ETC_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"

if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" fetch --depth 1 origin main
  git -C "$APP_DIR" reset --hard origin/main
else
  git clone --depth 1 --branch main "$REPO_URL" "$APP_DIR"
fi

python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

install -o root -g root -m 0755 "$APP_DIR/ops/iyke-vps-helper" "$HELPER"
cat > /etc/sudoers.d/iyke-vps-manager <<EOF
$SERVICE_USER ALL=(root) NOPASSWD: $HELPER *
EOF
chmod 0440 /etc/sudoers.d/iyke-vps-manager
visudo -cf /etc/sudoers.d/iyke-vps-manager

if [[ ! -f "$ETC_DIR/manager.env" ]]; then
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  BOOT_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  cat > "$ETC_DIR/manager.env" <<EOF
IYKE_SECRET_KEY=$SECRET
IYKE_DATABASE=$DATA_DIR/manager.sqlite3
IYKE_BOOTSTRAP_ADMIN=admin
IYKE_BOOTSTRAP_PASSWORD=$BOOT_PASS
IYKE_COOKIE_SECURE=0
EOF
  chmod 0640 "$ETC_DIR/manager.env"
  chown root:"$SERVICE_USER" "$ETC_DIR/manager.env"
  printf '%s\n' "$BOOT_PASS" > /root/iyke-vps-manager-initial-password
  chmod 0600 /root/iyke-vps-manager-initial-password
fi

install -o root -g root -m 0644 "$APP_DIR/ops/iyke-vps-manager.service" /etc/systemd/system/iyke-vps-manager.service
chown -R root:"$SERVICE_USER" "$APP_DIR"
chmod -R o-rwx "$APP_DIR"
chmod -R u=rwX,g=rX,o= "$APP_DIR"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"
systemctl daemon-reload
systemctl enable --now iyke-vps-manager
for attempt in $(seq 1 15); do
  if systemctl is-active --quiet iyke-vps-manager; then break; fi
  sleep 2
done
if systemctl is-active --quiet iyke-vps-manager; then
  # The first administrator is now stored as a password hash in SQLite.
  # Remove the one-time plaintext bootstrap secret from future service environments.
  sed -i '/^IYKE_BOOTSTRAP_PASSWORD=/d' "$ETC_DIR/manager.env"
else
  echo "Service did not start. Bootstrap password retained in the root-only config for troubleshooting." >&2
fi

echo
echo "Iyke VPS Manager installation finished."
echo "Panel is bound to http://127.0.0.1:8787 (use an HTTPS reverse proxy for remote access)."
if [[ -f /root/iyke-vps-manager-initial-password ]]; then
  echo "Initial admin username: admin"
  echo "Initial admin password: $(cat /root/iyke-vps-manager-initial-password)"
  echo "Password file: /root/iyke-vps-manager-initial-password (root-only)"
  echo "Change this password after first login; delete the password file when safely stored."
fi
echo "Check status: systemctl status iyke-vps-manager"
