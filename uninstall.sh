#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo bash uninstall.sh" >&2; exit 1; fi
echo "This removes the panel application and service, but preserves its database and configuration."
read -r -p "Continue? [y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || exit 0
systemctl disable --now iyke-vps-manager 2>/dev/null || true
rm -f /etc/systemd/system/iyke-vps-manager.service /etc/sudoers.d/iyke-vps-manager
rm -f /usr/local/sbin/iyke-vps-helper
systemctl daemon-reload
rm -rf /opt/iyke-vps-manager
echo "Panel removed. Configuration remains in /etc/iyke-vps-manager and data in /var/lib/iyke-vps-manager."
