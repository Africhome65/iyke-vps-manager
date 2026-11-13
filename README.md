# Iyke VPS Manager

A modular, self-hosted VPS administration panel for Ubuntu and Debian.

## Current release

The first release provides:
- Administrator login and password changes with password hashing, CSRF protection and login throttling
- Dashboard with CPU, memory, disk and uptime metrics
- Managed SSH account listing, creation, expiry changes and deletion
- A restricted privileged helper; the Flask web process is not run as root
- SQLite-backed administrator bootstrap and audit events
- systemd service and installation/uninstallation scripts
- Read-only VPN software status for WireGuard and OpenVPN (no installation or configuration changes)

VPN peer and server configuration management, domain/SSL automation, backups and advanced traffic accounting are planned modules and are not claimed as implemented yet. The VPN page currently performs read-only software and service discovery only.

## Requirements

- Ubuntu 22.04/24.04 or Debian 12 (x86_64/arm64)
- Root access for installation
- A domain name and HTTPS reverse proxy are strongly recommended before exposing the panel publicly

## Install

Clone the repository and run:

```bash
sudo bash install.sh
```

The installer creates a dedicated `iyke-vps-manager` service account, installs the app under `/opt/iyke-vps-manager`, creates a random bootstrap administrator password, and prints it once at the end. Change it immediately after first login.

The service listens only on `127.0.0.1:8787`. For a secure first test from your computer, create an SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 root@SERVER_IP
```

Then open `http://127.0.0.1:8787` in your browser. For ongoing remote access, configure an HTTPS reverse proxy and set `IYKE_COOKIE_SECURE=1` in `/etc/iyke-vps-manager/manager.env`, then restart the service. Do not expose the panel directly to the public internet.

## Configuration

Configuration is stored in `/etc/iyke-vps-manager/`. The installer creates a secret key and administrator account. The service listens on `127.0.0.1:8787` by default; use a TLS reverse proxy for remote access.

## Account management and migration

For safety, the panel lists and modifies only Linux accounts created through Iyke VPS Manager. Its ownership registry is stored in `/var/lib/iyke-vps-manager-state/`, owned by root with mode `0700`; the unprivileged web-service account cannot read or alter it. Existing Linux accounts are not automatically adopted when upgrading. They remain on the VPS but will not appear in the panel unless a deliberate, separately reviewed adoption process is added. This avoids allowing the panel to expire or delete unrelated system accounts.

## Security model

- The application runs as an unprivileged system user.
- Only the root-owned helper at `/usr/local/sbin/iyke-vps-helper` is allowed through sudo.
- The helper accepts a small fixed set of actions, validates usernames and expiry dates, and checks every modification against its root-owned managed-account registry.
- Passwords are passed to the helper over stdin, never as command-line arguments.
- CSRF protection, secure cookie defaults, login throttling and audit logging are enabled.
- VPN discovery uses a fixed helper action and reports service metadata only; it never returns private keys or VPN configuration contents.
- Never commit `.env`, database files, private keys, passwords or generated secrets.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export IYKE_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export IYKE_DATABASE="/tmp/iyke-vps-manager-dev.sqlite3"
export IYKE_BOOTSTRAP_ADMIN="admin"
export IYKE_BOOTSTRAP_PASSWORD="replace-with-a-long-random-password"
python run.py
```

The development server is not intended for production. Run automated checks with `pytest`.

## Roadmap

1. Foundation, dashboard, secure authentication and SSH account operations
2. VPN/proxy protocol adapters (WireGuard, OpenVPN, VMess, VLESS, Trojan, Shadowsocks)
3. Domain and TLS lifecycle management
4. Usage limits, backups, monitoring improvements and notifications
5. Integration tests, hardening and deployment documentation

## License

MIT. See [LICENSE](LICENSE).
