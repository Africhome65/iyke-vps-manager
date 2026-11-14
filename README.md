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
- WireGuard installation and explicit interface start/stop controls
- WireGuard client creation and revocation with unique tunnel addresses
- Authenticated, non-cacheable client profile downloads and QR-code display

WireGuard installation creates a private server configuration but does not automatically start the interface, change firewall rules, enable IP forwarding, or configure internet egress. The panel attempts to detect the public IPv4 address of the VPS hosting that installation and pre-fills it as the client endpoint on UDP port 51820. Administrators can replace it with their own DNS name or another public address. Detection requires outbound HTTPS access to api.ipify.org; if unavailable, the endpoint can be entered manually. Each installation detects its own VPS address and keeps its own keys and client registry separate. Client profiles currently route only the private VPN subnet (10.66.0.0/24); full-tunnel internet access is not configured. OpenVPN discovery remains read-only and its installation/client management are planned separately. Xray-core can now be installed from the panel on a clean Ubuntu/Debian host using the official XTLS/Xray-install script pinned to an immutable upstream commit. The installer verifies the downloaded Xray release archive against its published SHA256 digest. The helper refuses to overwrite an existing Xray binary, service, configuration directory or `xray` account. Installation runs in a bounded transient systemd service so the web app's `ProtectSystem=strict` sandbox remains intact. The panel supports protected VMess/VLESS client identity records with UUID generation, duplicate-name protection, authenticated creation/revocation and a root-owned registry. It also performs read-only inspection of the existing `/usr/local/etc/xray/config.json`, displaying sanitized inbound protocol, listen address, port, transport, security mode and WebSocket path without exposing client UUIDs or private settings. Inspection does not modify the Xray configuration or service. Client-registry synchronization and downloadable connection profiles are not yet implemented; these must be integrated against the VPS owner's existing inbound and reverse-proxy configuration without replacing it.

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
- WireGuard package operations and Xray installation are launched as fixed, bounded systemd system services so system package and installation tasks can run without weakening the web service's `ProtectSystem=strict` sandbox.
- Xray installation uses the official upstream installer pinned to an immutable commit and refuses to replace existing Xray files or accounts.
- The helper accepts a small fixed set of actions, validates usernames and expiry dates, and checks every modification against its root-owned managed-account registry.
- Passwords are passed to the helper over stdin, never as command-line arguments.
- CSRF protection, secure cookie defaults, login throttling and audit logging are enabled.
- VPN status discovery never returns private keys or configuration contents.
- WireGuard server and client private keys are kept in root-owned, mode-0600 files; client profiles are served only to authenticated administrators with cache prevention headers. Treat every downloaded profile and QR code as a password-equivalent secret.
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
2. Xray VLESS/VMess configuration, per-VPS domain/TLS or REALITY setup and client management; OpenVPN installation, certificate-based client creation/revocation and secure .ovpn downloads; WireGuard routing/NAT and firewall setup
3. Domain and TLS lifecycle management
4. Usage limits, backups, monitoring improvements and notifications
5. Integration tests, hardening and deployment documentation

## License

MIT. See [LICENSE](LICENSE).
