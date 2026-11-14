# Hysteria 2 multi-port deployment design

## Current status

The web panel currently validates a domain and up to eight individual UDP ports and performs read-only DNS and local-listener checks. It does not write a Hysteria configuration, change the firewall, enable a unit, or start a service.

## Constraints

- Preserve existing Caddy TCP 80/443 and UDP 443 listeners.
- Preserve Xray VMess/VLESS WebSocket routes, OpenVPN UDP 1194, SSH, UFW policy, and fail2ban.
- Do not take over Caddy's certificate files or loosen their filesystem permissions.
- Do not run Hysteria's contiguous port-range listener mode as a shortcut: that mode manages firewall redirection rules and is not equivalent to a list of unrelated ports.
- Treat any failed or unavailable listener inspection as unknown, never as proof that a port is free.

## Listener model: unresolved implementation decision

Hysteria's documented server configuration exposes one `listen` endpoint. Its built-in port hopping accepts a contiguous range and manages firewall redirection; it does not provide a documented comma-separated set of unrelated listener ports.

A possible design is one systemd-managed Hysteria process and isolated config per selected UDP port. This is not yet approved for implementation. Before adopting it, verify against the exact pinned Hysteria release:

1. The CLI accepts an explicit config path for each independently managed server process.
2. Multiple processes can coexist with independent listen sockets and no shared mutable state.
3. ACME storage is isolated per process, or certificate issuance is centralized safely.
4. Each unit has a unique identity, restrictive config/secret permissions, resource limits, and deterministic stop/rollback behavior.
5. Failure of one listener does not leave the others in an inconsistent state.

Do not create several ACME clients for the same hostname without first establishing safe storage and rate-limit behavior. Prefer a single certificate lifecycle and shared read-only certificate/key files for listener processes if that can be implemented without exposing private keys.

## TLS lifecycle

Hysteria documents DNS-01 ACME support for selected DNS providers. This avoids binding TCP 80/443, but requires provider-specific API credentials and all names in one ACME configuration to use the same DNS provider. Unsupported DNS providers need a separately managed certificate/key path; do not silently fall back to insecure TLS.

For file-based TLS, Hysteria documents that certificate files are read on each TLS handshake. This permits atomic certificate-file replacement without restarting the server. It does not, by itself, solve secure issuance, renewal, ownership, or key distribution.

## UDP 53 special case

The current VPS has a loopback-only systemd-resolved UDP listener on `127.0.0.53:53`. A wildcard Hysteria bind to UDP 53 can conflict with it. The existing UFW UDP 53 rules are not proof that a public listener exists. Do not select UDP 53 automatically. A public-interface-specific bind may be possible, but must be tested on the target host and must not disrupt local DNS resolution.

## Rollout gates

No live configuration should be applied until all of the following are true:

- The listener model is verified against the pinned Hysteria binary.
- The selected public address and every selected UDP socket are checked.
- DNS answers are compared with the VPS public address; mere DNS resolution is insufficient.
- TLS issuance or supplied certificate validity and SAN coverage are verified.
- The exact firewall delta is previewed and limited to selected UDP ports.
- Existing listener, route, firewall, SSH, OpenVPN, Caddy, Xray, and fail2ban state is captured for rollback.
- The user explicitly approves the proposed live changes.

## References

- Hysteria server setup: https://v2.hysteria.network/docs/getting-started/Server/
- Full server config (listen, TLS, ACME): https://v2.hysteria.network/docs/advanced/Full-Server-Config/
- ACME DNS providers: https://v2.hysteria.network/docs/advanced/ACME-DNS-Config/
- Environment variables (including ACME storage and port-range firewall backend): https://v2.hysteria.network/docs/advanced/Environment-Variables/
