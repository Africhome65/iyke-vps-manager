# Xray VLESS/VMess WebSocket over TLS design

## Goal

Add an opt-in, administrator-managed Xray deployment for a VPS with a domain name and a valid Let's Encrypt certificate. The same code must work on other VPS instances; domains and client names are runtime inputs and must never be committed as deployment constants.

## Network layout

- TCP 80: ACME HTTP-01 webroot challenge; redirect all other HTTP requests to HTTPS.
- TCP 443: Nginx terminates TLS and proxies WebSocket traffic to Xray.
- VLESS: Nginx path `/vless` -> Xray WebSocket inbound on `127.0.0.1:10000`.
- VMess: Nginx path `/vmess` -> Xray WebSocket inbound on `127.0.0.1:10001`.
- Xray inbounds bind only to loopback. No Xray listener is exposed directly to the public network.
- The existing management panel remains bound to `127.0.0.1:8787`; it is not proxied or exposed by this feature.

## Provisioning requirements

1. Validate the supplied DNS hostname strictly and verify it resolves to a public address assigned to this VPS before changing services.
2. Require an existing, valid certificate for that exact hostname. Never request, display, log, or return the private key.
3. Inspect TCP 80/443 and Xray loopback ports before changes. Refuse conflicts rather than replacing unrelated services or configurations.
4. Preserve existing Xray, Nginx, Certbot, WireGuard, OpenVPN, and firewall configuration unless it is positively identified as owned by this feature.
5. Install Nginx only through a bounded transient systemd APT task.
6. Use a dedicated, root-owned feature state directory and atomic, permission-restricted writes for generated configuration and client credentials.
7. Validate generated Xray JSON with the installed Xray binary before activating it.
8. Validate Nginx configuration with `nginx -t` before reload. Back up owned configuration and roll back on any failed validation or service activation.
9. Configure Certbot renewal to use a dedicated webroot for HTTP-01 challenges. Do not leave standalone renewal configured to compete with Nginx on port 80. Verify renewal with a dry run.
10. Do not modify UFW or provider firewall rules in this feature; the administrator has to confirm TCP 80/443 are already allowed.

## Client management

- Generate independent UUIDs for each VLESS and VMess client.
- Store identifiers only in root-owned state with restrictive permissions.
- Show only non-secret service metadata in the status page.
- Serve individual client URIs/configuration files only to authenticated administrators, with `Cache-Control: no-store` and no audit-log secrets.
- Support revocation by rebuilding and validating the Xray config before applying it.
- Do not include private server keys in client downloads.

## Operational constraints

- No promise of zero connection failures: WebSocket/TLS compatibility depends on client software, DNS, certificates, network filtering, and the VPS provider.
- This design uses port 443 for both protocols on separate WebSocket paths. Port 80 is not a second VPN transport.
- Do not change WireGuard interfaces, peers, routes, forwarding, NAT, or firewall rules.
- Do not expose the management panel's port 8787.
- Deploy only after code review and passing CI; VPS deployment is a separate administrator-approved step.

## Acceptance tests

- Reject malformed hostnames, private/reserved IP resolutions, certificate mismatches, and port conflicts without changing existing files.
- Confirm VLESS and VMess inbounds bind to loopback only and use separate paths/ports.
- Confirm generated Xray configuration passes `xray run -test`.
- Confirm Nginx configuration passes `nginx -t` and routes only the exact WebSocket paths.
- Confirm HTTP-01 challenge files are served on port 80 and other HTTP requests redirect to HTTPS.
- Confirm Certbot renewal dry-run succeeds after Nginx is enabled.
- Confirm client credentials are not present in status output, audit logs, or application logs.
- Confirm unauthenticated profile downloads are denied and authenticated downloads are non-cacheable.
- Confirm rollback preserves pre-existing Nginx/Xray/Certbot/WireGuard configurations on any failure.
