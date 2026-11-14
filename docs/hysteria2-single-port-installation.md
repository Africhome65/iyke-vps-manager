# Hysteria 2 single-port installation plan

## Goal

Provide a repeatable Hysteria 2 setup for an administrator's own Ubuntu or Debian VPS. The flow must use the VPS owner's domain and certificate material, not project-maintainer infrastructure or credentials.

This document describes the first supported deployment shape: one domain, one UDP listener, password authentication, and a dedicated systemd instance. Multi-port deployment remains a separate future milestone.

## Safety invariants

- Never use a maintainer-owned domain, DNS account, API token, email address, or certificate.
- Never overwrite an existing Hysteria binary, service, configuration, account, or certificate.
- Never stop, reconfigure, or take over Caddy, Nginx, OpenVPN, Xray, SSH, or another service.
- Never open firewall ports implicitly. Display the exact UDP port and request explicit administrator confirmation.
- Never enable or start a new Hysteria instance until its configuration and TLS inputs have passed validation.
- Never log passwords, DNS API tokens, private keys, or generated client URIs.
- Write configuration atomically with restrictive ownership and permissions; retain a recoverable backup when replacing an explicitly managed file.
- Treat unavailable DNS, listener, certificate, or firewall inspection as unknown, not as success.

## First release: manual certificate path

The first end-to-end configuration flow should support an existing certificate and private key supplied by the VPS owner. This avoids colliding with a web server already bound to TCP 80/443 and avoids provider-specific DNS token handling in the initial release.

The form collects:
- A fully qualified domain name.
- Exactly one UDP port (default suggestion may be 8443, never auto-selected).
- Absolute certificate and private-key paths on the VPS.
- A generated password, with an explicit regenerate action if the administrator wants a different credential.

Before applying anything, the privileged helper must:
1. Validate the domain, port, and absolute file paths (reject control characters, traversal, symlinks where unsafe, and non-regular files).
2. Verify the certificate's validity period and hostname/SAN with OpenSSL.
3. Verify the private key parses and matches the certificate's public key.
4. Confirm the Hysteria service account can read the certificate and key without loosening their permissions.
5. Perform read-only DNS and UDP-listener checks. DNS must be compared with the VPS public address where that address can be determined reliably.
6. Verify the selected systemd template exists and matches the expected service user and config path.
7. Return a plan describing the exact config path, systemd instance, UDP firewall delta, and any warnings. No changes are made during preview.

On explicit confirmation, the helper should atomically write a dedicated config file (not the upstream example file), validate it with the installed Hysteria binary's supported validation command, install or update only the dedicated instance, and then ask for separate confirmation before adding the UDP firewall rule and starting/enabling the service. If any step fails, restore the previous managed files and leave the service stopped.

## Configuration and client profile

- Use a YAML serializer if one is already available; otherwise add and pin a maintained YAML dependency. Do not interpolate untrusted form values into YAML.
- Use Hysteria 2 password authentication with a cryptographically random secret generated server-side.
- Return the client URI only to the authenticated administrator after successful service verification.
- Escape URI components correctly and do not include `insecure=1`.
- Do not expose the password in audit details, logs, status output, or generic flash messages.

## Later TLS methods

After the manual-certificate flow is tested end to end, add:
- Built-in ACME HTTP-01 only when the required TCP challenge port is demonstrably available and the administrator approves any listener changes.
- DNS-01 only for explicitly supported provider integrations, with provider credentials stored in a root-only secret file and never echoed back to the web app or logs.

Do not claim support for every DNS provider. Do not silently fall back from a failed secure TLS method to insecure TLS.

## Test gates

Tests must cover invalid domains and ports, paths and symlinks, expired or mismatched certificates, unreadable keys, DNS mismatch, occupied or uninspectable UDP ports, pre-existing Hysteria state, Caddy port conflicts, malformed generated configuration, systemd start failure, firewall failure, rollback, secret redaction, and successful client URI generation.

Integration tests should run on the supported Ubuntu/Debian matrix using disposable VMs or containers with systemd support. Unit tests alone do not prove that ACME, firewall, certificate permissions, or the Hysteria daemon work on a real host.

## References

- Hysteria server setup: https://v2.hysteria.network/docs/getting-started/Server/
- Full server configuration: https://v2.hysteria.network/docs/advanced/Full-Server-Config/
- ACME DNS configuration: https://v2.hysteria.network/docs/advanced/ACME-DNS-Config/
- ACME environment variables: https://v2.hysteria.network/docs/advanced/Environment-Variables/
