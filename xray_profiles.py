"""Build client connection URIs for the manager's Caddy-terminated WebSocket setup.

This module is deliberately pure: it does not read server configuration, handle
credentials, modify Xray, or assume a particular public hostname.
"""
import base64
import ipaddress
import json
import re
from urllib.parse import quote, urlencode
import uuid


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_CLIENT_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")


def _validate_inputs(client_id, hostname, path, name):
    try:
        parsed = uuid.UUID(client_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid Xray client UUID") from exc
    if str(parsed) != client_id:
        raise ValueError("Invalid Xray client UUID")

    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise ValueError("Invalid public hostname")
    host = hostname.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Invalid public hostname")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 128:
        raise ValueError("Invalid WebSocket path")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in path) or "?" in path or "#" in path:
        raise ValueError("Invalid WebSocket path")
    if not isinstance(name, str) or not _CLIENT_NAME.fullmatch(name):
        raise ValueError("Invalid Xray client name")
    return str(parsed), host, path, name


def build_vmess_uri(client_id, hostname, path, name, port=443):
    """Return a VMess-over-WebSocket-over-TLS URI."""
    client_id, host, path, name = _validate_inputs(client_id, hostname, path, name)
    if port not in (80, 443):
        raise ValueError("Only ports 80 and 443 are supported")
    tls = port == 443
    profile = {
        "v": "2",
        "ps": name,
        "add": host,
        "port": str(port),
        "id": client_id,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls" if tls else "",
        "sni": host if tls else "",
    }
    encoded = base64.b64encode(
        json.dumps(profile, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    return "vmess://" + encoded


def build_vless_uri(client_id, hostname, path, name, port=443):
    """Return a VLESS-over-WebSocket-over-TLS URI."""
    client_id, host, path, name = _validate_inputs(client_id, hostname, path, name)
    if port not in (80, 443):
        raise ValueError("Only ports 80 and 443 are supported")
    tls = port == 443
    parameters = {
        "encryption": "none",
        "security": "tls" if tls else "none",
        "type": "ws",
        "host": host,
        "path": path,
    }
    if tls:
        parameters["sni"] = host
    query = urlencode(parameters, quote_via=quote, safe="")
    return f"vless://{client_id}@{host}:{port}?{query}#{quote(name, safe='')}"
