import base64
import json
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from xray_profiles import build_vless_uri, build_vmess_uri


CLIENT_ID = "12345678-1234-4234-8234-123456789abc"


def test_vmess_uri_encodes_expected_caddy_ws_tls_profile():
    uri = build_vmess_uri(CLIENT_ID, "vpn.example.net", "/vmess", "phone01")
    assert uri.startswith("vmess://")
    profile = json.loads(base64.b64decode(uri.removeprefix("vmess://")))
    assert profile == {
        "v": "2", "ps": "phone01", "add": "vpn.example.net", "port": "443",
        "id": CLIENT_ID, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": "vpn.example.net", "path": "/vmess", "tls": "tls",
        "sni": "vpn.example.net",
    }


def test_vless_uri_encodes_expected_caddy_ws_tls_profile():
    uri = build_vless_uri(CLIENT_ID, "vpn.example.net", "/vless", "phone01")
    parsed = urlsplit(uri)
    assert parsed.scheme == "vless"
    assert parsed.username == CLIENT_ID
    assert parsed.hostname == "vpn.example.net"
    assert parsed.port == 443
    query = parse_qs(parsed.query)
    assert query == {
        "encryption": ["none"], "security": ["tls"], "sni": ["vpn.example.net"],
        "type": ["ws"], "host": ["vpn.example.net"], "path": ["/vless"],
    }
    assert unquote(parsed.fragment) == "phone01"


@pytest.mark.parametrize("builder", [build_vmess_uri, build_vless_uri])
@pytest.mark.parametrize("client_id,host,path,name", [
    ("not-a-uuid", "vpn.example.net", "/ws", "phone01"),
    (CLIENT_ID, "https://vpn.example.net", "/ws", "phone01"),
    (CLIENT_ID, "vpn.example.net", "ws", "phone01"),
    (CLIENT_ID, "vpn.example.net", "/ws?x=1", "phone01"),
    (CLIENT_ID, "vpn.example.net", "/ws", "../escape"),
])
def test_profile_builders_reject_unsafe_inputs(builder, client_id, host, path, name):
    with pytest.raises(ValueError):
        builder(client_id, host, path, name)


@pytest.mark.parametrize("builder", [build_vmess_uri, build_vless_uri])
def test_profile_builders_reject_non_tls_port(builder):
    with pytest.raises(ValueError):
        builder(CLIENT_ID, "vpn.example.net", "/ws", "phone01", port=80)


def test_profile_builder_accepts_public_ipv4_host():
    uri = build_vless_uri(CLIENT_ID, "203.0.113.10", "/vless", "phone01")
    assert "@203.0.113.10:443?" in uri
