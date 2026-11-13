import os
import subprocess

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    database = tmp_path / "test.sqlite3"
    monkeypatch.setenv("IYKE_BOOTSTRAP_ADMIN", "admin")
    monkeypatch.setenv("IYKE_BOOTSTRAP_PASSWORD", "test-password-longer-than-16")
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-that-is-long-enough",
        "DATABASE": str(database),
        "WTF_CSRF_ENABLED": False,
        "HELPER": "/test/helper",
    })
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client):
    return client.post("/login", data={
        "username": "admin",
        "password": "test-password-longer-than-16",
    }, follow_redirects=True)


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_dashboard_requires_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_admin_can_login_and_change_password(client):
    response = login(client)
    assert response.status_code == 200
    response = client.post("/settings/password", data={
        "current_password": "test-password-longer-than-16",
        "new_password": "a-new-password-longer-than-16",
        "confirm_password": "a-new-password-longer-than-16",
    }, follow_redirects=True)
    assert response.status_code == 200
    client.post("/logout")
    response = client.post("/login", data={
        "username": "admin", "password": "a-new-password-longer-than-16"
    })
    assert response.status_code == 302


def test_ssh_user_creation_uses_generated_password_over_stdin(client, monkeypatch):
    login(client)
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="created", stderr="")

    monkeypatch.setattr("app.subprocess.run", fake_run)
    response = client.post("/users/create", data={
        "username": "client01", "expiry": "2099-12-31"
    })
    assert response.status_code == 200
    assert b"client01" in response.data
    assert len(calls) == 1
    assert calls[0][0] == ["sudo", "-n", "/test/helper"]
    request = __import__("json").loads(calls[0][1]["input"])
    assert request["action"] == "create"
    assert request["username"] == "client01"
    assert request["expiry"] == "2099-12-31"
    assert len(request["password"]) >= 20
    assert " " not in request["password"]


def test_invalid_username_is_rejected_before_helper(client, monkeypatch):
    login(client)
    monkeypatch.setattr("app.subprocess.run", lambda *a, **k: pytest.fail("helper should not run"))
    response = client.post("/users/create", data={
        "username": "root", "expiry": "2099-12-31"
    })
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/users")
    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])
    assert any("valid, non-system Linux username" in message for _, message in flashes)



def test_vpn_status_page_requires_login_and_displays_services(client, monkeypatch):
    response = client.get("/vpn")
    assert response.status_code == 302
    login(client)

    payload = {
        "wireguard": {"installed": True, "interfaces": [{"name": "wg0", "status": "active"}]},
        "openvpn": {"installed": False, "instances": []},
    }

    def fake_run(args, **kwargs):
        assert args == ["sudo", "-n", "/test/helper"]
        return subprocess.CompletedProcess(args, 0, stdout=__import__("json").dumps(payload), stderr="")

    monkeypatch.setattr("app.subprocess.run", fake_run)
    response = client.get("/vpn")
    assert response.status_code == 200
    assert b"WireGuard" in response.data
    assert b"wg0" in response.data
    assert b"OpenVPN" in response.data
    assert b"Not installed" in response.data


def test_wireguard_install_route_requires_login_and_calls_helper(client, monkeypatch):
    response = client.post("/vpn/wireguard/install")
    assert response.status_code == 302
    login(client)
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout='{"public_key":"abc"}', stderr="")
    monkeypatch.setattr("app.subprocess.run", fake_run)
    response = client.post("/vpn/wireguard/install")
    assert response.status_code == 302
    request = __import__("json").loads(calls[0][1]["input"])
    assert request == {"action": "wireguard_install"}
    assert calls[0][1]["timeout"] == 360


def test_wireguard_service_rejects_invalid_state(client, monkeypatch):
    login(client)
    monkeypatch.setattr("app.subprocess.run", lambda *a, **k: pytest.fail("helper should not run"))
    assert client.post("/vpn/wireguard/service", data={"state":"restart"}).status_code == 400


def test_wireguard_profile_download_requires_login_and_is_not_cached(client, monkeypatch):
    assert client.get("/vpn/wireguard/peers/phone/profile").status_code == 302
    login(client)
    monkeypatch.setattr("app.subprocess.run", lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=__import__("json").dumps({"profile":"[Interface]\nPrivateKey = secret\n"}), stderr=""))
    response = client.get("/vpn/wireguard/peers/phone/profile")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, private, max-age=0"
    assert b"PrivateKey" in response.data


def test_wireguard_profile_revoke_requires_post_and_login(client, monkeypatch):
    assert client.get("/vpn/wireguard/peers/phone/revoke").status_code == 405
    login(client)
    assert client.post("/vpn/wireguard/peers/phone/revoke").status_code == 302


def test_vpn_page_loads_peer_list_after_status(client, monkeypatch):
    login(client)
    calls = []
    def fake_run(args, **kwargs):
        payload = __import__("json").loads(kwargs["input"])
        action = payload["action"]
        calls.append(action)
        if action == "vpn_status":
            output = {
                "wireguard":{"installed":True,"interfaces":[]},
                "openvpn":{"installed":False,"instances":[]}
            }
        elif action == "wireguard_peers":
            output = [{"name":"phone01","address":"10.66.0.2/32","endpoint":"vpn.example.com:51820"}]
        else:
            raise AssertionError(action)
        return subprocess.CompletedProcess(args, 0, stdout=__import__("json").dumps(output), stderr="")
    monkeypatch.setattr("app.subprocess.run", fake_run)
    response = client.get("/vpn")
    assert response.status_code == 200
    assert b"phone01" in response.data
    assert calls == ["vpn_status", "wireguard_peers"]


def test_wireguard_create_peer_route_validates_name(client, monkeypatch):
    login(client)
    monkeypatch.setattr("app.subprocess.run", lambda *a, **k: pytest.fail("helper should not run"))
    response = client.post("/vpn/wireguard/peers", data={"name":"../bad","endpoint":"vpn.example.com:51820"})
    assert response.status_code == 302
