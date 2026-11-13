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
    assert calls[0][0][-3:] == ["create", "client01", "2099-12-31"]
    assert len(calls[0][1]["input"].strip()) >= 20
    assert " " not in calls[0][1]["input"].strip()


def test_invalid_username_is_rejected_before_helper(client, monkeypatch):
    login(client)
    monkeypatch.setattr("app.subprocess.run", lambda *a, **k: pytest.fail("helper should not run"))
    response = client.post("/users/create", data={
        "username": "root", "expiry": "2099-12-31"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"valid, non-system Linux username" in response.data
