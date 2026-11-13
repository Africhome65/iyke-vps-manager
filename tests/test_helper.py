import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import stat
from pathlib import Path

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "ops" / "iyke-vps-helper"
LOADER = SourceFileLoader("iyke_helper", str(HELPER_PATH))
SPEC = importlib.util.spec_from_loader("iyke_helper", LOADER)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    monkeypatch.setattr(helper, "STATE_DIR", str(directory))
    return directory


def test_registry_round_trip_and_lock(state_dir):
    with helper.registry_lock():
        assert helper.load_registry() == {}
        helper.save_registry({"client01": 1001, "client02": 1002})
        assert helper.load_registry() == {"client01": 1001, "client02": 1002}
    assert stat.S_IMODE((state_dir / "managed-users.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((state_dir / "managed-users.lock").stat().st_mode) == 0o600


def test_registry_rejects_corrupt_data(state_dir):
    path = state_dir / "managed-users.json"
    path.write_text('{"client01": "not-a-uid"}', encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(SystemExit):
        helper.load_registry()


def test_registry_rejects_symlink(state_dir, tmp_path):
    target = tmp_path / "outside.json"
    target.write_text('["client01"]', encoding="utf-8")
    (state_dir / "managed-users.json").symlink_to(target)
    with pytest.raises(SystemExit):
        helper.load_registry()


def test_registry_rejects_unsafe_directory(state_dir):
    state_dir.chmod(0o755)
    with pytest.raises(SystemExit):
        helper.load_registry()


def test_save_registry_rejects_invalid_name(state_dir):
    with pytest.raises(SystemExit):
        helper.save_registry({"../root": 1001})


def test_name_validation_protects_system_users():
    with pytest.raises(SystemExit):
        helper.valid_name("root")
    with pytest.raises(SystemExit):
        helper.valid_name("not valid")


def test_expiry_validation_rejects_past_date():
    with pytest.raises(SystemExit):
        helper.valid_expiry("2000-01-01")


def test_account_existence_check(monkeypatch):
    class Result:
        def __init__(self, returncode):
            self.returncode = returncode

    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Result(0))
    assert helper.account_exists("client01") is True
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: Result(2))
    assert helper.account_exists("client01") is False


def test_list_accounts_ignores_reused_username(monkeypatch):
    monkeypatch.setattr(helper, "run", lambda args: (
        "client01:x:2001:2001::/home/client01:/bin/bash"
        if args == ["getent", "passwd"] else "Account expires: never"
    ))
    assert helper.list_accounts({"client01": 1001}) == []
    rows = helper.list_accounts({"client01": 2001})
    assert len(rows) == 1
    assert rows[0]["uid"] == 2001



def test_list_accounts_parses_chage_aligned_colon(monkeypatch):
    def fake_run(args):
        if args == ["getent", "passwd"]:
            return "paneltest01:x:1001:1001::/home/paneltest01:/bin/bash"
        if args == ["chage", "-l", "paneltest01"]:
            return ("Last password change                                    : Nov 13, 2026\n"
                    "Account expires                                         : Nov 30, 2026\n"
                    "Password expires                                        : never")
        raise AssertionError(args)

    monkeypatch.setattr(helper, "run", fake_run)
    rows = helper.list_accounts({"paneltest01": 1001})
    assert rows[0]["expiry"] == "Nov 30, 2026"



def test_vpn_status_reports_missing_software(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which", lambda command: None)
    assert helper.vpn_status() == {
        "wireguard": {"installed": False, "interfaces": []},
        "openvpn": {"installed": False, "instances": []},
    }


def test_vpn_status_reports_wireguard_interfaces(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which",
                        lambda command: "/usr/bin/wg" if command == "wg" else None)

    def fake_run(args, **kwargs):
        if args == ["wg", "show", "interfaces"]:
            return helper.subprocess.CompletedProcess(args, 0, "wg0\n", "")
        raise AssertionError(args)

    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    status = helper.vpn_status()
    assert status["wireguard"]["installed"] is True
    assert status["wireguard"]["interfaces"] == [{"name": "wg0", "status": "active"}]
    assert status["openvpn"] == {"installed": False, "instances": []}


def test_wireguard_install_refuses_existing_config(monkeypatch, tmp_path):
    config_dir = tmp_path / "wireguard"
    config_dir.mkdir()
    (config_dir / "wg0.conf").write_text("keep me", encoding="utf-8")
    monkeypatch.setattr(helper, "_secure_wireguard_dir", lambda: str(config_dir))
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: path.endswith("wg0.conf"))
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: pytest.fail("must not install over existing config"))
    with pytest.raises(SystemExit):
        helper.wireguard_install()


def test_wireguard_service_validates_state():
    with pytest.raises(SystemExit):
        helper.wireguard_service("restart")
