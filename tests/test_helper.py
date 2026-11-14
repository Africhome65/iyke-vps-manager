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
        "xray": {"installed": False, "service": "not-installed"},
    }



def test_openvpn_crl_state_reports_missing_directive(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("port 1194\nproto udp\n", encoding="utf-8")
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_nlink": 1
    })())
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": False, "crl_file_present": False
    }


def test_openvpn_crl_state_checks_relative_crl_file(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    crl = tmp_path / "crl.pem"
    config.write_text("port 1194\ncrl-verify crl.pem\n", encoding="utf-8")
    crl.write_text("public CRL data\n", encoding="utf-8")
    real_lstat = helper.os.lstat

    def fake_lstat(path):
        info = real_lstat(path)
        return type("Info", (), {
            "st_mode": info.st_mode, "st_uid": 0, "st_nlink": info.st_nlink
        })()

    monkeypatch.setattr(helper.os, "lstat", fake_lstat)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": True
    }


def test_openvpn_crl_state_ignores_commented_directive(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("# crl-verify crl.pem\nport 1194\n", encoding="utf-8")
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_nlink": 1
    })())
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": False, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_symlink_crl(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    target = tmp_path / "actual-crl.pem"
    link = tmp_path / "crl.pem"
    config.write_text("crl-verify crl.pem\n", encoding="utf-8")
    target.write_text("public CRL data\n", encoding="utf-8")
    link.symlink_to(target)
    real_lstat = helper.os.lstat

    def fake_lstat(path):
        info = real_lstat(path)
        return type("Info", (), {
            "st_mode": info.st_mode, "st_uid": info.st_uid, "st_nlink": info.st_nlink
        })()

    monkeypatch.setattr(helper.os, "lstat", fake_lstat)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_reports_missing_crl_file(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("crl-verify missing-crl.pem\n", encoding="utf-8")
    real_lstat = helper.os.lstat

    def fake_lstat(path):
        info = real_lstat(path)
        return type("Info", (), {
            "st_mode": info.st_mode, "st_uid": 0, "st_nlink": info.st_nlink
        })()

    monkeypatch.setattr(helper.os, "lstat", fake_lstat)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }



def test_vpn_status_reports_xray_binary_and_service(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which",
                        lambda command: "/usr/local/bin/xray" if command == "xray" else None)
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    status = helper.vpn_status()
    assert status["xray"] == {"installed": True, "service": "active"}


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
    assert status["xray"] == {"installed": False, "service": "not-installed"}


def test_wireguard_install_refuses_existing_config(monkeypatch, tmp_path):
    config_dir = tmp_path / "wireguard"
    config_dir.mkdir()
    (config_dir / "wg0.conf").write_text("keep me", encoding="utf-8")
    monkeypatch.setattr(helper, "_secure_wireguard_dir", lambda: str(config_dir))
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: path.endswith("wg0.conf"))
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k: pytest.fail("must not install over existing config"))
    with pytest.raises(SystemExit):
        helper.wireguard_install()


def test_wireguard_public_endpoint_detects_global_ipv4(monkeypatch):
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, limit):
            assert limit == 64
            return b"8.8.8.8"

    monkeypatch.setattr(helper.urllib.request, "urlopen",
                        lambda request, timeout: Response())
    result = helper.wireguard_public_endpoint()
    assert result == {"host": "8.8.8.8", "port": 51820,
                      "endpoint": "8.8.8.8:51820"}


def test_wireguard_public_endpoint_rejects_unavailable_lookup(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("offline")
    monkeypatch.setattr(helper.urllib.request, "urlopen", unavailable)
    with pytest.raises(SystemExit):
        helper.wireguard_public_endpoint()


def test_wireguard_service_validates_state():
    with pytest.raises(SystemExit):
        helper.wireguard_service("restart")


def test_wireguard_config_must_be_manager_owned(monkeypatch, tmp_path):
    config_dir = tmp_path / "wireguard"
    config_dir.mkdir()
    config = config_dir / "wg0.conf"
    config.write_text("[Interface]\nPrivateKey = " + "A" * 43 + "=\nListenPort = 51820\n", encoding="utf-8")
    config.chmod(0o600)
    monkeypatch.setattr(helper, "_secure_wireguard_dir", lambda: str(config_dir))
    monkeypatch.setattr(helper, "_read_root_file", lambda path, mode_mask=0o077: config.read_text(encoding="utf-8"))
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/wg")
    with pytest.raises(SystemExit):
        helper._check_wg_config()


def test_wireguard_config_manager_marker_and_port_are_validated(monkeypatch, tmp_path):
    config_dir = tmp_path / "wireguard"
    config_dir.mkdir()
    config = config_dir / "wg0.conf"
    config.write_text("# Managed by Iyke VPS Manager; do not edit manually.\n[Interface]\nPrivateKey = " + "A" * 43 + "=\nListenPort = 51820\n", encoding="utf-8")
    config.chmod(0o600)
    monkeypatch.setattr(helper, "_secure_wireguard_dir", lambda: str(config_dir))
    monkeypatch.setattr(helper, "_read_root_file", lambda path, mode_mask=0o077: config.read_text(encoding="utf-8"))
    monkeypatch.setattr(helper.shutil, "which", lambda command: "/usr/bin/wg")
    assert "ListenPort = 51820" in helper._check_wg_config()


def test_wireguard_endpoint_validation():
    assert helper._valid_endpoint("vpn.example.com:51820")
    assert helper._valid_endpoint("8.8.8.8:51820")
    assert not helper._valid_endpoint("vpn.example.com")
    assert not helper._valid_endpoint("vpn.example.com:99999")
    assert not helper._valid_endpoint("https://vpn.example.com:51820")


def test_wireguard_peer_address_allocation():
    assert helper._allocate_peer_address({}) == "10.66.0.2/32"
    peers = {"phone": {"address": "10.66.0.2/32"}}
    assert helper._allocate_peer_address(peers) == "10.66.0.3/32"


def test_wireguard_peer_name_rejects_path_traversal():
    with pytest.raises(SystemExit):
        helper._valid_peer_name("../escape")


def test_wireguard_peer_config_has_only_private_subnet_routes():
    config = helper._peer_config_text("[Interface]\nAddress = 10.66.0.1/24\n", {
        "phone": {"public_key": "abc", "address": "10.66.0.2/32", "endpoint": "vpn.example.com:51820"}
    })
    assert "AllowedIPs = 10.66.0.2/32" in config
    assert "AllowedIPs = 0.0.0.0/0" not in config


def test_wireguard_peer_registry_accepts_client_host_address(monkeypatch, tmp_path):
    payload = json.dumps({
        "phone01": {
            "public_key": "A" * 43 + "=",
            "address": "10.66.0.2/32",
            "endpoint": "vpn.example.com:51820"
        }
    })
    monkeypatch.setattr(helper, "_secure_wireguard_dir", lambda: str(tmp_path))
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: True)
    monkeypatch.setattr(helper, "_read_root_file", lambda path: payload)
    assert helper._peer_registry()["phone01"]["address"] == "10.66.0.2/32"


def test_wireguard_service_start_is_not_persistent(monkeypatch):
    calls = []
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": stat.S_IFREG | 0o600, "st_uid": 0
    })())
    monkeypatch.setattr(helper, "run", lambda args, *a, **k: calls.append(args))
    assert helper.wireguard_service("start")["requested_state"] == "start"
    assert calls == [["systemctl", "start", "wg-quick@wg0.service"]]



def test_apt_task_runs_in_transient_system_service(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return helper.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which",
                        lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None)
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    helper._run_apt_task("/usr/bin/apt-get", ["update"], "update")

    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/systemd-run"
    assert "--wait" in command
    assert "--pipe" in command
    assert "--collect" in command
    assert "--property=RuntimeMaxSec=240" in command
    assert "--setenv=DEBIAN_FRONTEND=noninteractive" in command
    assert command[-2:] == ["/usr/bin/apt-get", "update"]
    assert kwargs["check"] is True
    assert kwargs["timeout"] == 270


def test_apt_task_reports_system_service_failure(monkeypatch, capsys):
    def failed_run(command, **kwargs):
        raise helper.subprocess.CalledProcessError(
            100, command, output="", stderr="APT package operation failed"
        )

    monkeypatch.setattr(helper.shutil, "which",
                        lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None)
    monkeypatch.setattr(helper.subprocess, "run", failed_run)
    with pytest.raises(SystemExit) as exc:
        helper._run_apt_task("/usr/bin/apt-get", ["install", "-y", "wireguard"], "install")
    assert exc.value.code == 1
    assert "APT package operation failed" in capsys.readouterr().err


def test_apt_task_requires_systemd_run(monkeypatch, capsys):
    monkeypatch.setattr(helper.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit) as exc:
        helper._run_apt_task("/usr/bin/apt-get", ["update"], "update")
    assert exc.value.code == 1
    assert "systemd-run is unavailable" in capsys.readouterr().err



def test_xray_install_refuses_existing_installation(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which",
                        lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None)
    monkeypatch.setattr(helper.os.path, "lexists",
                        lambda path: path == "/usr/local/bin/xray")
    monkeypatch.setattr(helper.subprocess, "run",
                        lambda *a, **k: pytest.fail("must not run installer over an existing Xray"))
    with pytest.raises(SystemExit):
        helper.xray_install()


def test_xray_install_uses_pinned_official_installer_in_transient_service(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:2] == ["getent", "passwd"]:
            return helper.subprocess.CompletedProcess(command, 2, "", "")
        return helper.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.shutil, "which",
                        lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None)
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: False)
    monkeypatch.setattr(helper.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(helper.os, "access", lambda path, mode: True)
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "inactive")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)

    result = helper.xray_install()
    assert result == {"installed": True, "service": "inactive",
                      "installer": "official-pinned", "firewall_changed": False}
    assert len(calls) == 2
    command, kwargs = calls[1]
    assert command[0] == "/usr/bin/systemd-run"
    assert "--wait" in command and "--pipe" in command and "--collect" in command
    assert "--property=RuntimeMaxSec=300" in command
    assert command[-2] == "-c"
    assert helper.XRAY_INSTALLER_COMMIT in command[-1]
    assert "install --without-logfiles" in command[-1]
    assert kwargs["check"] is True
    assert kwargs["timeout"] == 330


def test_xray_action_rejects_unexpected_fields():
    with pytest.raises(SystemExit):
        helper.handle_xray_action({"action": "xray_install", "domain": "example.com"})
