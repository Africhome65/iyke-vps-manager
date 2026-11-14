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




def test_openvpn_index_parses_client_metadata_without_private_material():
    index = (
        "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
        "R\t301231235959Z\t261101120000Z\t02\tunknown\t/CN=oldphone\n"
        "V\tbad-date\t\t03\tunknown\t/CN=broken\n"
        "V\t301231235959Z\t\t04\tunknown\t/CN=server\n"
    )
    rows = helper._openvpn_index_clients(index)
    assert rows == [
        {"common_name": "oldphone", "status": "revoked",
         "expires": "2030-12-31", "serial": "02"},
        {"common_name": "phone01", "status": "valid",
         "expires": "2030-12-31", "serial": "01"},
        {"common_name": "server", "status": "valid",
         "expires": "2030-12-31", "serial": "04"},
    ]



def _pretend_root_owned(monkeypatch):
    real_lstat = helper.os.lstat
    real_fstat = helper.os.fstat

    def as_root(info):
        return type("Info", (), {
            "st_mode": info.st_mode, "st_uid": 0, "st_nlink": info.st_nlink,
            "st_size": info.st_size
        })()

    monkeypatch.setattr(helper.os, "lstat", lambda path: as_root(real_lstat(path)))
    monkeypatch.setattr(helper.os, "fstat", lambda fd: as_root(real_fstat(fd)))


def test_openvpn_clients_discovers_one_trusted_database(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    (pki / "index.txt").write_text(
        "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n",
        encoding="utf-8")
    (pki / "index.txt").chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    result = helper.openvpn_clients()
    assert result == {
        "available": True, "reason": "",
        "clients": [{"common_name": "phone01", "status": "valid",
                     "expires": "2030-12-31", "serial": "01"}],
    }


def test_openvpn_clients_rejects_oversized_index(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    index = pki / "index.txt"
    index.write_text("V" + "x" * (1024 * 1024), encoding="utf-8")
    index.chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    assert helper.openvpn_clients()["available"] is False


def test_openvpn_clients_rejects_symlink_index(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    outside = tmp_path / "outside-index"
    outside.write_text("", encoding="utf-8")
    outside.chmod(0o600)
    (pki / "index.txt").symlink_to(outside)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    assert helper.openvpn_clients()["available"] is False


def test_openvpn_clients_rejects_symlinked_parent_directory(tmp_path, monkeypatch):
    real_parent = tmp_path / "real"
    pki = real_parent / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    (pki / "index.txt").write_text("", encoding="utf-8")
    (pki / "index.txt").chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates",
                        lambda: [str(alias / "pki")])
    assert helper.openvpn_clients()["available"] is False


def test_openvpn_clients_requires_unambiguous_database(tmp_path, monkeypatch):
    paths = []
    for number in ("one", "two"):
        pki = tmp_path / number
        for name in ("issued", "private"):
            (pki / name).mkdir(parents=True, mode=0o700)
            (pki / name).chmod(0o700)
        pki.chmod(0o700)
        (pki / "index.txt").write_text("", encoding="utf-8")
        (pki / "index.txt").chmod(0o600)
        paths.append(str(pki))
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: paths)
    result = helper.openvpn_clients()
    assert result["available"] is False
    assert result["clients"] == []
    assert "More than one" in result["reason"]


def test_vpn_status_reports_missing_software(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which", lambda command: None)
    assert helper.vpn_status() == {
        "wireguard": {"installed": False, "interfaces": []},
        "openvpn": {"installed": False, "instances": []},
        "xray": {"installed": False, "service": "not-installed"},
    }



def test_openvpn_runtime_config_matches_active_exact_process(monkeypatch):
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        return helper.subprocess.CompletedProcess(args, 0, "4321\n", "")
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    monkeypatch.setattr("builtins.open", lambda path, mode: __import__("io").BytesIO(
        b"/usr/sbin/openvpn\0--config\0/etc/openvpn/server/edge.conf\0"
    ))
    monkeypatch.setattr(helper.os, "readlink", lambda path: "/usr/sbin/openvpn")
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/sbin/openvpn")
    assert helper._openvpn_runtime_config_matches(
        "openvpn-server@edge.service", "/etc/openvpn/server/edge.conf"
    ) is True
    assert len(calls) == 2


def test_openvpn_runtime_config_rejects_inactive_or_mismatched_process(monkeypatch):
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "inactive")
    assert helper._openvpn_runtime_config_matches(
        "openvpn-server@edge.service", "/etc/openvpn/server/edge.conf"
    ) is False


def test_openvpn_runtime_config_rejects_relative_or_multiple_configs(monkeypatch):
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper.subprocess, "run", lambda args, **kwargs:
        helper.subprocess.CompletedProcess(args, 0, "4321\n", ""))
    monkeypatch.setattr("builtins.open", lambda path, mode: __import__("io").BytesIO(
        b"/usr/sbin/openvpn\0--config\0edge.conf\0--config\0/etc/openvpn/server/edge.conf\0"
    ))
    monkeypatch.setattr(helper.os, "readlink", lambda path: "/usr/sbin/openvpn")
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/sbin/openvpn")
    assert helper._openvpn_runtime_config_matches(
        "openvpn-server@edge.service", "/etc/openvpn/server/edge.conf"
    ) is False


def test_openvpn_runtime_config_rejects_unexpected_unit_and_systemctl_failure(monkeypatch):
    assert helper._openvpn_runtime_config_matches(
        "openvpn-server@../edge.service", "/etc/openvpn/server/edge.conf"
    ) is False
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper.subprocess, "run", lambda args, **kwargs:
        helper.subprocess.CompletedProcess(args, 1, "", "failed"))
    assert helper._openvpn_runtime_config_matches(
        "openvpn-server@edge.service", "/etc/openvpn/server/edge.conf"
    ) is False


def test_openvpn_crl_state_reports_missing_directive(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("port 1194\nproto udp\n", encoding="utf-8")
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": False, "crl_file_present": False
    }


def test_openvpn_crl_state_verifies_crl_against_matching_ca(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    config.write_text("port 1194\ncrl-verify pki/crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    for name in ("crl.pem", "ca.crt"):
        (pki / name).write_text("test public material\n", encoding="utf-8")
        (pki / name).chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return helper.subprocess.CompletedProcess(args, 0, "verify OK", "")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": True
    }
    args, kwargs = calls[0]
    assert args[:2] == ["/usr/bin/openssl", "crl"]
    assert args[-2:] == ["-noout", "-verify"]
    assert kwargs["timeout"] == 10
    assert len(kwargs["pass_fds"]) == 2


def test_openvpn_crl_state_rejects_unmatched_pki(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    config.write_text("crl-verify crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    (tmp_path / "crl.pem").write_text("not trusted", encoding="utf-8")
    (tmp_path / "crl.pem").chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_invalid_signature(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    config.write_text("crl-verify pki/crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    for name in ("crl.pem", "ca.crt"):
        (pki / name).write_text("invalid public material", encoding="utf-8")
        (pki / name).chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k:
        helper.subprocess.CompletedProcess(a[0], 1, "", "verification failure"))
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_duplicate_directives(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("crl-verify one.pem\ncrl-verify two.pem\n", encoding="utf-8")
    config.chmod(0o600)
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_ignores_commented_directive(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("# crl-verify crl.pem\nport 1194\n", encoding="utf-8")
    _pretend_root_owned(monkeypatch)
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
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_group_or_world_writable_crl(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    crl = tmp_path / "crl.pem"
    config.write_text("crl-verify crl.pem\n", encoding="utf-8")
    crl.write_text("public CRL data\n", encoding="utf-8")
    crl.chmod(0o666)
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_reports_missing_crl_file(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("crl-verify missing-crl.pem\n", encoding="utf-8")
    _pretend_root_owned(monkeypatch)
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


def test_openvpn_crl_state_rejects_symlinked_config_parent(tmp_path, monkeypatch):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    config = real_parent / "server.conf"
    config.write_text("crl-verify crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(alias / "server.conf")) == {
        "crl_configured": False, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_symlinked_crl_parent(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    config.write_text("crl-verify alias/crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    crl = real_parent / "crl.pem"
    crl.write_text("public CRL data\n", encoding="utf-8")
    crl.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    _pretend_root_owned(monkeypatch)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


def test_openvpn_crl_state_rejects_symlink_config(tmp_path):
    target = tmp_path / "actual-server.conf"
    config = tmp_path / "server.conf"
    target.write_text("crl-verify crl.pem\n", encoding="utf-8")
    target.chmod(0o600)
    config.symlink_to(target)
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": False, "crl_file_present": False
    }


def test_openvpn_create_client_uses_trusted_easyrsa_and_never_returns_key(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    script = tmp_path / "easyrsa"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: (str(pki), ""))
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: str(script))
    updated = "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: updated)
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        (pki / "private" / "phone01.key").write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
        (pki / "private" / "phone01.key").chmod(0o600)
        (pki / "issued" / "phone01.crt").write_text("PUBLIC CERTIFICATE", encoding="utf-8")
        (pki / "issued" / "phone01.crt").chmod(0o600)
        return helper.subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    result = helper.openvpn_create_client("phone01")
    assert result == {"created": True, "name": "phone01"}
    assert calls[0][0] == [str(script), "--batch", "build-client-full", "phone01", "nopass"]
    assert calls[0][1]["env"]["EASYRSA_PKI"] == str(pki)
    assert calls[0][1]["env"]["EASYRSA_BATCH"] == "1"
    assert calls[0][1]["timeout"] == 90
    assert "PRIVATE KEY" not in json.dumps(result)


def test_openvpn_create_client_rejects_invalid_or_reserved_names(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki",
                        lambda **kwargs: pytest.fail("PKI must not be inspected"))
    for name in ("../bad", "Server", "server", "root", "ca"):
        with pytest.raises(SystemExit):
            helper.openvpn_create_client(name)


def test_openvpn_create_client_refuses_existing_name_and_files(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki",
                        lambda require_ca_key=False: ("/safe/pki",
                            "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"))
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path",
                        lambda: pytest.fail("Easy-RSA must not run for duplicate"))
    with pytest.raises(SystemExit):
        helper.openvpn_create_client("phone01")


def test_openvpn_create_client_rejects_failed_easyrsa(monkeypatch, capsys):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: ("/safe/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: "/usr/share/easy-rsa/easyrsa")
    monkeypatch.setattr(helper.subprocess, "run", lambda args, **kwargs:
        helper.subprocess.CompletedProcess(args, 1, "", "sensitive output"))
    with pytest.raises(SystemExit):
        helper.openvpn_create_client("phone01")
    assert "Easy-RSA client issuance failed" in capsys.readouterr().err




def test_openvpn_unique_pki_rejects_ambiguity_even_if_only_one_has_ca_key(tmp_path, monkeypatch, capsys):
    paths = []
    for label in ("one", "two"):
        pki = tmp_path / label
        for name in ("issued", "private"):
            (pki / name).mkdir(parents=True, mode=0o700)
            (pki / name).chmod(0o700)
        pki.chmod(0o700)
        (pki / "index.txt").write_text("", encoding="utf-8")
        (pki / "index.txt").chmod(0o600)
        paths.append(pki)
    ca_key = paths[0] / "private" / "ca.key"
    ca_key.write_text("PRIVATE CA KEY", encoding="utf-8")
    ca_key.chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(p) for p in paths])
    with pytest.raises(SystemExit):
        helper._openvpn_unique_pki(require_ca_key=True)
    assert "More than one Easy-RSA database" in capsys.readouterr().err


def test_openvpn_unique_pki_rejects_group_readable_ca_key(tmp_path, monkeypatch, capsys):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    (pki / "index.txt").write_text("", encoding="utf-8")
    (pki / "index.txt").chmod(0o600)
    ca_key = pki / "private" / "ca.key"
    ca_key.write_text("PRIVATE CA KEY", encoding="utf-8")
    ca_key.chmod(0o640)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    with pytest.raises(SystemExit):
        helper._openvpn_unique_pki(require_ca_key=True)
    assert "accessible only to root" in capsys.readouterr().err





def test_openvpn_get_profile_builds_inline_profile_only_for_verified_server(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: ("/etc/openvpn/easy-rsa/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_index_clients", lambda value: [{"common_name": "phone01", "status": "valid"}])
    monkeypatch.setattr(helper, "_openvpn_server_config_paths", lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: True)
    monkeypatch.setattr(helper, "_openvpn_config_directives", lambda path: {
        "port": [["1194"]], "proto": [["udp"]], "dev": [["tun"]], "ca": [["ca.crt"]]
    })
    def read_pem(path, label, max_bytes=1024 * 1024):
        return {
            "CA certificate": "-----BEGIN CERTIFICATE-----\\nCA\\n-----END CERTIFICATE-----\\n",
            "client certificate": "-----BEGIN CERTIFICATE-----\\nCERT\\n-----END CERTIFICATE-----\\n",
            "client private key": "-----BEGIN PRIVATE KEY-----\\nKEY\\n-----END PRIVATE KEY-----\\n",
        }[label]
    monkeypatch.setattr(helper, "_openvpn_read_pem", read_pem)
    result = helper.openvpn_get_profile("phone01", "vpn.example.com")
    assert result["name"] == "phone01"
    assert "remote vpn.example.com 1194" in result["profile"]
    assert "<ca>" in result["profile"] and "<cert>" in result["profile"]
    assert "<key>" in result["profile"] and "KEY" in result["profile"]


def test_openvpn_get_profile_rejects_private_or_invalid_endpoint(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: pytest.fail("must reject endpoint before reading PKI"))
    for endpoint in ("127.0.0.1", "localhost", "vpn.example.com:1194", "../bad"):
        with pytest.raises(SystemExit):
            helper.openvpn_get_profile("phone01", endpoint)


def test_openvpn_get_profile_requires_verified_active_server(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: ("/safe/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_index_clients", lambda value: [{"common_name": "phone01", "status": "valid"}])
    monkeypatch.setattr(helper, "_openvpn_server_config_paths", lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: False)
    with pytest.raises(SystemExit):
        helper.openvpn_get_profile("phone01", "vpn.example.com")
