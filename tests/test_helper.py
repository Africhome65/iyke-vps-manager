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


def test_xray_lock_does_not_relabel_operation_oserror(state_dir):
    with pytest.raises(OSError, match="operation failed inside lock"):
        with helper._xray_client_lock():
            raise OSError("operation failed inside lock")


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
    _pretend_root_owned(monkeypatch)
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
        "xray": {"installed": False, "service": "not-installed",
                 "config_status": "unavailable", "inbounds": [], "public_hostname": ""},
        "hysteria": {"installed": False, "service": "not-installed",
                     "config_status": "missing"},
    }


def _prepare_xray_state_dir(monkeypatch, tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setattr(helper, "STATE_DIR", str(state))
    return state


def test_xray_create_client_fails_closed_without_live_sync(tmp_path, monkeypatch):
    state = _prepare_xray_state_dir(monkeypatch, tmp_path)

    # Simulate an unavailable or unsafe live configuration explicitly.  Do not
    # inspect the host running pytest: it may have a real Xray installation.
    monkeypatch.setattr(
        helper, "_read_xray_config_document",
        lambda: helper.fail("Existing Xray configuration is unavailable")
    )
    with pytest.raises(SystemExit):
        helper.xray_create_client("phone01", "vless")
    assert not (state / "xray-clients.json").exists()


def test_xray_create_client_validates_name_and_protocol_before_failing_closed(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    with pytest.raises(SystemExit):
        helper.xray_create_client("Phone01", "vless")
    with pytest.raises(SystemExit):
        helper.xray_create_client("phone01", "trojan")


def test_xray_revoke_client_fails_closed_without_touching_registry(tmp_path, monkeypatch):
    state = _prepare_xray_state_dir(monkeypatch, tmp_path)
    registry = state / "xray-clients.json"
    registry.write_text('[{"name":"phone01","protocol":"vless","id":"00000000-0000-4000-8000-000000000001"}]\n',
                        encoding="utf-8")
    registry.chmod(0o600)
    before = registry.read_bytes()
    with pytest.raises(SystemExit):
        helper.xray_revoke_client("phone01")
    assert registry.read_bytes() == before


def test_xray_config_summary_reports_only_safe_inbound_metadata(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10000, "protocol": "vmess",
             "settings": {"clients": [{"id": "secret-uuid"}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess"}}},
            {"listen": "127.0.0.1", "port": 10001, "protocol": "vless",
             "settings": {"clients": [{"id": "another-secret"}]},
             "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless"}}}
        ]
    }), encoding="utf-8")
    real_open = helper.os.open
    real_fstat = helper.os.fstat
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": helper.stat.S_IFDIR | 0o755, "st_uid": 0
    })())
    monkeypatch.setattr(helper.os, "open", lambda path, flags: real_open(
        str(config_path) if path == "/usr/local/etc/xray/config.json" else path, flags))
    monkeypatch.setattr(helper.os, "fstat", lambda fd: type("Info", (), {
        "st_mode": helper.stat.S_IFREG | 0o640, "st_uid": 0,
        "st_nlink": 1, "st_size": config_path.stat().st_size
    })())
    summary = helper._xray_config_summary()
    assert summary == {
        "config_status": "readable",
        "inbounds": [
            {"protocol": "vmess", "listen": "127.0.0.1", "port": 10000,
             "network": "ws", "security": "none", "path": "/vmess"},
            {"protocol": "vless", "listen": "127.0.0.1", "port": 10001,
             "network": "ws", "security": "none", "path": "/vless"}
        ]
    }
    assert "secret-uuid" not in json.dumps(summary)
    monkeypatch.setattr(helper.os, "open", real_open)
    monkeypatch.setattr(helper.os, "fstat", real_fstat)


def test_xray_config_summary_fails_closed_on_unsafe_parent(monkeypatch):
    def fake_lstat(path):
        if path == "/usr/local/etc/xray":
            return type("Info", (), {"st_mode": helper.stat.S_IFLNK | 0o777, "st_uid": 0})()
        return type("Info", (), {"st_mode": helper.stat.S_IFDIR | 0o755, "st_uid": 0})()
    monkeypatch.setattr(helper.os, "lstat", fake_lstat)
    assert helper._xray_config_summary() == {"config_status": "unsafe", "inbounds": []}


def test_caddy_public_hostname_reads_one_site_without_exposing_config(monkeypatch, tmp_path):
    config = tmp_path / "Caddyfile"
    config.write_text("smarty.example.net {" + chr(10) + "  reverse_proxy 127.0.0.1:10000" + chr(10) + "}" + chr(10), encoding="utf-8")
    real_open = helper.os.open
    real_lstat = helper.os.lstat
    real_fstat = helper.os.fstat
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": helper.stat.S_IFDIR | 0o755, "st_uid": 0
    })() if path in {"/etc", "/etc/caddy"} else real_lstat(path))
    monkeypatch.setattr(helper.os, "open", lambda path, flags: real_open(config, flags)
                        if path == "/etc/caddy/Caddyfile" else real_open(path, flags))
    monkeypatch.setattr(helper.os, "fstat", lambda fd: type("Info", (), {
        "st_mode": helper.stat.S_IFREG | 0o640, "st_uid": 0,
        "st_nlink": 1, "st_size": config.stat().st_size
    })())
    assert helper._caddy_public_hostname() == "smarty.example.net"
    monkeypatch.setattr(helper.os, "open", real_open)
    monkeypatch.setattr(helper.os, "lstat", real_lstat)
    monkeypatch.setattr(helper.os, "fstat", real_fstat)


def test_caddy_public_hostname_fails_closed_when_multiple_sites(monkeypatch, tmp_path):
    config = tmp_path / "Caddyfile"
    config.write_text("one.example.net {" + chr(10) + "}" + chr(10) + "two.example.net {" + chr(10) + "}" + chr(10), encoding="utf-8")
    real_open = helper.os.open
    real_lstat = helper.os.lstat
    monkeypatch.setattr(helper.os, "lstat", lambda path: type("Info", (), {
        "st_mode": helper.stat.S_IFDIR | 0o755, "st_uid": 0
    })() if path in {"/etc", "/etc/caddy"} else real_lstat(path))
    monkeypatch.setattr(helper.os, "open", lambda path, flags: real_open(config, flags)
                        if path == "/etc/caddy/Caddyfile" else real_open(path, flags))
    monkeypatch.setattr(helper.os, "fstat", lambda fd: type("Info", (), {
        "st_mode": helper.stat.S_IFREG | 0o640, "st_uid": 0,
        "st_nlink": 1, "st_size": config.stat().st_size
    })())
    assert helper._caddy_public_hostname() == ""



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


def test_openvpn_ca_cert_matches_same_certificate_at_different_paths(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    (pki / "issued").mkdir(parents=True, mode=0o700)
    (pki / "private").mkdir(mode=0o700)
    pki.chmod(0o700)
    configured_ca = tmp_path / "server-ca.crt"
    configured_ca.write_text("certificate A", encoding="ascii")
    configured_ca.chmod(0o600)
    (pki / "ca.crt").write_text("certificate A", encoding="ascii")
    (pki / "ca.crt").chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    calls = []
    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return helper.subprocess.CompletedProcess(args, 0, b"same DER certificate", b"")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    assert helper._openvpn_ca_cert_matches(str(configured_ca), str(pki)) is True
    assert len(calls) == 2
    assert all(call[0][:2] == ["/usr/bin/openssl", "x509"] for call in calls)
    assert all(call[0][-2:] == ["-outform", "DER"] for call in calls)
    assert all(call[1]["timeout"] == 10 and len(call[1]["pass_fds"]) == 1 for call in calls)


def test_openvpn_ca_cert_matches_rejects_different_certificates(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    (pki / "issued").mkdir(parents=True, mode=0o700)
    (pki / "private").mkdir(mode=0o700)
    pki.chmod(0o700)
    configured_ca = tmp_path / "server-ca.crt"
    configured_ca.write_text("certificate A", encoding="ascii")
    configured_ca.chmod(0o600)
    (pki / "ca.crt").write_text("certificate B", encoding="ascii")
    (pki / "ca.crt").chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    outputs = iter((b"DER certificate A", b"DER certificate B"))
    def fake_run(args, **kwargs):
        return helper.subprocess.CompletedProcess(args, 0, next(outputs), b"")
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    assert helper._openvpn_ca_cert_matches(str(configured_ca), str(pki)) is False


def test_openvpn_crl_state_verifies_crl_against_matching_ca(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    config.write_text("port 1194\nca pki/ca.crt\ncrl-verify pki/crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    for name in ("crl.pem", "ca.crt"):
        (pki / name).write_text("test public material\n", encoding="utf-8")
        (pki / name).chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    monkeypatch.setattr(helper, "_openvpn_ca_cert_matches", lambda config_ca, selected_pki: True)
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


def test_openvpn_crl_state_rejects_server_ca_mismatch(tmp_path, monkeypatch):
    config = tmp_path / "server.conf"
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    config.write_text("ca other-ca.crt\ncrl-verify pki/crl.pem\n", encoding="utf-8")
    config.chmod(0o600)
    for name in ("crl.pem", "ca.crt"):
        (pki / name).write_text("public material\\n", encoding="utf-8")
        (pki / name).chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    monkeypatch.setattr(helper.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("CRL must not be verified against a different CA"))
    assert helper._openvpn_crl_state(str(config)) == {
        "crl_configured": True, "crl_file_present": False
    }


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
    config.write_text("ca pki/ca.crt\ncrl-verify pki/crl.pem\n", encoding="utf-8")
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
    summary = {"config_status": "readable", "inbounds": [
        {"protocol": "vless", "listen": "127.0.0.1", "port": 10001,
         "network": "ws", "security": "none", "path": "/vless"}
    ]}
    monkeypatch.setattr(helper, "_xray_config_summary", lambda: summary)
    # Keep this unit test independent of a real /etc/caddy/Caddyfile.
    monkeypatch.setattr(helper, "_caddy_public_hostname", lambda: "")
    status = helper.vpn_status()
    assert status["xray"] == {"installed": True, "service": "active",
                              "public_hostname": "", **summary}


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
    assert status["xray"] == {"installed": False, "service": "not-installed",
                              "config_status": "unavailable", "inbounds": [],
                              "public_hostname": ""}


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


def test_hysteria_install_refuses_existing_installation(monkeypatch):
    monkeypatch.setattr(helper.shutil, "which",
                        lambda name: "/usr/bin/systemd-run" if name == "systemd-run" else None)
    monkeypatch.setattr(helper.os.path, "lexists",
                        lambda path: path == "/etc/hysteria")
    monkeypatch.setattr(helper.subprocess, "run",
                        lambda *a, **k: pytest.fail("must not run installer over existing Hysteria"))
    with pytest.raises(SystemExit):
        helper.hysteria_install()


def test_hysteria_install_uses_pinned_official_installer_in_transient_service(monkeypatch):
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

    result = helper.hysteria_install()
    assert result == {
        "installed": True, "service": "inactive", "config_status": "example",
        "installer": "official-pinned", "service_started": False, "firewall_changed": False,
    }
    assert len(calls) == 2
    command, kwargs = calls[1]
    assert command[0] == "/usr/bin/systemd-run"
    assert "--wait" in command and "--pipe" in command and "--collect" in command
    assert "--property=RuntimeMaxSec=300" in command
    assert helper.HYSTERIA_INSTALLER_COMMIT in command[-1]
    assert "HYSTERIA_USER=hysteria bash" in command[-1]
    assert "systemctl enable" not in command[-1]
    assert kwargs["check"] is True
    assert kwargs["timeout"] == 330


def test_hysteria_action_rejects_unexpected_fields():
    with pytest.raises(SystemExit):
        helper.handle_hysteria_action({"action": "hysteria_install", "domain": "example.com"})


def test_xray_action_rejects_unexpected_fields():
    with pytest.raises(SystemExit):
        helper.handle_xray_action({"action": "xray_install", "domain": "example.com"})



def test_xray_profile_requires_live_registered_identity(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(helper, "_load_xray_clients", lambda: [{
        "name": "phone01", "protocol": "vless",
        "id": "00000000-0000-4000-8000-000000000001"
    }])
    monkeypatch.setattr(helper, "_xray_config_has_client", lambda protocol, client_id: True)
    monkeypatch.setattr(helper, "_xray_config_summary", lambda: {
        "config_status": "readable",
        "inbounds": [{"protocol": "vless", "listen": "127.0.0.1", "port": 10001,
                      "network": "ws", "security": "none", "path": "/vless"}]
    })
    monkeypatch.setattr(helper, "_caddy_public_hostname", lambda: "vpn.example.net")
    result = helper.xray_get_client_profile("phone01")
    assert result == {
        "name": "phone01", "protocol": "vless",
        "id": "00000000-0000-4000-8000-000000000001",
        "hostname": "vpn.example.net", "path": "/vless", "port": 443
    }


def test_xray_profile_refuses_registry_only_identity(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(helper, "_load_xray_clients", lambda: [{
        "name": "phone01", "protocol": "vless",
        "id": "00000000-0000-4000-8000-000000000001"
    }])
    monkeypatch.setattr(helper, "_xray_config_has_client", lambda protocol, client_id: False)
    with pytest.raises(SystemExit):
        helper.xray_get_client_profile("phone01")



def _managed_xray_test_config():
    return {
        "inbounds": [{
            "tag": "vmess-ws", "listen": "127.0.0.1", "port": 10000,
            "protocol": "vmess",
            "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111", "alterId": 0}]},
            "streamSettings": {"network": "ws", "security": "none",
                               "wsSettings": {"path": "/vmess"}}
        }, {
            "tag": "vless-ws", "listen": "127.0.0.1", "port": 10001,
            "protocol": "vless",
            "settings": {"decryption": "none", "clients": [
                {"id": "22222222-2222-4222-8222-222222222222", "email": "original"}
            ]},
            "streamSettings": {"network": "ws", "security": "none",
                               "wsSettings": {"path": "/vless"}}
        }]
    }


def _fake_xray_metadata():
    from types import SimpleNamespace
    return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o640, st_ino=123, st_mtime_ns=456)


def test_xray_create_client_adds_only_manager_client_and_preserves_original(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    config = _managed_xray_test_config()
    applied = []
    monkeypatch.setattr(helper, "_read_xray_config_document",
                        lambda: (b'{"original":true}\n', json.loads(json.dumps(config)), _fake_xray_metadata()))
    monkeypatch.setattr(helper, "_apply_xray_config_change",
                        lambda candidate, raw, metadata: applied.append(candidate) or "/protected/backup.bak")
    result = helper.xray_create_client("phone01", "vmess")
    assert result == {"created": True, "name": "phone01", "protocol": "vmess",
                      "backup": "backup.bak"}
    clients = applied[0]["inbounds"][0]["settings"]["clients"]
    assert clients[0]["id"] == "11111111-1111-4111-8111-111111111111"
    assert clients[1]["alterId"] == 0
    assert len(clients[1]["id"]) == 36
    assert _load_rows_for_test(helper, "phone01")["protocol"] == "vmess"


def _load_rows_for_test(helper_module, name):
    return next(row for row in helper_module._load_xray_clients() if row["name"] == name)


def test_xray_revoke_removes_only_managed_uuid_and_preserves_original(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    helper._save_xray_clients([{
        "name": "phone01", "protocol": "vless",
        "id": "33333333-3333-4333-8333-333333333333"
    }])
    config = _managed_xray_test_config()
    config["inbounds"][1]["settings"]["clients"].append({
        "id": "33333333-3333-4333-8333-333333333333", "email": "phone01"
    })
    applied = []
    monkeypatch.setattr(helper, "_read_xray_config_document",
                        lambda: (b'{"original":true}\n', json.loads(json.dumps(config)), _fake_xray_metadata()))
    monkeypatch.setattr(helper, "_apply_xray_config_change",
                        lambda candidate, raw, metadata: applied.append(candidate) or "/protected/backup.bak")
    assert helper.xray_revoke_client("phone01") == {"revoked": True, "name": "phone01"}
    remaining = applied[0]["inbounds"][1]["settings"]["clients"]
    assert remaining == [{"id": "22222222-2222-4222-8222-222222222222", "email": "original"}]
    assert helper._load_xray_clients() == []


def test_xray_client_mutation_refuses_ambiguous_inbounds(tmp_path, monkeypatch):
    _prepare_xray_state_dir(monkeypatch, tmp_path)
    config = _managed_xray_test_config()
    config["inbounds"].append(json.loads(json.dumps(config["inbounds"][0])))
    monkeypatch.setattr(helper, "_read_xray_config_document",
                        lambda: (b'{}', config, _fake_xray_metadata()))
    monkeypatch.setattr(helper, "_apply_xray_config_change",
                        lambda *args: pytest.fail("ambiguous config must not be written"))
    with pytest.raises(SystemExit):
        helper.xray_create_client("phone01", "vmess")
    assert helper._load_xray_clients() == []



def test_xray_apply_restores_original_bytes_if_atomic_replace_reports_failure(tmp_path, monkeypatch):
    from types import SimpleNamespace
    config_path = tmp_path / "config.json"
    config_path.write_text('{"old":true}\n', encoding="utf-8")
    original = b'{"old":true}\n'
    metadata = SimpleNamespace(
        st_uid=os.geteuid(), st_gid=os.getegid(),
        st_mode=stat.S_IFREG | 0o600, st_ino=123, st_mtime_ns=456
    )
    monkeypatch.setattr(helper, "XRAY_CONFIG_PATH", str(config_path))
    monkeypatch.setattr(helper, "_read_xray_config_document",
                        lambda: (original, {"inbounds": []}, metadata))
    monkeypatch.setattr(helper, "_xray_validate_candidate", lambda path: None)
    monkeypatch.setattr(helper, "_save_xray_backup", lambda raw: "/protected/backup.bak")
    writes = []

    def fail_first_write(raw, info):
        writes.append(raw)
        if len(writes) == 1:
            raise SystemExit(1)

    monkeypatch.setattr(helper, "_atomic_xray_config_write", fail_first_write)
    with pytest.raises(SystemExit):
        helper._apply_xray_config_change({"inbounds": []}, original, metadata)
    assert len(writes) == 2
    assert writes[1] == original



def test_xray_candidate_is_valid_json_with_real_newline_before_apply(tmp_path, monkeypatch):
    from types import SimpleNamespace
    config_path = tmp_path / "config.json"
    config_path.write_text('{"inbounds":[]}\n', encoding="utf-8")
    original = config_path.read_bytes()
    metadata = SimpleNamespace(
        st_uid=os.geteuid(), st_gid=os.getegid(),
        st_mode=stat.S_IFREG | 0o600, st_ino=123, st_mtime_ns=456
    )
    monkeypatch.setattr(helper, "XRAY_CONFIG_PATH", str(config_path))
    monkeypatch.setattr(helper, "_read_xray_config_document",
                        lambda: (original, {"inbounds": []}, metadata))
    validated = []
    def validate_candidate(path):
        raw = open(path, "rb").read()
        validated.append(raw)
        assert raw.endswith(b"\n")
        assert json.loads(raw.decode("utf-8")) == {"inbounds": []}
    monkeypatch.setattr(helper, "_xray_validate_candidate", validate_candidate)
    monkeypatch.setattr(helper, "_save_xray_backup", lambda raw: "/protected/backup.bak")
    writes = []
    monkeypatch.setattr(helper, "_atomic_xray_config_write",
                        lambda raw, info: writes.append(raw))
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k:
                        helper.subprocess.CompletedProcess(a[0], 0, "", ""))
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    result = helper._apply_xray_config_change({"inbounds": []}, original, metadata)
    assert result == "/protected/backup.bak"
    assert len(validated) == 1 and len(writes) == 1
    assert json.loads(writes[0].decode("utf-8")) == {"inbounds": []}


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


def test_openvpn_pki_lock_does_not_relabel_operation_oserror(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(helper, "_safe_root_directory", lambda path: True)
    monkeypatch.setattr(helper.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1
    ))
    monkeypatch.setattr(helper.fcntl, "flock", lambda *args: None)

    with pytest.raises(OSError, match="operation failed"):
        with helper._openvpn_pki_lock(str(tmp_path)):
            raise OSError("operation failed")


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
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: True)
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
    assert calls[0][0] == [
        "/bin/sh", "-c", 'umask 077; exec "$@"', "iyke-openvpn-easyrsa",
        str(script), "--batch", "build-client-full", "phone01", "nopass"
    ]
    assert calls[0][1]["env"]["EASYRSA_PKI"] == str(pki)
    assert calls[0][1]["env"]["EASYRSA_BATCH"] == "1"
    assert calls[0][1]["timeout"] == 90
    assert "PRIVATE KEY" not in json.dumps(result)
    assert stat.S_IMODE((pki / "private" / "phone01.key").stat().st_mode) == 0o600


def test_openvpn_create_client_restricts_permissive_key_before_success(tmp_path, monkeypatch):
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
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda path: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: str(script))
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: True)
    updated = "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: updated)

    def fake_run(args, **kwargs):
        key = pki / "private" / "phone01.key"
        key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
        key.chmod(0o644)
        cert = pki / "issued" / "phone01.crt"
        cert.write_text("PUBLIC CERTIFICATE", encoding="utf-8")
        cert.chmod(0o600)
        return helper.subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    result = helper.openvpn_create_client("phone01")
    assert result == {"created": True, "name": "phone01"}
    assert stat.S_IMODE((pki / "private" / "phone01.key").stat().st_mode) == 0o600


def test_openvpn_create_client_revokes_certificate_after_post_issue_validation_failure(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    script = tmp_path / "easyrsa"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    _pretend_root_owned(monkeypatch)
    initial = ""
    issued = "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
    revoked = "R\t301231235959Z\t261114000000Z\t01\tunknown\t/CN=phone01\n"
    index_state = {"value": initial}
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: (str(pki), initial))
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda path: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: str(script))
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: index_state["value"])
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: False)
    monkeypatch.setattr(helper, "_openvpn_crl_contains_serial", lambda path, serial: True)
    monkeypatch.setattr(helper, "_openvpn_crl_signed_by_ca", lambda path, pki_path: True)

    def fake_issue(args, **kwargs):
        key = pki / "private" / "phone01.key"
        key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
        key.chmod(0o644)
        cert = pki / "issued" / "phone01.crt"
        cert.write_text("INVALID CLIENT CERTIFICATE", encoding="utf-8")
        cert.chmod(0o600)
        index_state["value"] = issued
        return helper.subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(helper.subprocess, "run", fake_issue)
    easyrsa_calls = []

    def fake_easyrsa(easyrsa, pki_path, arguments):
        easyrsa_calls.append(arguments)
        if arguments[0] == "revoke":
            index_state["value"] = revoked

    monkeypatch.setattr(helper, "_openvpn_run_easyrsa", fake_easyrsa)
    with pytest.raises(SystemExit):
        helper.openvpn_create_client("phone01")
    assert not (pki / "private" / "phone01.key").exists()
    assert helper._openvpn_index_clients(index_state["value"])[0]["status"] == "revoked"
    assert easyrsa_calls == [["revoke", "phone01"], ["gen-crl"]]


def test_openvpn_failed_issuance_repairs_crl_for_already_revoked_index(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    _pretend_root_owned(monkeypatch)
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    key = pki / "private" / "phone01.key"
    key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
    key.chmod(0o600)
    revoked = "R\t301231235959Z\t261114000000Z\t01\tunknown\t/CN=phone01\n"
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: revoked)
    crl_state = {"contains": False}
    monkeypatch.setattr(
        helper, "_openvpn_crl_contains_serial",
        lambda path, serial: crl_state["contains"]
    )
    monkeypatch.setattr(helper, "_openvpn_crl_signed_by_ca", lambda path, pki_path: True)
    easyrsa_calls = []

    def fake_easyrsa(easyrsa, pki_path, arguments):
        easyrsa_calls.append(arguments)
        if arguments == ["gen-crl"]:
            crl_state["contains"] = True

    monkeypatch.setattr(helper, "_openvpn_run_easyrsa", fake_easyrsa)
    helper._openvpn_cleanup_failed_issuance(str(pki), "phone01", "/usr/bin/easyrsa")
    assert easyrsa_calls == [["gen-crl"]]
    assert crl_state["contains"] is True
    assert not key.exists()


def test_openvpn_failed_issuance_rejects_untrusted_crl_signature(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    _pretend_root_owned(monkeypatch)
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    key = pki / "private" / "phone01.key"
    key.write_text("PRIVATE KEY MATERIAL", encoding="utf-8")
    key.chmod(0o600)
    revoked = "R\t301231235959Z\t261114000000Z\t01\tunknown\t/CN=phone01\n"
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: revoked)
    monkeypatch.setattr(helper, "_openvpn_crl_contains_serial", lambda path, serial: True)
    monkeypatch.setattr(helper, "_openvpn_crl_signed_by_ca", lambda path, pki_path: False)
    monkeypatch.setattr(helper, "_openvpn_run_easyrsa", lambda *args, **kwargs: None)

    with pytest.raises(SystemExit):
        helper._openvpn_cleanup_failed_issuance(str(pki), "phone01", "/usr/bin/easyrsa")
    assert not key.exists()


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


def test_openvpn_create_client_rejects_pki_change_after_lock(monkeypatch):
    monkeypatch.setattr(
        helper, "_openvpn_unique_pki",
        lambda require_ca_key=False: ("/different/pki", "")
    )
    monkeypatch.setattr(
        helper, "_openvpn_easyrsa_path",
        lambda: pytest.fail("Easy-RSA must not run when the PKI changes")
    )
    with pytest.raises(SystemExit):
        helper._openvpn_create_client_unlocked("phone01", "/locked/pki")


def test_openvpn_create_client_rejects_failed_easyrsa(monkeypatch, capsys):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: ("/safe/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda pki: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: "/usr/share/easy-rsa/easyrsa")
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: "")
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


@pytest.mark.parametrize("pem_header", [
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\\n",
    b"-----BEGIN RSA PRIVATE KEY-----\\nProc-Type: 4,ENCRYPTED\\n",
])
def test_openvpn_unique_pki_rejects_encrypted_ca_key(tmp_path, monkeypatch, capsys, pem_header):
    pki = tmp_path / "pki"
    for name in ("issued", "private"):
        (pki / name).mkdir(parents=True, mode=0o700)
        (pki / name).chmod(0o700)
    pki.chmod(0o700)
    (pki / "index.txt").write_text("", encoding="utf-8")
    (pki / "index.txt").chmod(0o600)
    ca_key = pki / "private" / "ca.key"
    ca_key.write_bytes(pem_header + b"redacted-test-payload\\n")
    ca_key.chmod(0o600)
    _pretend_root_owned(monkeypatch)
    monkeypatch.setattr(helper, "_openvpn_pki_candidates", lambda: [str(pki)])
    with pytest.raises(SystemExit):
        helper._openvpn_unique_pki(require_ca_key=True)
    assert "CA private key is encrypted" in capsys.readouterr().err


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





def test_openvpn_get_profile_builds_inline_profile_only_for_verified_server(monkeypatch, tmp_path):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: ("/etc/openvpn/easy-rsa/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda pki: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_index_clients", lambda value: [{"common_name": "phone01", "status": "valid"}])
    monkeypatch.setattr(helper, "_openvpn_server_config_paths", lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: True)
    monkeypatch.setattr(helper, "_openvpn_config_uses_pki_ca", lambda config_path, directives, selected_pki: True)
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: True)
    monkeypatch.setattr(helper, "_openvpn_config_directives", lambda path: {
        "port": [["1194"]], "proto": [["udp"]], "dev": [["tun"]],
        "ca": [["/etc/openvpn/easy-rsa/pki/ca.crt"]],
        "tls-auth": [["ta.key"]],
    })
    def read_pem(path, label, max_bytes=1024 * 1024):
        return {
            "CA certificate": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
            "client certificate": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
            "client private key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
            "tls-auth key": "-----BEGIN OpenVPN Static key V1-----\nTLSKEY\n-----END OpenVPN Static key V1-----\n",
        }[label]
    monkeypatch.setattr(helper, "_openvpn_read_pem", read_pem)
    key_file = tmp_path / "phone01.key"
    key_file.write_text("private key", encoding="ascii")
    key_file.chmod(0o600)
    monkeypatch.setattr(helper, "_openvpn_trusted_file",
                        lambda path, max_bytes=4 * 1024 * 1024: os.open(key_file, os.O_RDONLY))
    result = helper.openvpn_get_profile("phone01", "vpn.example.com")
    assert result["name"] == "phone01"
    assert "remote vpn.example.com 1194" in result["profile"]
    assert "<ca>" in result["profile"] and "<cert>" in result["profile"]
    assert "<key>" in result["profile"] and "KEY" in result["profile"]
    assert "<tls-auth>" in result["profile"]
    assert "key-direction" not in result["profile"]


@pytest.mark.parametrize(
    ("serial", "crl_text", "expected"),
    [
        ("01", "Serial Number: 01\n", True),
        ("000A", "Serial Number: 0a\n", True),
        ("01", "Serial Number: 02\n", False),
        ("not-hex", "Serial Number: 01\n", False),
    ],
)
def test_openvpn_crl_contains_exact_revoked_serial(
    tmp_path, monkeypatch, serial, crl_text, expected
):
    crl = tmp_path / "crl.pem"
    crl.write_text("CRL", encoding="ascii")
    monkeypatch.setattr(helper, "_openvpn_trusted_file",
                        lambda path, max_bytes=4 * 1024 * 1024: os.open(crl, os.O_RDONLY))
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    monkeypatch.setattr(helper.subprocess, "run", lambda args, **kwargs:
        helper.subprocess.CompletedProcess(args, 0, crl_text, ""))
    assert helper._openvpn_crl_contains_serial(str(crl), serial) is expected


def test_openvpn_revoke_client_requires_client_eku_before_any_easyrsa_action(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    pki.mkdir(mode=0o700)
    index = "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: (str(pki), index))
    monkeypatch.setattr(helper, "_safe_root_directory", lambda path: True)
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: index)
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: False)
    monkeypatch.setattr(helper, "_openvpn_run_easyrsa",
                        lambda *args, **kwargs: pytest.fail("Easy-RSA must not run for a non-client certificate"))
    with pytest.raises(SystemExit):
        helper.openvpn_revoke_client("phone01")


def test_openvpn_revoke_client_regenerates_verified_crl(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    pki.mkdir(mode=0o700)
    initial = "V\t301231235959Z\t\t01\tunknown\t/CN=phone01\n"
    revoked = "R\t301231235959Z\t261114000000Z\t01\tunknown\t/CN=phone01\n"
    index_state = {"value": initial}
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda require_ca_key=False: (str(pki), initial))
    monkeypatch.setattr(helper, "_safe_root_directory", lambda path: True)
    monkeypatch.setattr(helper.os, "fstat", lambda fd: type("Info", (), {
        "st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_nlink": 1,
        "st_size": 128
    })())
    monkeypatch.setattr(helper, "_read_openvpn_index", lambda path: index_state["value"])
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: True)
    monkeypatch.setattr(helper, "_openvpn_server_config_paths",
                        lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: True)
    monkeypatch.setattr(helper, "_openvpn_crl_state", lambda path: {
        "crl_configured": True, "crl_file_present": True
    })
    monkeypatch.setattr(helper, "_openvpn_crl_contains_serial", lambda path, serial: serial == "01")
    ca_file = pki / "ca.crt"
    ca_file.write_text("CA CERTIFICATE", encoding="ascii")
    ca_file.chmod(0o600)
    monkeypatch.setattr(helper, "_openvpn_config_directives", lambda path: {
        "ca": [[str(ca_file)]], "cert": [["server.crt"]]
    })
    monkeypatch.setattr(helper, "_openvpn_config_uses_pki_ca",
                        lambda config_path, directives, selected_pki: True)
    monkeypatch.setattr(helper, "_openvpn_read_pem", lambda path, label: "-----BEGIN X509 CRL-----\nCRL\n-----END X509 CRL-----\n")
    monkeypatch.setattr(helper, "_openvpn_easyrsa_path", lambda: "/usr/bin/easyrsa")
    calls = []
    def fake_easyrsa(easyrsa, pki_path, arguments):
        calls.append(arguments)
        if arguments[0] == "revoke":
            index_state["value"] = revoked
    monkeypatch.setattr(helper, "_openvpn_run_easyrsa", fake_easyrsa)
    result = helper.openvpn_revoke_client("phone01")
    assert result == {
        "name": "phone01", "revoked": True, "crl_regenerated": True,
        "server_reload_performed": False,
    }
    assert calls == [["revoke", "phone01"], ["gen-crl"]]


def test_openvpn_get_profile_rejects_private_or_invalid_endpoint(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: pytest.fail("must reject endpoint before reading PKI"))
    for endpoint in ("127.0.0.1", "localhost", "vpn.example.com:1194", "../bad"):
        with pytest.raises(SystemExit):
            helper.openvpn_get_profile("phone01", endpoint)


def test_openvpn_get_profile_requires_verified_active_server(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: ("/safe/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda pki: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_index_clients", lambda value: [{"common_name": "phone01", "status": "valid"}])
    monkeypatch.setattr(helper, "_openvpn_server_config_paths", lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: False)
    with pytest.raises(SystemExit):
        helper.openvpn_get_profile("phone01", "vpn.example.com")


def test_openvpn_certificate_is_client_requires_client_auth_eku(monkeypatch, tmp_path):
    cert = tmp_path / "client.crt"
    cert.write_text("certificate", encoding="ascii")
    cert.chmod(0o600)
    fd = os.open(cert, os.O_RDONLY)
    monkeypatch.setattr(helper, "_openvpn_trusted_file", lambda path, max_bytes=4 * 1024 * 1024: os.dup(fd))
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/openssl")
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k:
        helper.subprocess.CompletedProcess(a[0], 0, "X509v3 Extended Key Usage:\n TLS Web Client Authentication\n", ""))
    assert helper._openvpn_certificate_is_client(str(cert)) is True
    monkeypatch.setattr(helper.subprocess, "run", lambda *a, **k:
        helper.subprocess.CompletedProcess(a[0], 0, "X509v3 Extended Key Usage:\n TLS Web Server Authentication\n", ""))
    assert helper._openvpn_certificate_is_client(str(cert)) is False
    os.close(fd)


def test_openvpn_profile_rejects_server_certificate_eku(monkeypatch):
    monkeypatch.setattr(helper, "_openvpn_unique_pki", lambda: ("/safe/pki", ""))
    monkeypatch.setattr(helper, "_openvpn_pki_lock", lambda pki: __import__("contextlib").nullcontext())
    monkeypatch.setattr(helper, "_openvpn_index_clients", lambda value: [{"common_name": "phone01", "status": "valid"}])
    monkeypatch.setattr(helper, "_openvpn_server_config_paths", lambda: ["/etc/openvpn/server/server.conf"])
    monkeypatch.setattr(helper, "_unit_state", lambda unit: "active")
    monkeypatch.setattr(helper, "_openvpn_runtime_config_matches", lambda unit, path: True)
    monkeypatch.setattr(helper, "_openvpn_config_directives", lambda path: {})
    monkeypatch.setattr(helper, "_openvpn_certificate_is_client", lambda path: False)
    with pytest.raises(SystemExit):
        helper.openvpn_get_profile("phone01", "vpn.example.com")
