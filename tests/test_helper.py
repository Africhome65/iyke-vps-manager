import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "ops" / "iyke-vps-helper"
SPEC = importlib.util.spec_from_file_location("iyke_helper", HELPER_PATH)
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
        assert helper.load_registry() == set()
        helper.save_registry({"client01", "client02"})
        assert helper.load_registry() == {"client01", "client02"}
    assert stat.S_IMODE((state_dir / "managed-users.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((state_dir / "managed-users.lock").stat().st_mode) == 0o600


def test_registry_rejects_corrupt_data(state_dir):
    path = state_dir / "managed-users.json"
    path.write_text('["client01", 42]', encoding="utf-8")
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
        helper.save_registry({"../root"})


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
