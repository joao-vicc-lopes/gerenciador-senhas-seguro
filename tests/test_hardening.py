"""Additional regression checks for v3, backups, security and concurrency."""
import json
import multiprocessing
import os
from pathlib import Path
import stat
import time

import pytest
from cryptography.fernet import Fernet
from vault.crypto import VaultCorruptedError, check_master_strength, record_id
from vault.service import VaultService
from vault import storage


def test_password_policy():
    assert not check_master_strength("123456")
    assert not check_master_strength("passwordpassword")
    assert not check_master_strength("aaaaaaaaaaaaaaaaaaa")
    assert not check_master_strength("short")
    assert check_master_strength("correct-horse-battery-staple")


def test_initial_creation_weak_passphrase_no_artifacts(tmp_path):
    service = VaultService(str(tmp_path / "cofre.json"), str(tmp_path / "salt.key"))
    with pytest.raises(ValueError):
        service.create("passwordpassword")
    assert not (tmp_path / "cofre.json").exists()
    assert not (tmp_path / "salt.key").exists()


def test_display_opt_in(setup_vault, capsys):
    app, key, _ = setup_vault
    app.add_senha(key, "bank.test", "user", "very-secret")
    capsys.readouterr()
    app.get_senha(key, "bank.test")
    assert "very-secret" not in capsys.readouterr().out
    app.get_senha(key, "bank.test", reveal=True)
    assert "very-secret" in capsys.readouterr().out


def test_v3_index_hides_site_and_is_deterministic(setup_vault):
    app, key, _ = setup_vault
    app.add_senha(key, "private-site.test", "private-login", "secret")
    data = json.loads(Path(app.COFRE_ARQUIVO).read_text())
    assert data["__FORMAT_VERSION__"] == 3
    assert "private-site.test" not in json.dumps(data)
    assert "private-login" not in json.dumps(data)
    assert record_id(key, "private-site.test") in data["__RECORDS__"]


def test_v3_corrupt_other_record_does_not_block_lookup(setup_vault, capsys):
    app, key, _ = setup_vault
    app.add_senha(key, "good.test", "user", "good-secret")
    app.add_senha(key, "bad.test", "user", "bad-secret")
    path = Path(app.COFRE_ARQUIVO)
    d = json.loads(path.read_text())
    d["__RECORDS__"][record_id(key, "bad.test")] = "corrupted"
    path.write_text(json.dumps(d))
    app.get_senha(key, "good.test", reveal=True)
    assert "good-secret" in capsys.readouterr().out
    app.get_senha(key, "bad.test", reveal=True)
    assert "corrompid" in capsys.readouterr().out.lower()


def test_backup_contains_previous_state_without_plaintext(setup_vault):
    app, key, _ = setup_vault
    app.add_senha(key, "one.test", "user", "one-secret")
    app.add_senha(key, "two.test", "user", "two-secret")
    backup = Path(app.COFRE_ARQUIVO + ".bak")
    raw = backup.read_text()
    assert "one.test" not in raw and "one-secret" not in raw
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert "__RECORDS__" in json.loads(Path(app.COFRE_ARQUIVO).read_text())


def test_explicit_recovery_undoes_last_addition(setup_vault):
    app, key, master = setup_vault
    app.add_senha(key, "first.test", "user", "first")
    app.add_senha(key, "second.test", "user", "second")
    service = VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO)
    service.recover(master)
    assert service.get(key, "first.test")["senha"] == "first"
    assert service.get(key, "second.test") is None


def test_recovery_with_wrong_password_never_replaces(setup_vault):
    app, key, master = setup_vault
    app.add_senha(key, "site.test", "user", "one")
    path = Path(app.COFRE_ARQUIVO)
    original = path.read_bytes()
    with pytest.raises(VaultCorruptedError):
        VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO).recover("wrong-password")
    assert path.read_bytes() == original


def test_recovery_with_tampered_backup_never_replaces(setup_vault):
    app, key, master = setup_vault
    app.add_senha(key, "site.test", "user", "one")
    path = Path(app.COFRE_ARQUIVO)
    original = path.read_bytes()
    back = Path(app.COFRE_ARQUIVO + ".bak")
    bundle = json.loads(back.read_text())
    bundle["vault"] = "AQ=="
    back.write_text(json.dumps(bundle))
    with pytest.raises((VaultCorruptedError, ValueError, UnicodeError)):
        VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO).recover(master)
    assert path.read_bytes() == original


def _add_in_separate_process(path, salt, key, prefix, count):
    service = VaultService(path, salt)
    for i in range(count):
        service.add(key, f"{prefix}-{i}.test", "user", "safe-secret")


@pytest.mark.skipif(os.name != "posix", reason="fcntl file locking requires POSIX")
def test_two_writers_do_not_lose_updates(setup_vault):
    app, key, master = setup_vault
    ctx = multiprocessing.get_context("spawn")
    first = ctx.Process(target=_add_in_separate_process, args=(app.COFRE_ARQUIVO, app.SALT_ARQUIVO, key, "a", 6))
    second = ctx.Process(target=_add_in_separate_process, args=(app.COFRE_ARQUIVO, app.SALT_ARQUIVO, key, "b", 6))
    first.start(); second.start()
    first.join(25); second.join(25)
    if first.is_alive(): first.terminate()
    if second.is_alive(): second.terminate()
    assert first.exitcode == second.exitcode == 0
    service = VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO)
    for prefix in ("a", "b"):
        for i in range(6):
            assert service.get(key, f"{prefix}-{i}.test")["senha"] == "safe-secret"


def test_v2_vault_migrates_to_v3(setup_vault):
    app, key, _ = setup_vault
    path = Path(app.COFRE_ARQUIVO)
    status = json.loads(path.read_text())["STATUS"]
    encrypted = Fernet(key).encrypt(json.dumps({"old.test": {"login": "user", "senha": "old"}}).encode()).decode()
    path.write_text(json.dumps({"STATUS": status, "__FORMAT_VERSION__": 2, "__VAULT_DATA__": encrypted}))
    app.add_senha(key, "new.test", "new-user", "new-secret")
    assert json.loads(path.read_text())["__FORMAT_VERSION__"] == 3
    service = VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO)
    assert service.get(key, "old.test")["senha"] == "old"
    assert service.get(key, "new.test")["senha"] == "new-secret"


def test_v3_record_index_mismatch_rejected(setup_vault, capsys):
    app, key, master = setup_vault
    app.add_senha(key, "site1.test", "user", "one")
    data = json.loads(Path(app.COFRE_ARQUIVO).read_text())
    token = next(iter(data["__RECORDS__"].values()))
    data["__RECORDS__"] = {record_id(key, "other.test"): token}
    Path(app.COFRE_ARQUIVO).write_text(json.dumps(data))
    app.get_senha(key, "other.test", reveal=True)
    assert "corrompid" in capsys.readouterr().out.lower()