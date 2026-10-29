"""Fuzz-like bad input and failure-path checks; no real credentials."""
import json
import os
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from vault.crypto import VaultCorruptedError, record_id
from vault.service import VaultService
from vault import storage


def test_invalid_salt_direct():
    from vault.crypto import derive_key
    with pytest.raises(VaultCorruptedError):
        derive_key("fake", b"short")


@pytest.mark.parametrize("bad", [[], {"STATUS": "hi", "__FORMAT_VERSION__": 99},
    {"STATUS": 9}, {"STATUS": "hi", "__FORMAT_VERSION__": 3, "__RECORDS__": []},
    {"STATUS": "hi", "__FORMAT_VERSION__": 3, "__RECORDS__": {"wrong": "token"}},
    {"STATUS": "hi", "__FORMAT_VERSION__": 2, "__VAULT_DATA__": 7}])
def test_reject_malformed_structures(tmp_path, bad):
    path = tmp_path / "test.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(VaultCorruptedError):
        storage.read_json(str(path))


def test_bad_record_payload_rejected(initialized_service):
    service, key, _ = initialized_service
    service.add(key, "site.test", "user", "secret")
    data = json.loads(Path(service.path).read_text())
    token = Fernet(key).encrypt(b'{"site": "site.test", "login": "user"}').decode()
    data["__RECORDS__"][record_id(key, "site.test")] = token
    Path(service.path).write_text(json.dumps(data))
    with pytest.raises(VaultCorruptedError):
        service.get(key, "site.test")


def test_bad_record_cannot_be_overwritten(initialized_service):
    service, key, _ = initialized_service
    service.add(key, "site.test", "user", "secret")
    path = Path(service.path)
    data = json.loads(path.read_text())
    data["__RECORDS__"][record_id(key, "site.test")] = "invalid"
    path.write_text(json.dumps(data))
    before = path.read_bytes()
    with pytest.raises(VaultCorruptedError):
        service.add(key, "site.test", "user", "replacement")
    assert path.read_bytes() == before


def test_read_only_file_mode_after_recovery(initialized_service):
    service, key, password = initialized_service
    service.add(key, "first.test", "user", "secret")
    service.add(key, "second.test", "user", "secret")
    service.recover(password)
    assert service.get(key, "first.test") is not None
    assert service.get(key, "second.test") is None
    assert oct(os.stat(service.path).st_mode & 0o777) == "0o600"


def test_missing_backup_reports_failure(initialized_service):
    service, key, password = initialized_service
    with pytest.raises(FileNotFoundError):
        service.recover(password)


def test_bad_backup_salt_is_rejected(initialized_service):
    service, key, password = initialized_service
    service.add(key, "site.test", "user", "secret")
    backup = Path(service.path + ".bak")
    data = json.loads(backup.read_text())
    data["salt"] = "not-base64!"
    backup.write_text(json.dumps(data))
    with pytest.raises(VaultCorruptedError):
        service.recover(password)


def test_bad_legacy_field_blocks_migration(initialized_service):
    service, key, password = initialized_service
    path = Path(service.path)
    initial = json.loads(path.read_text())
    path.write_text(json.dumps({"STATUS": initial["STATUS"], "x.test": {"login": 9, "senha": "fake"}}))
    before = path.read_bytes()
    with pytest.raises(VaultCorruptedError):
        service.add(key, "another.test", "user", "pw")
    assert path.read_bytes() == before


def test_failed_backup_cannot_replace_vault(initialized_service, monkeypatch):
    service, key, password = initialized_service
    path = Path(service.path)
    before = path.read_bytes()
    original_atomic = storage.atomic_json
    def interrupt(path, value):
        if str(path).endswith(".bak"):
            raise OSError("backup unavailable")
        return original_atomic(path, value)
    monkeypatch.setattr(storage, "atomic_json", interrupt)
    with pytest.raises(OSError):
        service.add(key, "site.test", "user", "secret")
    assert path.read_bytes() == before


def test_restore_wrong_token_safely_rejected(initialized_service):
    service, key, password = initialized_service
    service.add(key, "first.test", "user", "secret")
    data = json.loads(Path(service.path + ".bak").read_text())
    import base64
    orig = json.loads(base64.b64decode(data["vault"]))
    orig["STATUS"] = "invalid"
    data["vault"] = base64.b64encode(json.dumps(orig).encode()).decode()
    Path(service.path + ".bak").write_text(json.dumps(data))
    with pytest.raises(VaultCorruptedError):
        service.recover(password)


@pytest.fixture
def initialized_service(tmp_path):
    svc = VaultService(str(tmp_path / "vault.json"), str(tmp_path / "salt.key"))
    pwd = "really-long-safe-master-2026"
    svc.create(pwd)
    return svc, svc.authenticate(pwd), pwd


def test_main_reprompts_weak_master(vault_app, monkeypatch, capsys):
    entries = iter(["weak", "weak", "safe-long-phrase-2026", "safe-long-phrase-2026"])
    monkeypatch.setattr(vault_app.getpass, "getpass", lambda *a, **kw: next(entries))
    vault_app.novo_cofre()
    assert "fraca" in capsys.readouterr().out
    assert Path(vault_app.COFRE_ARQUIVO).exists()


def test_recovery_cli_cancel_and_failure(setup_vault, monkeypatch, capsys):
    app, key, _ = setup_vault
    monkeypatch.setattr("builtins.input", lambda *args: "NO")
    app.recuperar_cofre()
    assert "cancelada" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda *args: "RECOVER")
    app.recuperar_cofre()
    assert "Backup inválido" in capsys.readouterr().out


def test_recovery_cli_success_and_menu_switch(setup_vault, monkeypatch, capsys):
    app, key, master = setup_vault
    app.add_senha(key, "first.test", "u", "first")
    app.add_senha(key, "last.test", "u", "last")
    monkeypatch.setattr(app.sys, "argv", ["main.py", "--recover"])
    monkeypatch.setattr("builtins.input", lambda *args: "RECOVER")
    monkeypatch.setattr(app.getpass, "getpass", lambda *args, **kw: master)
    app.menu()
    assert "restaurado" in capsys.readouterr().out
    assert VaultService(app.COFRE_ARQUIVO, app.SALT_ARQUIVO).get(key, "last.test") is None


def test_backup_rejects_invalid_envelope_and_bad_salt(initialized_service):
    service, key, password = initialized_service
    service.add(key, "x.test", "u", "secret")
    backup = Path(service.path + ".bak")
    backup.write_text(json.dumps({"backup_format": 5, "vault": "", "salt": ""}))
    with pytest.raises(VaultCorruptedError):
        service.recover(password)
    backup.write_text(json.dumps({"backup_format": 1, "vault": "e30=", "salt": "YQ=="}))
    with pytest.raises(VaultCorruptedError):
        service.recover(password)


def test_backup_rejects_unsupported_version(initialized_service):
    import base64
    service, key, pwd = initialized_service
    service.add(key, "x.test", "u", "secret")
    backup = Path(service.path + ".bak")
    d = json.loads(backup.read_text())
    raw = json.loads(base64.b64decode(d["vault"]))
    raw["__FORMAT_VERSION__"] = 99
    d["vault"] = base64.b64encode(json.dumps(raw).encode()).decode()
    backup.write_text(json.dumps(d))
    with pytest.raises(VaultCorruptedError):
        service.recover(pwd)


def test_backup_rejects_malformed_v3_records(initialized_service):
    import base64
    service, key, pwd = initialized_service
    service.add(key, "x.test", "u", "secret")
    backup = Path(service.path + ".bak")
    d = json.loads(backup.read_text())
    raw = json.loads(base64.b64decode(d["vault"]))
    raw["__RECORDS__"] = []
    d["vault"] = base64.b64encode(json.dumps(raw).encode()).decode()
    backup.write_text(json.dumps(d))
    with pytest.raises(VaultCorruptedError):
        service.recover(pwd)


def test_master_password_wrong_or_missing_salt(initialized_service):
    service, key, password = initialized_service
    with pytest.raises(VaultCorruptedError):
        service.authenticate("invalid-long-password-2026")
    Path(service.salt_path).write_bytes(b"short")
    with pytest.raises(VaultCorruptedError):
        service.authenticate(password)