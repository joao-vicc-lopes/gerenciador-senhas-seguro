import importlib.util
import json
from pathlib import Path
import pytest
from cryptography.fernet import Fernet

@pytest.fixture
def app(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("vault_test", Path(__file__).resolve().parents[1] / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "COFRE_ARQUIVO", str(tmp_path / "vault.json"))
    monkeypatch.setattr(m, "SALT_ARQUIVO", str(tmp_path / "salt.key"))
    return m

@pytest.fixture
def initialized(app, monkeypatch):
    monkeypatch.setattr(app.getpass, "getpass", lambda *args: "fake-master")
    app.novo_cofre()
    k = app.autenticar()
    assert k
    return app, k

def test_s01_hides_metadata(initialized):
    app, k = initialized
    app.add_senha(k, "private.example", "user@example.invalid", "secret-value")
    raw = Path(app.COFRE_ARQUIVO).read_text()
    for text in ("private.example", "user@example.invalid", "secret-value"):
        assert text not in raw
    assert json.loads(raw)["__FORMAT_VERSION__"] == 2

def test_s02_refuses_empty_master(app, monkeypatch):
    inputs = iter(["", ""])
    monkeypatch.setattr(app.getpass, "getpass", lambda *args: next(inputs))
    with pytest.raises(StopIteration):
        app.novo_cofre()
    assert not Path(app.COFRE_ARQUIVO).exists()
    assert not Path(app.SALT_ARQUIVO).exists()

def test_s03_failure_preserves_existing_vault(initialized, monkeypatch):
    app, k = initialized
    target = Path(app.COFRE_ARQUIVO)
    original = target.read_bytes()
    def fail_dump(data, fp, *args, **kwargs):
        fp.write("partial")
        raise OSError("simulated disk error")
    monkeypatch.setattr(app.json, "dump", fail_dump)
    app.add_senha(k, "site", "user", "pw")
    assert target.read_bytes() == original

def test_s03_replace_failure_preserves_data(initialized, monkeypatch):
    app, k = initialized
    target = Path(app.COFRE_ARQUIVO)
    before = target.read_bytes()
    def fail(*args):
        raise OSError("simulated replace error")
    monkeypatch.setattr(app.os, "replace", fail)
    app.add_senha(k, "site", "user", "pw")
    assert target.read_bytes() == before
    assert list(target.parent.glob(".vault-*.tmp")) == []

def test_s04_missing_status_rejected(initialized):
    app, k = initialized
    target = Path(app.COFRE_ARQUIVO)
    target.write_text('{"invalid":"data"}')
    assert app.autenticar() is None
    before = target.read_bytes()
    app.add_senha(k, "site", "user", "pw")
    assert target.read_bytes() == before

def test_legacy_read_and_migrate(initialized, capsys):
    app, k = initialized
    target = Path(app.COFRE_ARQUIVO)
    current = json.loads(target.read_text())
    legacy = {"STATUS": current["STATUS"],
              "old.example": {"login": "old-user",
                              "senha": Fernet(k).encrypt(b"old-password").decode()}}
    target.write_text(json.dumps(legacy))
    app.get_senha(k, "old.example")
    assert "old-password" in capsys.readouterr().out
    assert json.loads(target.read_text()) == legacy
    app.add_senha(k, "new.example", "new-user", "new-password")
    assert "old.example" not in target.read_text()
    app.get_senha(k, "old.example")
    assert "old-password" in capsys.readouterr().out
