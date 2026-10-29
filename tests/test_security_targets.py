"""S-01 to S-04: formerly XFAIL, now permanent security regression tests."""
import json
from pathlib import Path
import pytest


def test_metadados_nao_ficam_legiveis_no_arquivo(setup_vault):
    app, key, _ = setup_vault
    app.add_senha(key, "site-ultra-sensivel.test", "login-ficticio@exemplo.test", "segredo")
    raw = Path(app.COFRE_ARQUIVO).read_text()
    assert "site-ultra-sensivel.test" not in raw
    assert "login-ficticio@exemplo.test" not in raw


def test_criacao_rejeita_senha_mestra_vazia(vault_app, monkeypatch):
    entradas = iter(["", ""])
    monkeypatch.setattr(vault_app.getpass, "getpass", lambda *a, **kw: next(entradas))
    try:
        vault_app.novo_cofre()
    except (StopIteration, ValueError, SystemExit):
        pass
    assert not Path(vault_app.COFRE_ARQUIVO).exists()


def test_erro_na_gravacao_nao_destroi_cofre(setup_vault, monkeypatch):
    app, key, _ = setup_vault
    caminho = Path(app.COFRE_ARQUIVO)
    antes = caminho.read_bytes()
    original_dump = json.dump

    def falha_apos_escrita_parcial(obj, fp, *args, **kwargs):
        fp.write('{"escrita":"incompleta"')
        raise OSError("Falha de escrita simulada")

    monkeypatch.setattr(app.json, "dump", falha_apos_escrita_parcial)
    try:
        app.add_senha(key, "x.test", "user", "pw")
    except OSError:
        pass
    finally:
        monkeypatch.setattr(app.json, "dump", original_dump)
    assert caminho.read_bytes() == antes


def test_json_sem_status_falha_de_modo_controlado(setup_vault):
    app, _, _ = setup_vault
    Path(app.COFRE_ARQUIVO).write_text('{"invalido":"x"}', encoding="utf-8")
    assert app.autenticar() is None


def test_legacy_vault_read_then_migrate_losslessly(setup_vault, capsys):
    """An original v1 vault remains readable and is upgraded only on add."""
    from cryptography.fernet import Fernet
    app, key, _ = setup_vault
    motor = Fernet(key)
    path = Path(app.COFRE_ARQUIVO)
    original = json.loads(path.read_text())
    legacy = {
        "STATUS": original["STATUS"],
        "legacy.example": {
            "login": "old-user@example.org",
            "senha": motor.encrypt("old-secret".encode()).decode("ascii"),
        },
    }
    path.write_text(json.dumps(legacy), encoding="utf-8")
    capsys.readouterr()
    app.get_senha(key, "legacy.example", reveal=True)
    assert "old-secret" in capsys.readouterr().out
    assert json.loads(path.read_text()) == legacy  # reads do not mutate
    app.add_senha(key, "new.example", "new-user", "new-secret")
    content = path.read_text()
    assert "legacy.example" not in content
    assert "old-user@example.org" not in content
    assert "new.example" not in content
    assert "new-user" not in content
    assert json.loads(content)["__FORMAT_VERSION__"] == 3
    capsys.readouterr()
    app.get_senha(key, "legacy.example", reveal=True)
    app.get_senha(key, "new.example", reveal=True)
    result = capsys.readouterr().out
    assert "old-secret" in result and "new-secret" in result


def test_corrupted_legacy_record_prevents_migration(setup_vault):
    app, key, _ = setup_vault
    path = Path(app.COFRE_ARQUIVO)
    original = json.loads(path.read_text())
    original["bad.example"] = {"login": "old", "senha": "definitely-not-fernet"}
    path.write_text(json.dumps(original), encoding="utf-8")
    before = path.read_bytes()
    app.add_senha(key, "fresh.example", "new", "new-password")
    assert path.read_bytes() == before


def test_failed_replace_preserves_previous_vault(setup_vault, monkeypatch):
    app, key, _ = setup_vault
    path = Path(app.COFRE_ARQUIVO)
    before = path.read_bytes()

    def replace_fails(*args, **kwargs):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(app.os, "replace", replace_fails)
    app.add_senha(key, "x.test", "x", "p")
    assert path.read_bytes() == before
    assert not list(path.parent.glob(".vault-*.tmp"))


def test_new_vault_creation_failure_cleans_up_salt(vault_app, monkeypatch):
    app = vault_app
    monkeypatch.setattr(app.getpass, "getpass", lambda *a, **kw: "valid-long-test-phrase-2026")

    def dump_fails(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(app.json, "dump", dump_fails)
    app.novo_cofre()
    assert not Path(app.COFRE_ARQUIVO).exists()
    assert not Path(app.SALT_ARQUIVO).exists()


def test_malformed_v2_envelope_rejected_without_overwrite(setup_vault):
    app, key, _ = setup_vault
    path = Path(app.COFRE_ARQUIVO)
    contents = json.loads(path.read_text())
    contents["__FORMAT_VERSION__"] = 999
    path.write_text(json.dumps(contents), encoding="utf-8")
    before = path.read_bytes()
    assert app.autenticar() is None
    app.add_senha(key, "x.test", "x", "p")
    assert path.read_bytes() == before


def test_created_files_restrict_permissions(setup_vault):
    import stat
    app, key, _ = setup_vault
    vault_mode = stat.S_IMODE(Path(app.COFRE_ARQUIVO).stat().st_mode)
    salt_mode = stat.S_IMODE(Path(app.SALT_ARQUIVO).stat().st_mode)
    assert vault_mode == 0o600
    assert salt_mode == 0o600
    app.add_senha(key, "site.example", "login", "secret")
    assert stat.S_IMODE(Path(app.COFRE_ARQUIVO).stat().st_mode) == 0o600