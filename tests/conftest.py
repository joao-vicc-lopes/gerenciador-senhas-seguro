"""Fixtures que isolam totalmente os testes de qualquer cofre pessoal."""
import importlib.util
import sys
from pathlib import Path
import pytest


@pytest.fixture
def vault_app(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "main.py"
    if not source.exists():
        pytest.fail("main.py não encontrado. Copie tests/, scripts/ e pytest.ini para a raiz do repositório.")

    spec = importlib.util.spec_from_file_location("main", source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "main", module)
    spec.loader.exec_module(module)

    # Nunca modifica os arquivos cofre.json e salt.key do usuário.
    monkeypatch.setattr(module, "COFRE_ARQUIVO", str(tmp_path / "cofre.json"), raising=True)
    monkeypatch.setattr(module, "SALT_ARQUIVO", str(tmp_path / "salt.key"), raising=True)
    return module


@pytest.fixture
def setup_vault(vault_app, monkeypatch):
    fake_master = "senha-mestra-ficticia-123!"
    monkeypatch.setattr(vault_app.getpass, "getpass", lambda *a, **kw: fake_master)
    vault_app.novo_cofre()
    key = vault_app.autenticar()
    assert key is not None
    return vault_app, key, fake_master