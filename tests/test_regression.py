"""Comportamentos atuais que precisamos preservar ao evoluir o programa."""
import json
import os
from pathlib import Path
import pytest
from cryptography.fernet import Fernet, InvalidToken


def test_kdf_determinista_e_sensivel_a_salt_e_senha(vault_app):
    salt_1, salt_2 = b"a" * 16, b"b" * 16
    key = vault_app.get_chave("mestra-ficticia", salt_1)
    assert key == vault_app.get_chave("mestra-ficticia", salt_1)
    assert key != vault_app.get_chave("outra", salt_1)
    assert key != vault_app.get_chave("mestra-ficticia", salt_2)
    assert len(Fernet(key).encrypt(b"teste")) > 0


def test_criacao_do_cofre_e_salt_aleatorio(setup_vault):
    app, key, _ = setup_vault
    cofre = Path(app.COFRE_ARQUIVO)
    salt = Path(app.SALT_ARQUIVO)
    assert cofre.exists() and salt.exists()
    assert len(salt.read_bytes()) == 16
    assert "AUTENTICADO" not in cofre.read_text()
    # Asserting authentication rather than tying future formats to a STATUS key.
    assert key == app.autenticar()


def test_senha_mestra_errada_nao_autentica(setup_vault, monkeypatch):
    app, _, _ = setup_vault
    monkeypatch.setattr(app.getpass, "getpass", lambda *a, **kw: "senha-errada")
    assert app.autenticar() is None


def test_adicionar_e_recuperar_unicode_sem_vazar_senha_no_json(setup_vault, capsys):
    app, key, _ = setup_vault
    site, login, secret = "exemplo.test", "alguem+ç@exemplo.test", "segredo-fictício-🔒"
    app.add_senha(key, site, login, secret)
    raw = Path(app.COFRE_ARQUIVO).read_text()
    assert secret not in raw
    capsys.readouterr()
    app.get_senha(key, site, reveal=True)
    saida = capsys.readouterr().out
    assert login in saida and secret in saida


def test_adicao_no_mesmo_site_substitui_registro(setup_vault, capsys):
    app, key, _ = setup_vault
    app.add_senha(key, "x.test", "a", "primeira")
    app.add_senha(key, "x.test", "b", "segunda")
    capsys.readouterr()
    app.get_senha(key, "x.test", reveal=True)
    saida = capsys.readouterr().out
    assert "segunda" in saida and "primeira" not in saida and "Login: b" in saida


def test_nome_reservado_nao_substitui_status(setup_vault):
    app, key, _ = setup_vault
    antes = Path(app.COFRE_ARQUIVO).read_bytes()
    app.add_senha(key, "STATUS", "x", "senha")
    assert Path(app.COFRE_ARQUIVO).read_bytes() == antes


def test_token_adulterado_e_rejeitado(setup_vault, capsys):
    app, key, _ = setup_vault
    app.add_senha(key, "x.test", "usuario", "senha")
    caminho = Path(app.COFRE_ARQUIVO)
    dados = json.loads(caminho.read_text())
    # V2 encrypts the whole credentials object: tamper with its opaque token.
    dados["__RECORDS__"][next(iter(dados["__RECORDS__"]))] = "token-invalido"
    caminho.write_text(json.dumps(dados))
    capsys.readouterr()
    app.get_senha(key, "x.test", reveal=True)
    saida = capsys.readouterr().out.lower()
    assert "adulterad" in saida or "corrompid" in saida
    with pytest.raises(InvalidToken):
        Fernet(key).decrypt(b"token-invalido")


def test_json_malformado_nao_e_sobrescrito_na_adicao(setup_vault):
    app, key, _ = setup_vault
    caminho = Path(app.COFRE_ARQUIVO)
    caminho.write_text('{"STATUS": ', encoding="utf-8")
    antes = caminho.read_bytes()
    app.add_senha(key, "site.test", "usuario", "senha")
    assert caminho.read_bytes() == antes


def test_json_malformado_na_autenticacao_e_tratado(setup_vault):
    app, _, _ = setup_vault
    Path(app.COFRE_ARQUIVO).write_text('{"STATUS": ', encoding="utf-8")
    assert app.autenticar() is None


def test_ausencia_de_um_arquivo_nao_recria_cofre(setup_vault):
    app, _, _ = setup_vault
    caminho = Path(app.COFRE_ARQUIVO)
    anterior = caminho.read_bytes()
    os.unlink(app.SALT_ARQUIVO)
    try:
        app.novo_cofre()
    except (SystemExit, ValueError, RuntimeError):
        pass
    assert caminho.read_bytes() == anterior


def test_reabrir_cofre_existente_preserva_arquivos(setup_vault):
    app, _, _ = setup_vault
    salt = Path(app.SALT_ARQUIVO).read_bytes()
    vault = Path(app.COFRE_ARQUIVO).read_bytes()
    app.novo_cofre()
    assert Path(app.SALT_ARQUIVO).read_bytes() == salt
    assert Path(app.COFRE_ARQUIVO).read_bytes() == vault


def test_criacao_pede_nova_confirmacao_quando_nao_coincide(vault_app, monkeypatch, capsys):
    entradas = iter(["uma-senha", "outra-senha", "passphrase-segura-2026", "passphrase-segura-2026"])
    monkeypatch.setattr(vault_app.getpass, "getpass", lambda *a, **kw: next(entradas))
    vault_app.novo_cofre()
    assert "não coincidem" in capsys.readouterr().out
    monkeypatch.setattr(vault_app.getpass, "getpass", lambda *a, **kw: "passphrase-segura-2026")
    assert vault_app.autenticar() is not None


def test_site_nao_encontrado_e_palavra_reservada(setup_vault, capsys):
    app, key, _ = setup_vault
    capsys.readouterr()
    app.get_senha(key, "inexistente.test")
    assert "não encontrado" in capsys.readouterr().out
    app.get_senha(key, "STATUS")
    assert "reservada" in capsys.readouterr().out


def test_token_de_autenticacao_adulterado_bloqueia_acesso(setup_vault):
    app, _, _ = setup_vault
    caminho = Path(app.COFRE_ARQUIVO)
    dados = json.loads(caminho.read_text())
    dados["STATUS"] = "token-invalido"
    caminho.write_text(json.dumps(dados))
    assert app.autenticar() is None


def test_autenticacao_sem_arquivo_retorna_erro_controlado(setup_vault):
    app, _, _ = setup_vault
    Path(app.COFRE_ARQUIVO).unlink()
    assert app.autenticar() is None


def test_consulta_em_json_malformado_nao_crasha(setup_vault):
    app, key, _ = setup_vault
    Path(app.COFRE_ARQUIVO).write_text('{"STATUS": ', encoding="utf-8")
    assert app.get_senha(key, "site.test") is None


def test_fluxo_do_menu_criar_consultar_e_sair(setup_vault, monkeypatch, capsys):
    app, _, master = setup_vault
    inputs = iter(["1", "site.test", "login-teste", "2", "site.test", "y", "3"])
    monkeypatch.setattr("builtins.input", lambda *a, **kw: next(inputs))
    monkeypatch.setattr(app.getpass, "getpass", lambda *a, **kw: master)
    app.menu()
    saida = capsys.readouterr().out
    assert "Senha adicionada" in saida
    assert "Login: login-teste" in saida
    assert "Programa Encerrado" in saida


def test_opcao_invalida_menu_nao_interrompe_execucao(setup_vault, monkeypatch, capsys):
    app, _, master = setup_vault
    entradas = iter(["0", "3"])
    monkeypatch.setattr("builtins.input", lambda *a, **kw: next(entradas))
    monkeypatch.setattr(app.getpass, "getpass", lambda *a, **kw: master)
    app.menu()
    assert "Opção inválida" in capsys.readouterr().out