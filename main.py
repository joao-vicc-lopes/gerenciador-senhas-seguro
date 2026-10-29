"""Compatibility API and local CLI for the secure password vault.

Core functionality lives under vault/; this facade keeps educational scripts
and older tests importing main.py working.
"""
import getpass
import json  # retained for existing test monkeypatches
import os    # retained for existing test monkeypatches
import sys
from cryptography.fernet import Fernet, InvalidToken
from vault.crypto import VaultCorruptedError, derive_key
from vault.service import VaultService
from vault import storage

COFRE_ARQUIVO = "cofre.json"
SALT_ARQUIVO = "salt.key"


def _service(trace=None):
    return VaultService(COFRE_ARQUIVO, SALT_ARQUIVO, trace=trace)


def get_chave(senha_mestra, salt):
    return derive_key(senha_mestra, salt)


def novo_cofre():
    if os.path.exists(COFRE_ARQUIVO) and os.path.exists(SALT_ARQUIVO):
        return
    if os.path.exists(COFRE_ARQUIVO) or os.path.exists(SALT_ARQUIVO):
        print("[!] ATENÇÃO: Arquivos corrompidos detectados (Salt ou Cofre faltando).")
        print("Por segurança, o programa não irá sobrescrever os dados.")
        raise SystemExit(1)
    while True:
        password = getpass.getpass("Digite uma nova Senha Mestra: ")
        confirmation = getpass.getpass("Confirme a Senha Mestra: ")
        if password != confirmation:
            print("[X] Senhas não coincidem. Tente novamente.\n")
        elif not password.strip():
            print("[X] A senha mestra não pode estar vazia. Tente novamente.\n")
        else:
            try:
                created = _service().create(password)
            except ValueError as exc:
                if not isinstance(exc, VaultCorruptedError):
                    print(f"[X] Senha mestra fraca: {exc}. Tente novamente.\n")
                    continue
                print("[X] Erro ao configurar cofre: dados inválidos ou ausentes.")
                return None
            except OSError:
                print("[X] Erro ao criar o cofre; nenhum cofre anterior foi sobrescrito.")
                return None
            if created:
                print("[+] Cofre configurado com Sucesso. Guarde sua senha mestra com segurança.\n")
            return None


def autenticar():
    try:
        return _service().authenticate(getpass.getpass("Digite sua Senha Mestra: "))
    except (OSError, ValueError, UnicodeError, InvalidToken):
        print("[X] Senha incorreta ou arquivos do cofre adulterados/corrompidos.\n")
        return None


def add_senha(chave, site, login, senha):
    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return None
    try:
        _service().add(chave, site, login, senha)
    except (OSError, ValueError, UnicodeError):
        print("[X] ERRO CRÍTICO: Falha ao ler ou gravar o cofre; dados anteriores preservados quando possível.\n")
        return None
    print("[+] Senha adicionada com sucesso!\n")


def get_senha(chave, site, reveal=False):
    """Password is hidden unless the caller explicitly opts into display."""
    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return None
    try:
        record = _service().get(chave, site)
    except (OSError, ValueError, UnicodeError):
        print("[X] ERRO CRÍTICO: O cofre foi adulterado ou está corrompido.\n")
        return None
    if record is None:
        print(f"[X] Site '{site}' não encontrado!\n")
        return None
    print(f"Login: {record['login']} | Senha: {record['senha'] if reveal else '[oculta]'}\n")
    return None


def recuperar_cofre():
    print("[!] Recuperação volta ao estado do backup anterior e pode perder alterações recentes.")
    if input("Confirmar recuperação? (digite RECOVER): ").strip() != "RECOVER":
        print("Operação cancelada.")
        return
    password = getpass.getpass("Digite a senha mestra do backup: ")
    try:
        _service().recover(password)
    except (OSError, ValueError, UnicodeError):
        print("[X] Backup inválido, senha incorreta ou falha de recuperação.\n")
        return
    print("[+] Backup restaurado. Reabra o programa e autentique novamente.")


def menu():
    if len(sys.argv) > 1 and sys.argv[1] == "--recover":
        recuperar_cofre()
        return
    novo_cofre()
    key = autenticar()
    if key is None:
        return
    while True:
        print("\n-- Gerenciador de Senhas --")
        print("1. Adicionar nova senha")
        print("2. Ver credencial")
        print("3. sair\n")
        option = input("\n")
        if option == "1":
            site = input("Digite o nome do site: ")
            login = input("\nDigite o login: ")
            secret = getpass.getpass("\nDigite sua senha: ")
            add_senha(key, site, login, secret)
        elif option == "2":
            site = input("Digite o nome do site: ")
            # Reveal only after explicit user consent; safer default for terminals.
            reveal = input("Mostrar a senha na tela? [y/N]: ").strip().lower() == "y"
            get_senha(key, site, reveal=reveal)
        elif option == "3":
            print("-- Programa Encerrado --\n")
            break
        else:
            print("[X] Opção inválida!\n")

if __name__ == "__main__":
    menu()