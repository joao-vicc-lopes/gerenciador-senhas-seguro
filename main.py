"""Local password vault (educational project).

Version 2 encrypts all credential metadata, preserves access to legacy vaults,
and replaces vault files atomically. No data is sent to external services.
"""

import base64
import getpass
import json
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

COFRE_ARQUIVO = "cofre.json"
SALT_ARQUIVO = "salt.key"

_FORMAT_FIELD = "__FORMAT_VERSION__"
_DATA_FIELD = "__VAULT_DATA__"
_CURRENT_FORMAT = 2
_VERIFICATION_TEXT = b"AUTENTICADO"


class VaultCorruptedError(ValueError):
    """The vault format, authentication token or content is invalid."""


def get_chave(senha_mestra, salt):
    """Derive a Fernet-compatible key using the unchanged 480,000 rounds."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(senha_mestra.encode("utf-8")))


def _load_vault():
    """Read and validate only the unencrypted envelope (no silent recovery)."""
    with open(COFRE_ARQUIVO, "r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or not isinstance(data.get("STATUS"), str):
        raise VaultCorruptedError("Missing or invalid STATUS token")
    version = data.get(_FORMAT_FIELD)
    if version is not None:
        if (version != _CURRENT_FORMAT or
                set(data) != {"STATUS", _FORMAT_FIELD, _DATA_FIELD} or
                not isinstance(data.get(_DATA_FIELD), str)):
            raise VaultCorruptedError("Invalid or unsupported vault format")
    return data


def _read_credentials(data, engine):
    """Return decrypted {site: {login, senha}}, including from legacy vaults.

    Legacy records are validated and decrypted BEFORE any upgrade or rewrite.
    This prevents a damaged record from being silently discarded on migration.
    """
    try:
        if engine.decrypt(data["STATUS"].encode("utf-8")) != _VERIFICATION_TEXT:
            raise VaultCorruptedError("Invalid vault verification token")
        if data.get(_FORMAT_FIELD) == _CURRENT_FORMAT:
            raw = engine.decrypt(data[_DATA_FIELD].encode("utf-8"))
            credentials = json.loads(raw.decode("utf-8"))
        else:
            credentials = {}
            for site, record in data.items():
                if site == "STATUS":
                    continue
                if not isinstance(record, dict):
                    raise VaultCorruptedError("Invalid legacy record")
                credentials[site] = {
                    "login": record["login"],
                    "senha": engine.decrypt(record["senha"].encode("utf-8")).decode("utf-8"),
                }
        if not isinstance(credentials, dict):
            raise VaultCorruptedError("Invalid credential collection")
        for site, record in credentials.items():
            if (not isinstance(site, str) or not isinstance(record, dict) or
                    not isinstance(record.get("login"), str) or
                    not isinstance(record.get("senha"), str)):
                raise VaultCorruptedError("Invalid credential record")
        return credentials
    except (InvalidToken, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise VaultCorruptedError("Vault content is corrupt or cannot be decrypted") from error


def _pack_v2(verification_token, credentials, engine):
    clear = json.dumps(credentials, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return {
        "STATUS": verification_token,
        _FORMAT_FIELD: _CURRENT_FORMAT,
        _DATA_FIELD: engine.encrypt(clear).decode("ascii"),
    }


def _atomic_save(data):
    """Write, flush and fsync a same-directory temp file before os.replace.

    If serialization or replacement fails, the original vault remains intact.
    Temporary files are created with owner-only permissions (0600).
    """
    target = Path(COFRE_ARQUIVO)
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=target.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def novo_cofre():
    """Create a new v2 vault only when neither file exists."""
    salt_exists = os.path.exists(SALT_ARQUIVO)
    vault_exists = os.path.exists(COFRE_ARQUIVO)
    if salt_exists and vault_exists:
        return
    if salt_exists or vault_exists:
        print("[!] ATENÇÃO: Arquivos corrompidos detectados (Salt ou Cofre faltando).")
        print("Por segurança, o programa não irá sobrescrever os dados.")
        raise SystemExit(1)

    # S-02: collect a nonempty master password before creating either file.
    while True:
        password = getpass.getpass("Digite uma nova Senha Mestra: ")
        confirmation = getpass.getpass("Confirme a Senha Mestra: ")
        if not password.strip():
            print("[X] A senha mestra não pode estar vazia. Tente novamente.\n")
        elif password != confirmation:
            print("[X] Senhas não coincidem. Tente novamente.\n")
        else:
            break

    salt = os.urandom(16)
    engine = Fernet(get_chave(password, salt))
    token = engine.encrypt(_VERIFICATION_TEXT).decode("ascii")
    data = _pack_v2(token, {}, engine)
    salt_created = False
    try:
        fd = os.open(SALT_ARQUIVO, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        salt_created = True
        with os.fdopen(fd, "wb") as file:
            file.write(salt)
            file.flush()
            os.fsync(file.fileno())
        _atomic_save(data)
    except OSError:
        # Do not leave a stray salt that would prevent retrying creation.
        if salt_created and not os.path.exists(COFRE_ARQUIVO):
            os.unlink(SALT_ARQUIVO)
        print("[X] Erro ao criar o cofre; nenhum cofre anterior foi sobrescrito.")
        return None
    print("[+] Cofre configurado com Sucesso. Guarde sua senha mestra com segurança.\n")


def autenticar():
    try:
        with open(SALT_ARQUIVO, "rb") as file:
            salt = file.read()
        if len(salt) != 16:
            raise VaultCorruptedError("Invalid salt length")
        data = _load_vault()  # S-04: validate STATUS and payload structure.
    except FileNotFoundError:
        print("[X] Cofre não encontrado! Configure o sistema primeiro.\n")
        return None
    except (OSError, ValueError, UnicodeError):
        print("[X] ERRO CRÍTICO: Arquivos do cofre ausentes, inválidos ou corrompidos.\n")
        return None

    password = getpass.getpass("Digite sua Senha Mestra: ")
    key = get_chave(password, salt)
    try:
        _read_credentials(data, Fernet(key))
    except VaultCorruptedError:
        print("[X] Senha incorreta ou cofre adulterado/corrompido.\n")
        return None
    return key


def add_senha(chave, site, login, senha):
    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return None
    try:
        data = _load_vault()
        engine = Fernet(chave)
        credentials = _read_credentials(data, engine)
        credentials[site] = {"login": login, "senha": senha}
        # S-01: persist site name, login and password only inside the encrypted blob.
        updated = _pack_v2(data["STATUS"], credentials, engine)
        # S-03: never truncate the existing vault before successful serialization.
        _atomic_save(updated)
    except (OSError, ValueError, UnicodeError):
        print("[X] ERRO CRÍTICO: Falha ao ler ou gravar o cofre; dados anteriores preservados quando possível.\n")
        return None
    print("[+] Senha adicionada com sucesso!\n")


def get_senha(chave, site):
    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return None
    try:
        data = _load_vault()
        credentials = _read_credentials(data, Fernet(chave))
    except (OSError, ValueError, UnicodeError):
        print("[X] ERRO CRÍTICO: O cofre foi adulterado ou está corrompido.\n")
        return None
    if site not in credentials:
        print(f"[X] Site '{site}' não encontrado!\n")
        return None
    record = credentials[site]
    print(f"Login: {record['login']} | Senha: {record['senha']}\n")


def menu():
    novo_cofre()
    key = autenticar()
    if key is None:
        return
    while True:
        print("\n-- Gerenciador de Senhas --")
        print("1. Adicionar nova senha")
        print("2. Ver senha")
        print("3. sair\n")
        option = input("\n")
        if option == "1":
            site = input("Digite o nome do site: ")
            login = input("\nDigite o login: ")
            secret = getpass.getpass("\nDigite sua senha: ")
            add_senha(key, site, login, secret)
        elif option == "2":
            site = input("Digite o nome do site: ")
            get_senha(key, site)
        elif option == "3":
            print("-- Programa Encerrado --\n")
            break
        else:
            print("[X] Opção inválida!\n")
