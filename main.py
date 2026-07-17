import json
from json import JSONDecodeError
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass


COFRE_ARQUIVO = "cofre.json"
SALT_ARQUIVO = "salt.key"

def get_chave(senha_mestra, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length = 32,
        salt=salt,
        iterations=480000,
    )

    return base64.urlsafe_b64encode(kdf.derive(senha_mestra.encode('utf-8')))

#configurando novo cofre, rodamos essa função apenas na primeira vez que o programa for aberto
def novo_cofre(): 
    salt_existe = os.path.exists(SALT_ARQUIVO)
    cofre_existe = os.path.exists(COFRE_ARQUIVO)

    if salt_existe and cofre_existe:
        return
    
    elif salt_existe or cofre_existe:
        print("[!] ATENÇÃO: Arquivos corrompidos detectados (Salt ou Cofre faltando).")
        print("Por segurança, o programa não irá sobrescrever os dados.")
        exit()

    with open(SALT_ARQUIVO, "wb") as arquivo: #criamos o Salt
        salt = os.urandom(16)
        arquivo.write(salt)

    while True: #pedimos uma senha mestra com confirmação
        senha = getpass.getpass("Digite uma nova Senha Mestra: ")
        confirmacao = getpass.getpass("Confirme a Senha Mestra: ")
        if senha == confirmacao:
            break
        print("[X] Senhas não coincidem. Tente novamente. \n")

    chave = get_chave(senha, salt) #derivamos a chave do Fernet
    motor = Fernet(chave)

    palavra = "AUTENTICADO"
    palavra = motor.encrypt(palavra.encode('utf-8')).decode('utf-8')

    with open(COFRE_ARQUIVO, "w") as arquivo:
        dados = {"STATUS": palavra}
        json.dump(dados, arquivo, indent=4)
    
    print("[+] Cofre configurado com Sucesso. Guarde sua senha mestra com segurança.\n")

#autenticamos a senha
def autenticar(): 
    try:
        with open(SALT_ARQUIVO, "rb") as arquivo: #pegamos nosso salt
            salt = arquivo.read()

        with open(COFRE_ARQUIVO, "r") as arquivo: #pegamos nossa palavra no cofre
            try:
                dados = json.load(arquivo)
                palavra_cripto = dados["STATUS"]
            except JSONDecodeError:
                print("[X] ERRO CRÍTICO: O arquivo cofre.json está corrompido ou foi adulterado incorretamente!\n")
                return None

    except FileNotFoundError:
        print("[X] Cofre não encontrado! Configure o sistema primeiro.\n")
        return None

    senha = getpass.getpass("Digite sua Senha Mestra: ") #pedimos a senha para gerar a chave Fernet
    chave = get_chave(senha, salt)
    motor = Fernet(chave)

    try: #tentamos descriptografar nossa palavra usando a senha. Caso retorne InvalidToken, a senha está incorreta
        palavra = motor.decrypt(palavra_cripto.encode('utf-8'))
        return chave
    
    except InvalidToken:
        print("[X] Senha Incorreta!\n")
        return None
    
#adicionar uma nova senha ao sistema
def add_senha(chave, site, login, senha):
    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return

    motor = Fernet(chave)
    senha_site = motor.encrypt(senha.encode()).decode('utf-8')
    
    with open(COFRE_ARQUIVO, "r") as arquivo:
        try:
            dados = json.load(arquivo)
            dados[site] = {"login": login, "senha": senha_site}
        except JSONDecodeError:
            print("[X] ERRO CRÍTICO: O arquivo cofre.json está corrompido ou foi adulterado incorretamente!\n")
            return None

    with open(COFRE_ARQUIVO, "w") as arquivo:
        json.dump(dados, arquivo, indent=4)

    print("[+] Senha adicionada com sucesso!\n")

#recuperamos a senha do cofre
def get_senha(chave, site):
    try:
        with open(COFRE_ARQUIVO, "r") as arquivo:
            dados = json.load(arquivo)
    
    except JSONDecodeError:
        print("[X] ERRO CRÍTICO: O arquivo cofre.json está corrompido ou foi adulterado incorretamente!\n")
        return None

    if site == "STATUS":
        print("[X] Operação Inválida! Palavra reservada do sistema.")
        return
    
    if site in dados:
        motor = Fernet(chave)

        try:
            senha = motor.decrypt(dados[site]["senha"].encode('utf-8')).decode('utf-8')
            login = dados[site]["login"]
            print(f"Login: {login} | Senha: {senha}\n")
        except InvalidToken:
            print(f"[X]ERRO CRÍTICO! Senha do site '{site}' foi adulterada ou corrompida.")
    
    else:
        print(f"[X] Site '{site}' não encontrado!\n")



def menu():
    novo_cofre()
    chave = autenticar()
    if chave is None:
        return
    
    while True:
        print("\n-- Gerenciador de Senhas --")
        print("1. Adicionar nova senha")
        print("2. Ver senha")
        print("3. sair\n")

        opcao = input("\n")

        if opcao == '1':
            site = input("Digite o nome do site: ")
            login = input("\nDigite o login: ")
            senha = getpass.getpass("\nDigite sua senha: ")

            add_senha(chave, site, login, senha)
        
        elif opcao == '2':
            site = input("Digite o nome do site: ")
            get_senha(chave, site)

        elif opcao == '3':
            print("-- Programa Encerrado --\n")
            break

        else:
            print("[X] Opção inválida!\n")


if __name__ == "__main__":
    menu()