#  Gerenciador de Senhas Local (Zero-Knowledge)

Um gerenciador de senhas local desenvolvido em Python com foco em **Criptografia Simétrica**, **Funções de Derivação de Chave (KDF)** e **Resiliência a Falhas**. 

Este projeto foi construído como prova de conceito para aplicar boas práticas de Cibersegurança no armazenamento local de credenciais, sem depender de nuvem ou chaves estáticas em disco. PARA FINS DE ESTUDO.

##  Arquitetura de Segurança

Diferente de scripts simples que salvam a chave de criptografia no próprio disco (o que configura má gestão de chaves), este projeto adota uma arquitetura *Zero-Knowledge* para a senha mestra:

* **Key Derivation Function (KDF):** Utiliza **PBKDF2HMAC** com algoritmo SHA-256, um salt aleatório de 16 bytes e 480.000 iterações. Isso torna ataques de força bruta computacionalmente inviáveis.
* **Criptografia Simétrica:** Utiliza a biblioteca `cryptography` (módulo **Fernet**), que implementa o padrão industrial **AES-128 no modo CBC**, com assinatura de autenticação para garantir integridade.
* **Verificação via Token (Canário):** A Senha Mestra **nunca é salva** no disco (nem mesmo em formato de hash). A autenticação é feita testando a chave derivada contra um token de verificação criptografado previamente no arquivo JSON.
* **Gerenciamento de Memória:** A chave mestre existe apenas na memória RAM enquanto o script está em execução, sendo destruída pelo Garbage Collector do Python ao encerrar o programa.

##  Modelagem de Ameaças & Resiliência (Tampering)

O código foi desenhado para não apenas proteger os dados, mas também para não quebrar de forma abrupta caso o ambiente seja hostil ou corrompido:

1. **Adulteração de Cofre (Tampering):** Se um atacante alterar manualmente o texto criptografado de alguma senha no `cofre.json`, o validador HMAC do Fernet detectará a quebra de integridade (`InvalidToken`) e alertará o usuário, mantendo o programa estável.
2. **Corrupção de Arquivos:** Operações de I/O são blindadas contra `JSONDecodeError`. Caso o arquivo seja parcialmente apagado, o sistema alerta sobre o estado de corrupção sem sobrescrever os dados.
3. **Ofuscação de Input:** Uso nativo de `getpass` para mascarar a digitação da Senha Mestra e das senhas salvas, prevenindo *Shoulder Surfing*.

##  Como Executar

**Pré-requisitos:**
* Python 3.x instalado.
* Instalar a biblioteca de criptografia:
  ```bash
  pip install cryptography