# S-01–S-04 implementation record

**Reference:** public `main.py` from `joao-vicc-lopes/gerenciador-senhas-seguro`; local fix package prepared October 28, 2026. The user's three pre-test JSON baselines indicate Git revision `4e5e7e1` and use synthetic data.

| ID | Severity hypothesis | Initial reproducible observation | Code-level response | Verification |
|---|---|---|---|---|
| S-01 | High — confidentiality | Plaintext JSON exposed the site key and `login` | Fernet encrypts all credential records into `__VAULT_DATA__`; versioned envelope | `test_metadados_nao_ficam_legiveis_no_arquivo`, legacy migration test |
| S-02 | High — password selection | Creating vault with `""` was possible | Validate master password before salt creation, reject whitespace-only | `test_criacao_rejeita_senha_mestra_vazia` |
| S-03 | Critical — data integrity/availability | A partial `json.dump` truncated an existing healthy cofre | Owner-only temp file, JSON serialization, `flush`, `fsync`, `os.replace`, cleanup | `test_erro_na_gravacao_nao_destroi_cofre`, failed replace test |
| S-04 | Medium — error handling | Valid JSON missing `STATUS` raised `KeyError` | Validate `STATUS` and envelope structure; safe error and `None` | `test_json_sem_status_falha_de_modo_controlado`, malformed version test |

The severity labels are practical engineering priorities, not standardized vulnerability scores or results of an independent security audit.

## Traceability and testing

- Public pre-change code was recreated and executed with the original test suite: **18 passed, 4 expected failures**.
- Modified code was executed against the expanded test suite: **28 passed**, with 0 failures and 0 remaining XFAIL; line coverage **95% of 182 executable statements**.
- Existing tests that depended on plaintext JSON were updated with documented rationale, not silently removed.
- Added tests verify that legacy vaults remain readable, successful writes migrate without losing entries, corrupt legacy entries prevent migration, replace/dump failures preserve the previous vault, and newly created files have `0600` permissions on Linux.

## Trade-offs and next steps

- **Security:** confidentiality of site/login metadata is improved once files are v2. Neither this change nor high code coverage constitutes a security audit.
- **Reliability:** atomic file replacement reduces corruption risk when a write operation fails. It does not solve every potential crash, filesystem or multi-process concurrency scenario.
- **Performance:** repeated whole-vault encryptions and fsync can be slower; optimize only after measuring with the same benchmark protocol on the same machine.
- **Structure:** kept a single-file public API to focus on the four correctness fixes. Modularization remains the next workstream.
- **UI:** no interface work in this iteration.

## Personal AI contribution log (fill in with your actual actions)

| Prompt / research question | AI recommendation | Decision made by developer | Validation / outcome |
|---|---|---|---|
| *Record real prompt 1* | *Record actual advice* | *Record your rationale* | *Test/commit link* |
| *Record real prompt 2* | *Record actual advice* | *Record your rationale* | *Test/commit link* |

Do not invent AI mistakes or personal decisions for the interview. The record above contains verifiable technical changes only.