# Password Vault — AI-assisted Security Improvements (S-01 to S-04)

This is an educational **local** password manager. The application does not invoke external AI services or send credentials to a model. AI was used as a **development and code-review assistant**; the fixes are normal Python code and can be tested independently.

## Important: back up your vault first

Before replacing your local `main.py`, save **both** `cofre.json` and `salt.key` to a private, offline backup directory. **Do not upload either file to AI tools, GitHub, or this chat.** If a vault uses the original format, it is readable as-is, but **the first successful `add_senha` migrates it to version 2**. Old versions of the program cannot read the migrated format. To roll back, restore **both** backed-up files together.

The implementation was prepared against the publicly visible `main.py` in `joao-vicc-lopes/gerenciador-senhas-seguro`. The user's baseline JSON files identify revision `4e5e7e1`; local changes that are not in GitHub cannot be verified here. Review the diff before merging into a different checkout.

## What changed

| ID | Original problem | Fix and observable proof |
|---|---|---|
| **S-01** | Site names and usernames were stored in plaintext JSON keys/values | New vault envelope contains `STATUS`, `__FORMAT_VERSION__` and `__VAULT_DATA__`. The last field is a Fernet-authenticated encryption of **all** `{site: {login, senha}}` records. Automated test confirms sensitive strings are not present in the file. |
| **S-02** | Empty master passwords were accepted | Re-prompt if blank or whitespace-only, **before** any file is created. No arbitrary minimum password length was added, to preserve older test behavior. |
| **S-03** | `open('cofre.json', 'w')` could truncate a healthy vault before a failed write | Write a same-directory owner-only temporary file; `json.dump`, flush, `fsync`, then `os.replace`. On injected dump/replace exceptions, old bytes remain untouched and temp files are cleaned. |
| **S-04** | A syntactically valid JSON object missing `STATUS` crashed with `KeyError` | Validate JSON envelope and version; fail safely with an error and return `None` without overwriting the file. |

**Legacy compatibility:** version-1 vaults (top-level site records and `STATUS`) can still be read. Migration decrypts and verifies **all** existing credentials before writing the new encrypted representation, failing closed if any old entry is corrupt. Reads do not trigger migration. Newly created vaults are version 2 by default.

**Security limitations:** This is a learning project, not a production-reviewed password manager. In particular, master passwords/keys exist in Python process memory, displaying credentials in terminal output is a shoulder-surfing risk, password strength is not assessed beyond nonempty input, backups and multi-process locking are not implemented, and no full filesystem/power-failure threat assessment has been performed. `os.replace` provides atomic replacement on the same filesystem; stronger power-loss durability may require directory synchronization and platform-specific testing. Existing legacy vaults are not automatically protected from metadata disclosure until migrated.

## Install and test

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m pytest --cov=main --cov-report=term-missing
```

The suite uses only fake passwords and files in temporary directories. **Do not use real credentials as benchmarks or test data.**

Local validation performed here: **28 passed, 0 failed, 0 xfailed; 95% coverage of `main.py`** (Python 3.13.5, cryptography 46.0.4). This includes the four original S-01..S-04 tests, converted from XFAIL to genuine regression tests, and tests for legacy conversion, failure handling, and file permissions. The original public version reproduced **18 passed, 4 xfailed**. Your own original baseline showed **18 passed, 4 xfailed and 98% line coverage**; the raw coverage percentages are not directly comparable because the implementation has changed.

One original regression test was **deliberately adapted**: it used to edit `data['x.test']['senha']` in plaintext JSON. The new representation must not expose `x.test`, so that test now corrupts `__VAULT_DATA__` directly and asserts safe rejection. Additional tests validate migration of old records.

## Performance: compare compatible protocols only

Your three supplied baseline files (`pre.json`, `pre-2.json`, `pre-3.json`) are preserved under `results/baseline/`. All reference revision `4e5e7e1`, Linux, Python 3.12.3, cryptography 50.0.2, and 480,000 PBKDF2 iterations. **Note:** the `label` inside `pre-2.json` incorrectly says `pre-3`; the original file contents were preserved unchanged.

The previous `scripts/measure.py` generated **legacy-format** vaults by hand. Running it against version 2 would time **migration on every add**, which is not a fair benchmark of normal v2 operations. The revised benchmark uses each implementation's own public API to create and populate synthetic vaults (`config.protocol = "native-public-api-v2"`). This changes the methodology; **do not compare your three original `pre*.json` timings directly against output from this revised script**. The comparison tool prints a warning if protocols differ.

To compare performance fairly on your own computer, run the **same revised script** for both the original and updated versions, with the same Python environment, hardware, dependency versions and low background load. One approach, from the updated project's directory:

```bash
# Obtain a clean copy of the baseline main.py as it was actually measured.
mkdir -p /tmp/vault-baseline/scripts
# Only use this command if 4e5e7e1 really represents your pre-test main.py:
git show 4e5e7e1:main.py > /tmp/vault-baseline/main.py
cp scripts/measure.py /tmp/vault-baseline/scripts/measure.py

# Run both using the same interpreter and v2 measurement protocol:
python /tmp/vault-baseline/scripts/measure.py --label baseline-v2 --output results/baseline-v2.json
python scripts/measure.py --label post-v2 --output results/post-v2.json
python scripts/compare.py results/baseline-v2.json results/post-v2.json
```

The absolute timings obtained inside this assistant's container cannot be compared to those from your machine; different CPU and cryptography versions cause major differences. The security changes can also **increase** add latency because encryption and disk synchronization do extra work. That is an engineering trade-off, not an optimization failure. Preserve the 480,000 PBKDF2 iterations instead of reducing security to get attractive benchmarks.

For the interview, rerun each benchmark three times and summarize the *median of run medians*. Timing samples are small (11 repetitions per operation); p95 is merely the maximum observed sample for that size, not a robust tail-latency estimate.

## Suggested demo and AI contribution log

1. Show the *original* `18 PASS / 4 XFAIL` test output and the four failing security targets.
2. Show the actual conversations/prompts used to propose changes, how you evaluated the suggestions, and what you decided to implement. Avoid inventing claims about the AI or your personal decisions.
3. Run the updated suite: `28 PASS / 0 XFAIL`. Show a fake v2 JSON vault with no visible site names/login values.
4. Demonstrate the write-failure injection test preserving the original vault bytes.
5. Explain legacy migration, threat-model assumptions, known limitations, and performance trade-offs.

The aim of the AI Show Case is to explain **your engineering process and critical use of AI**, not to claim the app itself contains an AI model.