# Password vault — modular security release (v3)

## Design

- `main.py`: compatibility facade and CLI; retains original function names.
- `vault/crypto.py`: PBKDF2-HMAC-SHA256 (480,000 iterations), Fernet, keyed HMAC-SHA256 site indexes, password policy.
- `vault/storage.py`: POSIX advisory locking (`fcntl.flock`), JSON persistence, private atomic writes, directory fsync, encrypted backup snapshots.
- `vault/service.py`: create, authenticate, add, lookup, v1/v2 migration, manual authenticated recovery.
- `scripts/profile_add.py`: independent synthetic-data latency profile of staged `add()` calls.

## Format v3

```json
{"STATUS":"<fernet-auth-token>","__FORMAT_VERSION__":3,"__RECORDS__":{"<hmac-sha256-of-site>":"<fernet-encrypted-json-record>"}}
```

The `__RECORDS__` index does not disclose plaintext site or login names. Individual records contain `site`, `login`, and `senha` inside the authenticated Fernet ciphertext. The site key is HMAC-SHA256 of a versioned domain separator and the original site string using the decoded Fernet key. The encrypted record contains its original site; lookup validates the HMAC index against that site to detect misplaced records.

Legacy v1 and v2 vaults remain readable. The first successful addition migrates the entire collection (after all legacy records have been validated). Older versions of the software **cannot read v3**. Back up `cofre.json` and `salt.key` together before trying the release.

## Operational guarantees and limitations

**Concurrent writers.** Each operation obtains a shared or exclusive advisory lock on the stable `<vault>.lock` file. Two cooperating application processes cannot lose updates via read-modify-write races. Noncooperating tools that write the vault directly can still corrupt it. This is POSIX/Linux-oriented and not a portable Windows solution.

**Backup and recovery.** Before each addition, the previous valid vault bytes and matching salt are written to `<vault>.bak` atomically, restricted to mode `0600`. The vault is subsequently replaced with a same-directory temporary file after file and directory synchronization. A backup represents **only the previous committed state**, not an archive of all revisions. It cannot protect against disk destruction, malicious deletion, or simultaneous loss of the vault and backup. Keep a separate private offline backup for disaster recovery. Restore is intentionally never automatic and always requires confirmation and the correct backup master password:

```bash
python main.py --recover
```

Recovery validates every backed-up record prior to replacement. Do not repeatedly attempt recovery with live credentials in a shared or untrusted environment. The salt and vault are two files and cannot be restored as a single filesystem-atomic transaction; interrupted recovery may require repeating the command.

**Master password policy.** New passwords must be at least 12 characters and must not contain a short local denylist of obvious patterns; this is not a breached-password database check. Old vault passwords remain valid, avoiding destructive forced upgrades.

**Password exposure.** Lookup hides the secret by default; the user must choose `y` before it is printed. Explicitly revealed passwords remain visible in terminal scrollback and may be captured by terminal logging. No clipboard integration or remote processing is enabled.

**Per-record processing.** Reads decrypt only the targeted record instead of decrypting every credential. Writes only encrypt the modified record. However, the v3 JSON file still requires **O(n) parsing/serialization and copying on writes**, plus backup fsync. Future growth would benefit from an encrypted SQLite or transactional key/value store. The `STATUS` token is an authentication check; damage to an unrequested record will not necessarily be detected until that record is accessed or a full audit is run.

## Validation and profiling

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest --cov=main --cov=vault --cov-report=term-missing
python scripts/profile_add.py --entries 100 --samples 7
python scripts/measure.py --label post-v3 --output results/post-v3.json
```

Tests use temporary directories, synthetic passwords, and multiprocessing writer checks. The benchmark protocol `native-public-api-v2` is the **methodology identifier**, not the vault format. Compare latencies against `baseline-v2.json` and `review-v2.json` run on the same machine using the same version of `measure.py`.

## Scope

This is still an educational password manager, **not a formally audited production-grade password manager**. It does not implement password breach databases, hardware-backed secrets, secure memory erasure, multi-version disaster recovery, or a cross-platform locking protocol.