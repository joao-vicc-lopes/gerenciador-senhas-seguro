# Testing the v3 hardening release

- Existing security target tests (`S-01` through `S-04`) are now normal tests, **not `xfail`**.
- Run `python -m pytest --cov=main --cov=vault --cov-report=term-missing` from the repository root.
- Run `python scripts/profile_add.py --entries 100 --samples 7` for synthetic per-stage addition profiling.
- Run `python scripts/measure.py --label post-v3 --output results/post-v3.json` to repeat the public-API benchmark.
- Do not copy personal `cofre.json`, `salt.key`, or the `.bak` file into source control or testing artifacts.
- `tests/test_hardening.py` includes two concurrently running writers using Python multiprocessing `spawn`.
- `tests/test_regression.py` was updated because the display is now opt-in and the opaque record format replaces v2.

The original performance baseline was collected on Linux/Python 3.12.3; local validation here used Linux/Python 3.13.5. Performance results across these machines are not directly comparable.

See `ARCHITECTURE.md` for recovery semantics, security limitations, and migration behavior.