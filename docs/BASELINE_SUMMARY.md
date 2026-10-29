# Three original pre-test measurements — raw median summary

All data below are from the user’s baseline JSON files. These are NOT post-fix results.

| Operation | pre | pre-2 | pre-3 | Median of run medians |
|---|---:|---:|---:|---:|
| kdf | 251.063 ms | 260.152 ms | 248.284 ms | 251.063 ms |
| authenticate | 251.283 ms | 262.636 ms | 248.008 ms | 251.283 ms |
| add_0 | 0.342 ms | 0.417 ms | 0.379 ms | 0.379 ms |
| get_0 | 0.031 ms | 0.033 ms | 0.031 ms | 0.031 ms |
| add_10 | 0.424 ms | 0.414 ms | 0.425 ms | 0.424 ms |
| get_10 | 0.085 ms | 0.086 ms | 0.085 ms | 0.085 ms |
| add_100 | 0.837 ms | 0.817 ms | 0.877 ms | 0.837 ms |
| get_100 | 0.154 ms | 0.162 ms | 0.149 ms | 0.154 ms |
| add_500 | 3.215 ms | 3.218 ms | 3.034 ms | 3.215 ms |
| get_500 | 0.501 ms | 0.552 ms | 0.500 ms | 0.501 ms |

- All report Git revision `4e5e7e1`, Python `3.12.3`, cryptography `50.0.2`, and 480,000 PBKDF2 iterations.
- `pre-2.json` contains an incorrect internal `label` of `pre-3`. Source JSONs are unmodified.
- These timings were collected with the **original legacy-fixture benchmark protocol**. The updated script uses a new native-API protocol. Do not compare the two protocols directly.
- No artificial improvements are claimed. Measure both code versions with the updated script on the same machine.