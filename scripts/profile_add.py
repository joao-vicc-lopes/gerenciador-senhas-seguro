"""Profile stages of add() with only synthetic data; no real vault touched."""
import argparse
from collections import defaultdict
from pathlib import Path
import statistics
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vault.service import VaultService


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--entries", type=int, default=100)
    parser.add_argument("--samples", type=int, default=7)
    a = parser.parse_args()
    timings = defaultdict(list)
    with tempfile.TemporaryDirectory(prefix="password_vault_profile_") as directory:
        service = VaultService(str(Path(directory)/"cofre.json"), str(Path(directory)/"salt.key"))
        service.create("synthetic-strong-master-phrase-2026")
        key = service.authenticate("synthetic-strong-master-phrase-2026")
        for i in range(a.entries):
            service.add(key, f"site-{i}.test", "fake-user", "fake-password-for-test")
        service.trace = lambda stage, ms: timings[stage].append(ms)
        for i in range(a.samples):
            start = time.perf_counter_ns()
            service.add(key, f"profile-{i}.test", "fake-user", "fake-password-for-test")
            timings["total"].append((time.perf_counter_ns()-start)/1e6)
    for stage, values in timings.items():
        print(f"{stage:>19}: median {statistics.median(values):.3f} ms (n={len(values)})")
    print("No secret material or real vault data were used.")

if __name__ == "__main__":
    main()