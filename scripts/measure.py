#!/usr/bin/env python3
"""Benchmark sem rede nem credenciais reais. Salva resultados em JSON.

Uso: python scripts/measure.py --label pre --output results/pre.json
"""
import argparse
import ast
import contextlib
import datetime as dt
import importlib.util
import json
import math
import io
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from cryptography.fernet import Fernet
import cryptography

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
MASTER = "chave-mestra-de-teste-123!-NAO-REAL"
REPS = 11


def load_app():
    path = ROOT / "main.py"
    spec = importlib.util.spec_from_file_location("vault_measure_target", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def timing(fn, repeats=REPS, warmups=2):
    # Dados de teste sintéticos. Coleta realizada no mesmo processo.
    for _ in range(warmups):
        fn()
    values = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        fn()
        values.append((time.perf_counter_ns() - t0) / 1_000_000)
    v = sorted(values)
    return {"median_ms": round(statistics.median(values), 3),
            "p95_ms": round(v[math.ceil(0.95 * len(v)) - 1], 3),
            "samples_ms": [round(x, 3) for x in values]}


def complexity(func):
    # Complexidade aproximada, NÃO McCabe oficial.
    decisions = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                 ast.IfExp, ast.Assert, ast.ListComp, ast.SetComp, ast.DictComp,
                 ast.GeneratorExp)
    score = 1
    for node in ast.walk(func):
        if isinstance(node, decisions):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += max(0, len(node.values) - 1)
    return score


def code_metrics():
    files = []
    for p in ROOT.rglob("*.py"):
        if any(part in {"tests", "scripts", ".venv", "venv", "__pycache__"} for part in p.relative_to(ROOT).parts):
            continue
        files.append(p)
    funcs = []
    effective = 0
    for p in files:
        source = p.read_text(encoding="utf-8")
        effective += sum(bool(l.strip()) and not l.lstrip().startswith("#") for l in source.splitlines())
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.append({"name": f"{p.relative_to(ROOT)}:{node.name}",
                              "lines": node.end_lineno - node.lineno + 1,
                              "complexity_approx": complexity(node)})
    return {"python_source_files": len(files),
            "source_loc_nonblank": effective,
            "functions": len(funcs),
            "largest_function_lines": max((f["lines"] for f in funcs), default=0),
            "largest_function_complexity_approx": max((f["complexity_approx"] for f in funcs), default=0),
            "details": funcs}


def kdf_iterations():
    primary = ROOT / "vault" / "crypto.py"
    if primary.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("vault_crypto_metrics", primary)
        tree = ast.parse(primary.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ROUNDS" for t in node.targets) and isinstance(node.value, ast.Constant):
                return node.value.value
    tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "PBKDF2HMAC":
            for kw in node.keywords:
                if kw.arg == "iterations" and isinstance(kw.value, ast.Constant):
                    return kw.value.value
    return None


def git_revision():
    p = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                       text=True, capture_output=True, check=False)
    return p.stdout.strip() if p.returncode == 0 else "unknown"


def run():
    """Protocol v2: seed each version through its PUBLIC API.

    Unlike the original benchmark, never write v1-format fixtures directly:
    doing so would benchmark a migration on the updated application rather
    than a normal v2 add. Run this same v2 script on both git revisions.
    """
    app = load_app()
    fixed_salt = b"s" * 16  # deterministic only for the standalone KDF test
    original_salt, original_vault = app.SALT_ARQUIVO, app.COFRE_ARQUIVO
    original_prompt = app.getpass.getpass
    collected = {}
    with tempfile.TemporaryDirectory(prefix="cofre_benchmark_") as tmp:
        path = Path(tmp) / "cofre.json"
        salt_path = Path(tmp) / "salt.key"
        app.COFRE_ARQUIVO = str(path)
        app.SALT_ARQUIVO = str(salt_path)
        app.getpass.getpass = lambda *a, **kw: MASTER

        def seed(n):
            path.unlink(missing_ok=True)
            salt_path.unlink(missing_ok=True)
            app.novo_cofre()
            if not path.exists():
                raise RuntimeError("Vault creation failed during benchmark setup")
            key = app.get_chave(MASTER, salt_path.read_bytes())
            for i in range(n):
                app.add_senha(key, f"site-{i}.test", f"fake{i}@test.invalid", "fake-password")
            return key, path.read_bytes()

        try:
            with contextlib.redirect_stdout(io.StringIO()):
                collected["kdf"] = timing(lambda: app.get_chave(MASTER, fixed_salt),
                                           repeats=7, warmups=1)
                for n in (0, 10, 100, 500):
                    key, starting_bytes = seed(n)
                    # Pre-test restoration is not part of the measured operation.
                    def add_once():
                        path.write_bytes(starting_bytes)
                        t0 = time.perf_counter_ns()
                        app.add_senha(key, "new-site.test", "fake@test.invalid", "fake-password")
                        return (time.perf_counter_ns() - t0) / 1_000_000

                    for _ in range(2):
                        add_once()
                    vals = [add_once() for _ in range(REPS)]
                    sorted_vals = sorted(vals)
                    collected[f"add_{n}"] = {
                        "median_ms": round(statistics.median(vals), 3),
                        "p95_ms": round(sorted_vals[math.ceil(.95 * len(vals)) - 1], 3),
                        "samples_ms": [round(x, 3) for x in vals],
                    }
                    path.write_bytes(starting_bytes)
                    lookup = "site-0.test" if n else "absent.test"
                    collected[f"get_{n}"] = timing(lambda: app.get_senha(key, lookup))

                # Authentication scenario uses a newly created empty vault.
                seed(0)
                collected["authenticate"] = timing(app.autenticar, repeats=7, warmups=1)
        finally:
            app.SALT_ARQUIVO, app.COFRE_ARQUIVO = original_salt, original_vault
            app.getpass.getpass = original_prompt
    return collected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True, help="pre | iteracao-01 | pos")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = {"label": args.label,
              "utc_time": dt.datetime.now(dt.timezone.utc).isoformat(),
              "git_revision": git_revision(),
              "environment": {"python": sys.version.split()[0],
                              "system": platform.platform(),
                              "machine": platform.machine(),
                              "cryptography": cryptography.__version__},
              "config": {"reps": REPS, "synthetic_data": True,
                         "protocol": "native-public-api-v2",
                         "kdf_iterations_literal": kdf_iterations()},
              "performance": run(),
              "organization": code_metrics()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Medições salvas em: {args.output}")
    for name, data in result["performance"].items():
        print(f"  {name:>16}  mediana={data['median_ms']:.3f}ms  p95={data['p95_ms']:.3f}ms")
    print("  revisão:", result["git_revision"], "| kdf rounds:", result["config"]["kdf_iterations_literal"])


if __name__ == "__main__":
    main()