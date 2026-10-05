#!/usr/bin/env python3
"""Eighth-round review: show that this tree runs the same code as release 2.9.0, which produced every
simulated result (commit 9af3100). Every run record carries the code hash of the files that can change a
result (otp_guard.evaluation.provenance.source_files: the package source and the configuration, plus the
driving script). Release 2.9.1 corrected a module note in feedback.py, which changes that byte-level
hash, so this script compares each file with its 2.9.0 version instead: configuration files and driving
scripts byte for byte, Python source by its syntax tree with docstrings removed (comments are not in the
tree). Writes results/code_identity.md and exits non-zero if any file differs in code.

    python3 scripts/check_code_identity.py [--base 9af3100]"""
import argparse
import ast
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from otp_guard.evaluation.provenance import source_files      # noqa: E402

DRIVERS = ["scripts/run_evaluation.py", "scripts/run_counter_study.py", "scripts/run_round5_analyses.py",
           "scripts/run_analysis.py", "scripts/run_scenarios.py"]


def strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return ast.dump(tree, include_attributes=False)


def at_base(base, rel):
    r = subprocess.run(["git", "show", f"{base}:{rel}"], cwd=ROOT, capture_output=True)
    return r.stdout if r.returncode == 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="9af3100")
    a = ap.parse_args()
    files = [f.relative_to(ROOT).as_posix() for f in source_files() if "__pycache__" not in f.parts] + DRIVERS
    rows, bad = [], 0
    for rel in files:
        now, old = (ROOT / rel).read_bytes() if (ROOT / rel).exists() else None, at_base(a.base, rel)
        if now == old:
            rows.append((rel, "identical bytes"))
            continue
        if now is None or old is None:
            rows.append((rel, "added" if old is None else "removed")); bad += 1
            continue
        if rel.endswith(".py") and strip_docstrings(ast.parse(now)) == strip_docstrings(ast.parse(old)):
            rows.append((rel, "same code; docstrings or comments differ"))
            continue
        rows.append((rel, "CODE DIFFERS")); bad += 1
    changed = [r for r in rows if r[1] != "identical bytes"]
    L = ["# Code identity with release 2.9.0 (eighth-round review)", "",
         f"Compared with commit {a.base}{' (release 2.9.0, which produced every simulated result)' if a.base == '9af3100' else ''} by `scripts/check_code_identity.py`: "
         f"{len(files)} files that can change a result (package source, configuration, driving scripts). "
         f"{len(rows) - len(changed)} are byte-identical; " +
         (f"{len(changed)} {'differs' if len(changed) == 1 else 'differ'}: " + "; ".join(f"`{r}` ({w})" for r, w in changed) if changed else "none differs") + ".", "",
         ("No file differs in code: this tree runs the code that produced the results." if not bad else
          f"{bad} file(s) differ in code: the results were not produced by this tree.")]
    (ROOT / "results" / "code_identity.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
