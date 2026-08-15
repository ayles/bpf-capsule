#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Require every installed artifact consumed by the VM matrix."""

import importlib.util
from pathlib import Path
import sys


SOURCE = Path(__file__).resolve().parents[2] / "benchmarks/matrix.py"
SPEC = importlib.util.spec_from_file_location("bpf_capsule_matrix", SOURCE)
assert SPEC and SPEC.loader
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def main() -> int:
    missing = []
    for package in map(Path, sys.argv[1:]):
        root = package / "libexec/bpf-capsule"
        missing.extend(str(root / relative) for relative in matrix.ARTIFACTS
                       if not (root / relative).is_file())
    if missing:
        print("matrix artifact contract is incomplete:", file=sys.stderr)
        print("\n".join(missing), file=sys.stderr)
        return 1
    print("MATRIX-ARTIFACTS-PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
