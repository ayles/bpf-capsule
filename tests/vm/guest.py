#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Run one staged regression profile inside a disposable NixOS guest."""

import json
from pathlib import Path
import resource
import subprocess
import sys


SHARED = Path("/tmp/shared")


def main() -> int:
    resource.setrlimit(resource.RLIMIT_MEMLOCK,
                       (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    arguments = json.loads((SHARED / "config.json").read_text())
    command = [
        sys.executable,
        str(SHARED / "benchmarks/regression.py"),
        *arguments,
    ]
    try:
        status = subprocess.run(command, check=False).returncode
    except OSError as error:
        print(f"cannot start regression: {error}", file=sys.stderr)
        status = 127
    (SHARED / "status").write_text(f"{status}\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
