#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Differentially run generated Csmith programs natively and through Capsule."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


GENERATOR_FLAGS = (
    "--no-argc",
    "--concise",
    "--max-funcs",
    "12",
    "--max-block-depth",
    "6",
    "--max-block-size",
    "6",
    "--max-expr-complexity",
    "15",
    "--max-array-len-per-dim",
    "16",
    "--max-pointer-depth",
    "3",
    "--max-struct-fields",
    "16",
    "--max-union-fields",
    "8",
)
PROFILES = {
    "integer": ("--no-float",),
    "float": ("--float",),
    "int128": ("--no-float", "--int128", "--uint128"),
}


class Failure(RuntimeError):
    def __init__(self, phase: str, command: list[str], result: subprocess.CompletedProcess[str]):
        super().__init__(phase)
        self.phase = phase
        self.command = command
        self.result = result


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"required command is not in PATH: {name}")
    return path


def run(phase: str, command: list[str], timeout: float | None = None) -> str:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if result.returncode:
        raise Failure(phase, command, result)
    return result.stdout


def preserve(root: Path, case: Path, metadata: dict[str, object], output: str) -> Path:
    destination = root / f"{metadata['profile']}-seed-{metadata['seed']}"
    suffix = 1
    while destination.exists():
        destination = root / f"{metadata['profile']}-seed-{metadata['seed']}-{suffix}"
        suffix += 1
    destination.mkdir(parents=True)
    shutil.copy2(case, destination / "case.c")
    (destination / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (destination / "output.log").write_text(output)
    return destination


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--start-seed", type=int, default=1)
    parser.add_argument("--profiles", default=",".join(PROFILES))
    parser.add_argument("--target", default="6.9")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--failures",
        type=Path,
        default=Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "bpf-capsule/csmith-failures",
    )
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    return parser.parse_args()


def main() -> int:
    args = arguments()
    if args.count < 1:
        raise SystemExit("--count must be positive")
    profiles = args.profiles.split(",")
    unknown = [profile for profile in profiles if profile not in PROFILES]
    if unknown:
        raise SystemExit(f"unknown profiles: {', '.join(unknown)}")

    csmith = tool("csmith")
    cmake = tool("cmake")
    tool("ninja")
    sudo = None if os.geteuid() == 0 else tool("sudo")
    include = Path(csmith).resolve().parent.parent / "include"
    if not (include / "csmith.h").is_file():
        raise SystemExit(f"csmith.h is not installed beside {csmith}")
    args.failures.mkdir(parents=True, exist_ok=True)

    failures = 0
    with tempfile.TemporaryDirectory(prefix="bpf-capsule-csmith-") as temporary:
        work = Path(temporary)
        case = work / "case.c"
        build = work / "build"
        for index in range(args.count):
            seed = args.start_seed + index
            profile = profiles[index % len(profiles)]
            generator = [
                csmith,
                "--seed",
                str(seed),
                *GENERATOR_FLAGS,
                *PROFILES[profile],
                "--output",
                str(case),
            ]
            metadata: dict[str, object] = {
                "seed": seed,
                "profile": profile,
                "target": args.target,
                "generator": generator,
            }
            started = time.monotonic()
            output = ""
            try:
                output += run("generate", generator)
                output += run(
                    "configure",
                    [
                        cmake,
                        "-S",
                        str(args.source),
                        "-B",
                        str(build),
                        "-G",
                        "Ninja",
                        "-DCMAKE_BUILD_TYPE=Release",
                        f"-DBPF_CAPSULE_TARGET_KERNEL={args.target}",
                        "-DBPF_CAPSULE_BUILD_TESTS=ON",
                        "-DBPF_CAPSULE_BUILD_BENCHMARKS=OFF",
                        "-DBPF_CAPSULE_BUILD_LUA_TEST=OFF",
                        f"-DBPF_CAPSULE_CSMITH_CASE={case}",
                        f"-DBPF_CAPSULE_CSMITH_INCLUDE_DIR={include}",
                    ],
                )
                output += run(
                    "compile", [cmake, "--build", str(build), "--target", "csmith_test"]
                )
                test = str(build / "tests/csmith/csmith_test")
                command = [test, "--gtest_color=no"]
                if sudo:
                    command = [sudo, "--", *command]
                output += run("differential", command, timeout=args.timeout)
                print(
                    f"PASS {profile} seed={seed} elapsed={time.monotonic() - started:.1f}s",
                    flush=True,
                )
            except subprocess.TimeoutExpired as error:
                metadata.update(phase="differential", timeout=error.timeout)
                destination = preserve(args.failures, case, metadata, output)
                failures += 1
                print(f"FAIL {profile} seed={seed}: timeout; saved {destination}", flush=True)
            except Failure as error:
                metadata.update(phase=error.phase, command=error.command, status=error.result.returncode)
                output += error.result.stdout
                destination = preserve(args.failures, case, metadata, output)
                failures += 1
                print(f"FAIL {profile} seed={seed}: {error.phase}; saved {destination}", flush=True)

    print(f"csmith: {args.count - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
