#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Differentially execute generated Csmith programs natively and in Capsule."""

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


COMMON_GENERATOR_FLAGS = (
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
    # Csmith enables arrays, pointers, structs, unions, bitfields, packed
    # structs, volatile objects, division, and safe math by default.
    "integer": ("--no-float",),
    "float": ("--float",),
    "int128": ("--no-float", "--int128", "--uint128"),
}


class CommandFailure(RuntimeError):
    def __init__(self, phase: str, command: list[str], result: subprocess.CompletedProcess[str]):
        super().__init__(f"{phase} failed with status {result.returncode}")
        self.phase = phase
        self.command = command
        self.result = result


def command_path(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"required command is not in PATH: {name}")
    return path


def run(
    phase: str,
    command: list[str],
    *,
    timeout: float | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        raise CommandFailure(phase, command, result)
    return result


def csmith_include_dir(csmith: str) -> Path:
    executable = Path(csmith).resolve()
    include = executable.parent.parent / "include"
    if not (include / "csmith.h").is_file():
        raise SystemExit(f"could not find csmith.h next to {executable}")
    return include


def preserve_failure(
    failure_root: Path,
    case: Path,
    metadata: dict[str, object],
    output: str,
) -> Path:
    destination = failure_root / f"{metadata['profile']}-seed-{metadata['seed']}"
    suffix = 1
    while destination.exists():
        destination = failure_root / f"{metadata['profile']}-seed-{metadata['seed']}-{suffix}"
        suffix += 1
    destination.mkdir(parents=True)
    shutil.copy2(case, destination / "case.c")
    (destination / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (destination / "output.log").write_text(output)
    return destination


def configure(
    cmake: str,
    source: Path,
    build: Path,
    case: Path,
    include: Path,
    target: str,
) -> None:
    run(
        "configure",
        [
            cmake,
            "-S",
            str(source),
            "-B",
            str(build),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DBPF_CAPSULE_TARGET_KERNEL={target}",
            "-DBPF_CAPSULE_BUILD_TESTS=ON",
            f"-DBPF_CAPSULE_CSMITH_CASE={case}",
            f"-DBPF_CAPSULE_CSMITH_INCLUDE_DIR={include}",
        ],
    )


def native_probe(
    clang: str,
    source: Path,
    work: Path,
    include: Path,
    timeout: float,
) -> str:
    binary = work / "native-probe"
    run(
        "native compile",
        [
            clang,
            "-O2",
            "-w",
            # Csmith's float profile hashes float objects through char*
            # parameters; clang >= 17 treats that as an error, not a warning,
            # so -w alone does not cover it.
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=int-conversion",
            f"-I{include}",
            f"-I{work}",
            f"-I{source / 'tests/csmith'}",
            str(source / "tests/csmith/native_probe.c"),
            "-o",
            str(binary),
        ],
    )
    return run("native run", [str(binary)], timeout=timeout).stdout.strip()


def capsule_probe(cmake: str, build: Path, timeout: float) -> str:
    run("capsule compile", [cmake, "--build", str(build), "--target", "csmith_test_host"])
    binary = build / "tests/csmith/csmith_test_host"
    command = [str(binary)]
    if os.geteuid() != 0:
        command = ["sudo", "--preserve-env", "--", *command]
    return run("capsule run", command, timeout=timeout).stdout


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=30, help="number of generated cases")
    parser.add_argument("--start-seed", type=int, default=1)
    parser.add_argument(
        "--profiles",
        default=",".join(PROFILES),
        help=f"comma-separated rotation drawn from: {', '.join(PROFILES)}",
    )
    parser.add_argument("--target", default="6.9", help="BPF target kernel version")
    parser.add_argument("--native-timeout", type=float, default=5.0)
    parser.add_argument("--capsule-timeout", type=float, default=120.0)
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
    if args.count <= 0:
        raise SystemExit("--count must be positive")
    profiles = args.profiles.split(",")
    unknown = [profile for profile in profiles if profile not in PROFILES]
    if unknown:
        raise SystemExit(f"unknown profiles: {', '.join(unknown)}")

    csmith = command_path("csmith")
    clang = command_path("clang")
    cmake = command_path("cmake")
    command_path("ninja")
    if os.geteuid() != 0:
        command_path("sudo")
    include = csmith_include_dir(csmith)
    args.failures.mkdir(parents=True, exist_ok=True)

    failures = 0
    discarded = 0
    with tempfile.TemporaryDirectory(prefix="bpf-capsule-csmith-") as temporary:
        work = Path(temporary)
        case = work / "csmith_case.c"
        build = work / "build"

        for index in range(args.count):
            seed = args.start_seed + index
            profile = profiles[index % len(profiles)]
            generator = [
                csmith,
                "--seed",
                str(seed),
                *COMMON_GENERATOR_FLAGS,
                *PROFILES[profile],
                "--output",
                str(case),
            ]
            started = time.monotonic()
            metadata: dict[str, object] = {
                "seed": seed,
                "profile": profile,
                "target": args.target,
                "generator": generator,
            }
            output = ""
            try:
                run("generate", generator)
                checksum = native_probe(clang, args.source, work, include, args.native_timeout)
            except subprocess.TimeoutExpired:
                discarded += 1
                print(f"DISCARD {profile} seed={seed}: native timeout", flush=True)
                continue
            except CommandFailure as error:
                metadata.update(phase=error.phase, status=error.result.returncode)
                output = error.result.stdout
                destination = preserve_failure(args.failures, case, metadata, output)
                failures += 1
                print(f"FAIL {profile} seed={seed}: {error.phase}; saved {destination}", flush=True)
                continue

            try:
                configure(cmake, args.source, build, case, include, args.target)
                output = capsule_probe(cmake, build, args.capsule_timeout)
                if "CSMITH-PASS" not in output:
                    result = subprocess.CompletedProcess([], 1, output)
                    raise CommandFailure("capsule differential", [], result)
                elapsed = time.monotonic() - started
                print(
                    f"PASS {profile} seed={seed} native={checksum} elapsed={elapsed:.1f}s",
                    flush=True,
                )
            except subprocess.TimeoutExpired as error:
                metadata.update(phase="capsule timeout", timeout=error.timeout)
                destination = preserve_failure(args.failures, case, metadata, output)
                failures += 1
                print(f"FAIL {profile} seed={seed}: capsule timeout; saved {destination}", flush=True)
            except CommandFailure as error:
                metadata.update(phase=error.phase, status=error.result.returncode)
                output += error.result.stdout
                destination = preserve_failure(args.failures, case, metadata, output)
                failures += 1
                print(f"FAIL {profile} seed={seed}: {error.phase}; saved {destination}", flush=True)

    passed = args.count - failures - discarded
    print(f"csmith: {passed} passed, {discarded} discarded, {failures} failed")
    if not passed and not failures:
        print("FAIL: every generated case was discarded; no differential test ran", file=sys.stderr)
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
