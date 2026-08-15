#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build and run the BPF Capsule correctness/performance regression suite.

See PERFORMANCE.md before interpreting or comparing timing measurements.
"""

from __future__ import annotations

import argparse
import atexit
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL_VERSION = re.compile(r"^[0-9]+\.[0-9]+$")


def kernel_version(value: str) -> str:
    if not KERNEL_VERSION.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a major.minor kernel version")
    major, minor = (int(part) for part in value.split("."))
    if minor >= 1000 or (major, minor) < (5, 15):
        raise argparse.ArgumentTypeError("kernel version must be 5.15 or newer")
    return value


@dataclass(frozen=True)
class Metric:
    name: str
    pattern: str
    groups: tuple[tuple[str, str], ...]


@dataclass
class Case:
    name: str
    command: list[str]
    marker: str
    objects: list[Path]
    metrics: list[Metric]
    environment: dict[str, str] = field(default_factory=dict)
    repeatability_dir: Path | None = None
    # A case whose host has a userspace continuation loop may promise a bound
    # and must then record a drain metric. None means no such loop or promise.
    max_drains: int | None = None
    verifier_probe: bool = False


# Examples report the kernel's own BPF runtime accounting (run_time_ns), and
# comparative examples pair it with the native thread's CPU time.
KERNEL_NS = Metric(
    "time",
    r"kernel execution: ([0-9]+) ns",
    (("kernel_ns", "ns"),),
)

KERNEL_NATIVE_NS = Metric(
    "time",
    r"kernel execution: ([0-9]+) ns, native execution: ([0-9]+) ns",
    (("kernel_ns", "ns"), ("native_ns", "ns")),
)

LLAMA_TIME = Metric(
    "time",
    r"kernel execution: ([0-9]+) ns, native execution: ([0-9]+) ns for ([0-9]+) tokens",
    (("kernel_ns", "ns"), ("native_ns", "ns"), ("tokens", "count")),
)

INVOCATIONS = Metric(
    "invocations",
    r"invocations: ([0-9]+) entr(?:y|ies) \+ ([0-9]+) drains",
    (("entries", "count"), ("drains", "count")),
)

CONTINUATION_DRAINS = Metric(
    "continuation-drains",
    r"continuation drains: ([0-9]+)",
    (("drains", "count"),),
)

LOAD = Metric(
    "load",
    r"verified\+loaded in ([0-9.]+) s",
    (("load_s", "s"),),
)

YIELD_COST = Metric(
    "yield_cost",
    r"yield benchmark: ([0-9]+) ns yielded, ([0-9]+) ns baseline, ([0-9]+) round trips, ([+-]?[0-9.]+) ns/round-trip delta",
    (("yielded_ns", "ns"), ("baseline_ns", "ns"), ("round_trips", "count"), ("round_trip_delta_ns", "ns")),
)

CONTEXT_INTEROP = Metric(
    "context_interop",
    r"context interop: borrowed=([0-9]+)ns \(([0-9]+)ns baseline, ([0-9]+)ns net\) yield=([0-9]+)ns "
    r"\(([0-9]+)ns baseline, ([0-9]+)ns net\) ratio=([0-9.]+)x",
    (
        ("borrowed_ns", "ns"),
        ("borrowed_baseline_ns", "ns"),
        ("borrowed_net_ns", "ns"),
        ("yield_ns", "ns"),
        ("yield_baseline_ns", "ns"),
        ("yield_net_ns", "ns"),
        ("yield_over_borrowed", "ratio"),
    ),
)

CANONICAL_METRICS = {
    "direct_jit_bytes",
    "drains",
    "entries",
    "jit_bytes",
    "measured_frames",
    "round_trips",
    "verifier_expansion",
    "verifier_processed_insns",
    "verifier_static_insns",
}


def executable(build: Path, relative: str) -> str:
    return str(build / relative)


def packaged_or_local(build: Path, packaged: str, local: Path) -> Path:
    """Use an installed-matrix artifact when present, else the local tree."""
    installed = build / packaged
    return installed if installed.is_file() else local


def optional_path(value: str) -> Path | None:
    return None if value == "none" else Path(value)


def make_cases(build: Path, args: argparse.Namespace) -> list[Case]:
    lua_runner = packaged_or_local(
        build, "examples/lua/lua", build / "examples/lua/lua/lua")
    lua_object = packaged_or_local(
        build, "examples/lua/lua_bpf.o",
        build / "examples/lua/lua/lua_bpf.o")
    lua_script = packaged_or_local(
        build, "examples/lua/script.lua",
        ROOT / "examples/lua/lua/script.lua")
    lua_xdp_object = packaged_or_local(
        build, "examples/lua-xdp/lua_xdp_bpf.o",
        build / "examples/lua/lua-xdp/lua_xdp_bpf.o")
    lua_xdp_policy = packaged_or_local(
        build, "examples/lua-xdp/packet_filter.lua",
        ROOT / "examples/lua/lua-xdp/packet_filter.lua")
    lua_xdp_observer = packaged_or_local(
        build, "examples/lua-xdp/packet_observer.lua",
        ROOT / "examples/lua/lua-xdp/packet_observer.lua")

    cases = [
        Case(
            "fib",
            [executable(build, "examples/fib/fib")],
            "fib(20) = 6765",
            [],
            [KERNEL_NS],
        ),
        Case(
            "compiler-core",
            [executable(build, "tests/integration/compiler_test_host"),
             executable(build, "tests/integration/compiler_test_bpf.o"),
             "core"],
            "COMPILER-CORE-PASS",
            [build / "tests/integration/compiler_test_bpf.o"],
            [INVOCATIONS, LOAD],
            # This object is intentionally built with BPF_CAPSULE_DRIVE_LEVEL=16.
            # Its hundreds of drains are the continuation stress test, not a
            # compactness result for a normally configured workload; the host
            # has its own finite wedged-program cap.
            max_drains=None,
        ),
        Case(
            "fiber-lifecycle",
            [executable(build, "tests/integration/compiler_test_host"),
             executable(build, "tests/integration/compiler_test_bpf.o"),
             "fibers"],
            "FIBER-PASS",
            [build / "tests/integration/compiler_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "atomic-concurrency",
            [executable(build, "tests/atomics/atomic_runtime_host"),
             executable(build, "tests/atomics/atomic_runtime_bpf.o")],
            "ATOMIC-RUNTIME-PASS",
            [build / "tests/atomics/atomic_runtime_bpf.o"],
            [LOAD],
        ),
        Case(
            "allocator-concurrency",
            [executable(build, "tests/integration/compiler_test_host"),
             executable(build, "tests/integration/compiler_test_bpf.o"),
             "allocator"],
            "ALLOCATOR-CONCURRENCY-PASS",
            [build / "tests/integration/compiler_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "physical-spill-concurrency",
            [executable(build, "tests/spill-concurrency/physical_spill_host"),
             executable(build,
                        "tests/spill-concurrency/physical_spill_bpf.o")],
            "PHYSICAL-SPILL-PASS",
            [build / "tests/spill-concurrency/physical_spill_bpf.o"],
            [LOAD],
        ),
        Case(
            "error-strings",
            [executable(build, "tests/errors/error_strings_host")],
            "ERROR-STRINGS-PASS",
            [],
            [],
        ),
        Case(
            "host-header-cpp",
            [executable(build, "tests/errors/host_header_cpp")],
            "HOST-HEADER-CPP-PASS",
            [],
            [],
        ),
        Case(
            "drive-contract",
            [executable(build, "tests/errors/drive_contract_host")],
            "DRIVE-CONTRACT-PASS",
            [],
            [],
        ),
        Case(
            "freestanding-libc",
            [executable(build, "tests/libc/libc_test_host"), executable(build, "tests/libc/libc_test_bpf.o")],
            "LIBC-PASS",
            [build / "tests/libc/libc_test_bpf.o"],
            [LOAD],
            max_drains=None,
        ),
        Case(
            "arena-initialization",
            [executable(build, "tests/arena-init/arena_init_host"),
             executable(build, "tests/arena-init/arena_init_bpf.o")],
            "ARENA-INIT-PASS",
            [build / "tests/arena-init/arena_init_bpf.o"],
            [LOAD],
        ),
        Case(
            "fiber-scale",
            [executable(build, "tests/fiber-scale/fiber_scale_host"),
             executable(build, "tests/fiber-scale/fiber_scale_bpf.o")],
            "FIBER-SCALE-PASS",
            [build / "tests/fiber-scale/fiber_scale_bpf.o"],
            [LOAD],
        ),
        Case(
            "memory-io",
            [executable(build, "tests/memory/memory_test_host"),
             executable(build, "tests/memory/memory_test_bpf.o")],
            "MEMORY-IO-PASS",
            [build / "tests/memory/memory_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "verifier-pointer",
            [executable(build, "tests/verifier-pointer/verifier_pointer_test_host"),
             executable(build, "tests/verifier-pointer/verifier_pointer_test_bpf.o")],
            "VERIFIER-POINTER-PASS",
            [build / "tests/verifier-pointer/verifier_pointer_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "context-interop",
            [
                executable(build, "tests/context-interop/context_interop_test_host"),
                executable(build, "tests/context-interop/context_interop_borrowed_bpf.o"),
                executable(build, "tests/context-interop/context_interop_yield_bpf.o"),
            ],
            "CONTEXT-INTEROP-PASS",
            [
                build / "tests/context-interop/context_interop_borrowed_bpf.o",
                build / "tests/context-interop/context_interop_yield_bpf.o",
            ],
            [CONTEXT_INTEROP, LOAD],
        ),
        Case(
            "voluntary-yield",
            [executable(build, "tests/yield/yield_test_host"),
             executable(build, "tests/yield/yield_test_bpf.o")],
            "YIELD-PASS",
            [build / "tests/yield/yield_test_bpf.o"],
            [YIELD_COST, LOAD],
        ),
        Case(
            "standalone-expression",
            [executable(build, "tests/integration/standalone_expr_host")],
            # The default input is a 64-deep parenthesis tower of ones: the
            # example prints the evaluated value alone on stdout.
            "65\n",
            [build / "tests/integration/standalone_expr_bpf.o"],
            [],
        ),
        Case(
            "nosuspend-contract",
            [executable(build, "tests/nosuspend/nosuspend_test_host"),
             executable(build, "tests/nosuspend/nosuspend_test_bpf.o")],
            "NOSUSPEND-PASS",
            [build / "tests/nosuspend/nosuspend_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "stackify-source-liveness",
            [executable(build, "tests/rehash/rehash_test_host"),
             executable(build, "tests/rehash/rehash_test_bpf.o")],
            "REHASH-PASS",
            [build / "tests/rehash/rehash_test_bpf.o"],
            [LOAD],
        ),
        Case(
            "zlib",
            [executable(build, "examples/zlib/zlib")],
            "inflate time over",
            [build / "examples/zlib/zlib_bpf_lib.o"],
            [
                Metric(
                    "time",
                    r"inflate time over [0-9]+ runs: kernel ([0-9.]+) ms, "
                    r"matched scalar ([0-9.]+) ms \(([0-9.]+)x\), "
                    r"system zlib ([0-9.]+) ms",
                    (("kernel_ms", "ms"), ("native_ms", "ms"),
                     ("slowdown", "ratio"), ("system_zlib_ms", "ms")),
                ),
                CONTINUATION_DRAINS,
            ],
            max_drains=0,
            verifier_probe=True,
        ),
        Case(
            "wasm3-zlib",
            [executable(build, "examples/wasm3/wasm3")],
            "stock zlib Wasm: 65536 -> ",
            [build / "examples/wasm3/wasm3_bpf_lib.o"],
            [
                Metric(
                    "time",
                    r"kernel wasm3 execution: ([0-9]+) ns; native wasm3: ([0-9]+) ns; native zlib: ([0-9]+) ns",
                    (("kernel_ns", "ns"), ("native_ns", "ns"),
                     ("native_zlib_ns", "ns")),
                ),
                CONTINUATION_DRAINS,
            ],
            max_drains=0,
            verifier_probe=True,
        ),
        Case(
            "lua",
            [str(lua_runner), str(lua_script)],
            "Lua checksum\t16898\ttrue\t0",
            [lua_object],
            [KERNEL_NS, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ),
        Case(
            "lua-xdp",
            [executable(build, "tests/lua-xdp/lua_xdp_test_host"),
             str(lua_xdp_policy), str(lua_xdp_observer)],
            "LUA-XDP-PASS",
            [lua_xdp_object],
            [LOAD],
            verifier_probe=True,
        ),
        Case(
            "lua-xdp-steady",
            [executable(build, "benchmarks/lua-xdp/lua_xdp_benchmark"),
             str(lua_xdp_policy), "100"],
            "Lua state initializations: 1",
            [],
            [
                Metric(
                    "cold",
                    r"first policy after initialization: ([0-9.]+) ms",
                    (("cold_ms", "ms"),),
                ),
                Metric(
                    "steady",
                    r"steady policy: median ([0-9.]+) ms, p95 ([0-9.]+) ms",
                    (("kernel_ms", "ms"), ("p95_ms", "ms")),
                ),
                Metric(
                    "baseline",
                    r"matched XDP_PASS baseline: ([0-9.]+) ms",
                    (("xdp_baseline_ms", "ms"),),
                ),
                Metric(
                    "net",
                    r"net Lua inspection: ([0-9.]+) ms, ([0-9.]+) packets/s/core",
                    (("net_ms", "ms"), ("packets_per_second", "count/s")),
                ),
                LOAD,
            ],
        ),
        Case(
            "quickjs",
            [executable(build, "examples/quickjs/quickjs"),
             str(ROOT / "examples/quickjs/script.js")],
            "807746|743|100|true|0",
            [build / "examples/quickjs/quickjs_bpf_lib.o"],
            [KERNEL_NS, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ),
        Case(
            "sqlite",
            [executable(build, "examples/sqlite/sqlite")],
            "rows=11 checksum=4e4d372ad01ecc09",
            [build / "examples/sqlite/sqlite_bpf_lib.o"],
            [KERNEL_NATIVE_NS, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ),
    ]

    rust_host = build / "examples/rust/rust"
    if rust_host.exists():
        cases.append(Case(
            "rust",
            [str(rust_host)],
            "panic demo: status=exited code=101",
            [build / "examples/rust/rust_bpf.o"],
            [KERNEL_NATIVE_NS, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ))

    overhead = build / "benchmarks/overhead/overhead_host"
    if overhead.exists():
        cases.append(Case(
            "overhead-c",
            [str(overhead),
             executable(build, "benchmarks/overhead/overhead_direct.o"),
             executable(build, "benchmarks/overhead/overhead_transformed_exact.o"),
             executable(build, "benchmarks/overhead/overhead_transformed.o")],
            "OVERHEAD-PASS",
            [build / "benchmarks/overhead/overhead_direct.o",
             build / "benchmarks/overhead/overhead_transformed_exact.o",
             build / "benchmarks/overhead/overhead_transformed.o"],
            [
                Metric("native", r"native:\s+([0-9.]+) ns",
                       (("native_ns", "ns"),)),
                Metric("direct", r"direct BPF:\s+[0-9.]+ ns raw, [0-9.]+ ns empty, ([0-9.]+) ns net; ([0-9.]+)x native",
                       (("direct_ns", "ns"), ("direct_native", "ratio"))),
                Metric("transformed", r"transformed:\s+[0-9.]+ ns raw, [0-9.]+ ns empty, ([0-9.]+) ns net; [0-9.]+x native, ([0-9.]+)x direct",
                       (("kernel_ns", "ns"), ("transform_tax", "ratio"))),
                Metric("load", r"load/JIT: direct ([0-9.]+) ms \(([0-9]+) JIT bytes\), transformed ([0-9.]+) ms \(([0-9]+) JIT bytes\)",
                       (("direct_load_ms", "ms"), ("direct_jit_bytes", "bytes"),
                        ("load_ms", "ms"), ("jit_bytes", "bytes"))),
                Metric("capsule-call", r"capsule call: ([0-9.]+) ns raw, ([0-9.]+) ns over native empty",
                       (("capsule_call_ns", "ns"), ("capsule_call_net_ns", "ns"))),
                Metric("fiber-cap", r"fiber cap: lower\(max=64,count=[0-9]+\)=([0-9.]+) ns portable\(max=512,count=[0-9]+\)=([0-9.]+) ns ratio=([0-9.]+)x",
                       (("lower_cap_ns", "ns"), ("portable_cap_ns", "ns"), ("fiber_cap_ratio", "ratio"))),
            ],
        ))

    rust_overhead = build / "benchmarks/overhead/rust_overhead_host"
    if rust_overhead.exists():
        cases.append(Case(
            "overhead-rust",
            [str(rust_overhead),
             executable(build, "benchmarks/overhead/rust_overhead_direct.o"),
             executable(build, "benchmarks/overhead/rust_overhead_transformed.o")],
            "RUST-OVERHEAD-PASS",
            [build / "benchmarks/overhead/rust_overhead_direct.o",
             build / "benchmarks/overhead/rust_overhead_transformed.o"],
            [
                Metric("native", r"native Rust:\s+([0-9.]+) ns",
                       (("native_ns", "ns"),)),
                Metric("direct", r"direct Rust BPF:\s+[0-9.]+ ns raw, [0-9.]+ ns empty, ([0-9.]+) ns net; ([0-9.]+)x native",
                       (("direct_ns", "ns"), ("direct_native", "ratio"))),
                Metric("transformed", r"transformed Rust:\s+[0-9.]+ ns raw, [0-9.]+ ns empty, ([0-9.]+) ns net; [0-9.]+x native, ([0-9.]+)x direct",
                       (("kernel_ns", "ns"), ("transform_tax", "ratio"))),
                Metric("load", r"load/JIT: direct ([0-9.]+) ms \(([0-9]+) JIT bytes\), transformed ([0-9.]+) ms \(([0-9]+) JIT bytes\)",
                       (("direct_load_ms", "ms"), ("direct_jit_bytes", "bytes"),
                        ("load_ms", "ms"), ("jit_bytes", "bytes"))),
            ],
        ))

    if args.llama2_model:
        cases.append(Case(
            "llama2",
            [executable(build, "examples/llama2/llama2"),
             str(args.llama2_model), "32"],
            "tokens:",
            [build / "examples/llama2/llama2_bpf_lib.o"],
            [LLAMA_TIME, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ))
    if args.llama2q_model:
        cases.append(Case(
            "llama2-q8",
            [executable(build, "examples/llama2/llama2q"),
             str(args.llama2q_model), "32"],
            "tokens:",
            [build / "examples/llama2/llama2q_bpf_lib.o"],
            [LLAMA_TIME, CONTINUATION_DRAINS],
            max_drains=0,
            verifier_probe=True,
        ))
    # The csmith tripwire exists only in builds configured with
    # BPF_CAPSULE_CSMITH_CASE (the Nix matrix packages set it). A plain
    # source build skips it rather than failing on a product it never made.
    if (build / "tests/csmith/csmith_test_host").exists():
        cases.append(Case(
            "csmith-seed-17",
            [executable(build, "tests/csmith/csmith_test_host")],
            "CSMITH-PASS",
            [build / "tests/csmith/csmith_test_bpf.o"],
            [INVOCATIONS, LOAD],
            max_drains=0,
        ))
    else:
        print("csmith tripwire not built (BPF_CAPSULE_CSMITH_CASE unset); skipping", flush=True)
    if args.doom_wad:
        output = Path(tempfile.mkdtemp(prefix="bpf-capsule-doom-"))
        atexit.register(shutil.rmtree, output, ignore_errors=True)
        cases.append(Case(
            "doom",
            [executable(build, "examples/doom/doom"),
             str(args.doom_wad), "dump", str(args.doom_frames), str(output)],
            "dump done: status=0",
            [build / "examples/doom/doom_bpf_lib.o"],
            [
                Metric(
                    "time",
                    r"kernel frame time over ([0-9]+) frames: avg ([0-9.]+) ms, "
                    r"p50 ([0-9.]+) ms, p90 ([0-9.]+) ms, p99 ([0-9.]+) ms, "
                    r"max ([0-9.]+) ms",
                    (("measured_frames", "count"), ("kernel_ms", "ms"),
                     ("p50_ms", "ms"), ("p90_ms", "ms"), ("p99_ms", "ms"),
                     ("max_ms", "ms")),
                ),
            ],
            repeatability_dir=output,
            verifier_probe=True,
        ))
    return cases


def number(value: str) -> int | float:
    return float(value) if "." in value else int(value)


def parse_metrics(case: Case, output: str) -> dict[str, tuple[int | float, str]]:
    parsed: dict[str, tuple[int | float, str]] = {}
    for metric in case.metrics:
        match = re.search(metric.pattern, output)
        if not match:
            raise RuntimeError(f"{case.name}: missing {metric.name} metric")
        for value, (name, unit) in zip(match.groups(), metric.groups):
            parsed[name] = (number(value), unit)
    if "kernel_ms" in parsed and "native_ms" in parsed and "slowdown" not in parsed:
        native_ms = float(parsed["native_ms"][0])
        if native_ms > 0:
            parsed["slowdown"] = (
                float(parsed["kernel_ms"][0]) / native_ms,
                "ratio",
            )
    return parsed


def object_sizes(path: Path) -> dict[str, int | str]:
    data = path.read_bytes()
    result: dict[str, int | str] = {
        "file_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    # GNU size and eu-size print the same leading text/data/bss columns as
    # llvm-size.  Prefer the LLVM spelling in developer shells, but do not
    # pull LLVM into the small regression VMs merely to inspect object sizes.
    tool = (shutil.which("llvm-size") or shutil.which("size") or
            shutil.which("eu-size"))
    if not tool:
        return result
    process = subprocess.run(
        [tool, str(path)], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=False,
    )
    lines = process.stdout.splitlines()
    if process.returncode == 0 and len(lines) >= 2:
        fields = lines[-1].split()
        if len(fields) >= 4:
            result.update(text_bytes=int(fields[0]), data_bytes=int(fields[1]),
                          bss_bytes=int(fields[2]))
    if len(data) >= 16 and data[:4] == b"\x7fELF" and data[5] in (1, 2):
        endian = "<" if data[5] == 1 else ">"
        if data[4] == 2:
            header_format = endian + "HHIQQQIHHHHHH"
            section_format = endian + "IIQQQQIIQQ"
        elif data[4] == 1:
            header_format = endian + "HHIIIIIHHHHHH"
            section_format = endian + "IIIIIIIIII"
        else:
            return result
        header_size = struct.calcsize(header_format)
        if len(data) >= 16 + header_size:
            header = struct.unpack_from(header_format, data, 16)
            section_offset = header[5]
            section_entry_size = header[10]
            section_count = header[11]
            expected_size = struct.calcsize(section_format)
            if section_entry_size >= expected_size and section_offset <= len(data):
                code_bytes = 0
                for index in range(section_count):
                    offset = section_offset + index * section_entry_size
                    if offset + expected_size > len(data):
                        code_bytes = 0
                        break
                    section = struct.unpack_from(section_format, data, offset)
                    flags = section[2]
                    size = section[5]
                    if flags & 0x4:  # ELF SHF_EXECINSTR
                        code_bytes += size
                if code_bytes and code_bytes % 8 == 0:
                    result.update(code_bytes=code_bytes,
                                  static_insns=code_bytes // 8)
    return result


def privileged_prefix() -> list[str]:
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError("BPF execution needs root; sudo was not found")
    return [sudo]


def find_build_artifact(anchor: Path, relative: Path) -> Path:
    """Find one build-root-relative artifact from a nested build product."""
    for parent in anchor.parents:
        candidate = parent / relative
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"build artifact {relative} is missing above {anchor}")


def tree_digest(directory: Path) -> dict[str, int | str]:
    """Hash names and bytes so stale, missing, and changed frames all fail."""
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    total = 0
    for path in files:
        relative = path.relative_to(directory).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "little"))
        digest.update(relative)
        size = path.stat().st_size
        total += size
        digest.update(size.to_bytes(8, "little"))
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return {"sha256": digest.hexdigest(), "files": len(files), "bytes": total}


def run_verifier_probe(case: Case, verbose: bool) -> tuple[dict[str, tuple[int | float, str]], str]:
    if len(case.objects) != 1:
        raise RuntimeError(f"{case.name}: verifier probe needs exactly one object")
    probe = find_build_artifact(case.objects[0], Path("tests/verifier-metrics/verifier_load_probe"))
    command = privileged_prefix() + [str(probe), str(case.objects[0])]
    process = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if process.returncode or "VERIFIER-METRICS-PASS" not in process.stdout:
        sys.stdout.write(process.stdout)
        raise RuntimeError(
            f"{case.name}: verifier probe failed with status {process.returncode}"
        )
    processed = [int(value) for value in re.findall(
        r"^processed ([0-9]+) insns ", process.stdout, re.MULTILINE
    )]
    load = re.search(r"verified\+loaded in ([0-9.]+) s", process.stdout)
    if not processed or not load:
        sys.stdout.write(process.stdout)
        raise RuntimeError(f"{case.name}: verifier probe emitted incomplete metrics")
    if verbose:
        sys.stdout.write(process.stdout)
    return {
        "verifier_processed_insns": (max(processed), "insns"),
        "load_s": (float(load.group(1)), "s"),
    }, process.stdout


def run_case(case: Case, samples: int, verbose: bool) -> dict:
    missing = [path for path in case.objects if not path.exists()]
    if not Path(case.command[0]).exists() or missing:
        raise RuntimeError(f"{case.name}: build products are missing")

    print(f"\n==> {case.name} ({samples} fresh process{'es' if samples != 1 else ''})",
          flush=True)
    observed: dict[str, list[int | float]] = {}
    units: dict[str, str] = {}
    wall: list[float] = []
    outputs: list[str] = []
    artifacts: list[dict[str, int | str]] = []
    probe_metrics: dict[str, tuple[int | float, str]] = {}
    probe_output = ""
    if case.verifier_probe:
        probe_metrics, probe_output = run_verifier_probe(case, verbose)
    environment = dict(case.environment)
    environment.setdefault("BPF_CAPSULE_LOAD_TIMING", "1")
    if case.objects:
        environment.setdefault("BPF_CAPSULE_VERIFIER_STATS", "1")
    command = privileged_prefix()
    if command:
        command += ["env"] + [f"{key}={value}" for key, value in environment.items()]
    else:
        command = ["env"] + [f"{key}={value}" for key, value in environment.items()]
    command += case.command

    for sample in range(samples):
        if case.repeatability_dir:
            # Start every process with an empty tree. Otherwise a process
            # which silently omits one output could leave the preceding
            # sample's file behind and produce a falsely identical digest.
            shutil.rmtree(case.repeatability_dir)
            case.repeatability_dir.mkdir(parents=True)
        begin = time.monotonic()
        process = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        wall.append(time.monotonic() - begin)
        outputs.append(process.stdout)
        if process.returncode or case.marker not in process.stdout:
            sys.stdout.write(process.stdout)
            raise RuntimeError(
                f"{case.name}: sample {sample + 1} failed with status "
                f"{process.returncode} or lacked {case.marker!r}"
            )
        if case.repeatability_dir:
            current = tree_digest(case.repeatability_dir)
            if not current["files"]:
                raise RuntimeError(f"{case.name}: produced no repeatability artifacts")
            if artifacts and current != artifacts[0]:
                raise RuntimeError(
                    f"{case.name}: output differs between fresh processes: "
                    f"{artifacts[0]['sha256']} != {current['sha256']}"
                )
            artifacts.append(current)
        metrics = parse_metrics(case, process.stdout)
        verifier_insns = [int(value) for value in
                          re.findall(r"^processed ([0-9]+) insns ",
                                     process.stdout, re.MULTILINE)]
        if verifier_insns:
            metrics["verifier_processed_insns"] = (max(verifier_insns), "insns")
        if "entries" in metrics and int(metrics["entries"][0]) < 1:
            raise RuntimeError(f"{case.name}: reported no BPF entry calls")
        if case.max_drains is not None:
            if "drains" not in metrics:
                raise RuntimeError(
                    f"{case.name}: has a drain limit but reported no drain metric"
                )
            if int(metrics["drains"][0]) > case.max_drains:
                raise RuntimeError(
                    f"{case.name}: required {metrics['drains'][0]} userspace drains"
                    f" (allowed {case.max_drains})"
                )
        for name, (value, unit) in metrics.items():
            observed.setdefault(name, []).append(value)
            units[name] = unit
        print(f"  sample {sample + 1}: {wall[-1]:.3f} s process wall",
              flush=True)
        if verbose:
            sys.stdout.write(process.stdout)

    for name, (value, unit) in probe_metrics.items():
        if name not in observed:
            observed[name] = [value] * samples
            units[name] = unit

    observed["process_wall_s"] = wall
    units["process_wall_s"] = "s"
    metrics = {
        name: {
            "unit": units[name],
            "samples": values,
            "median": statistics.median(values),
            "minimum": min(values),
            "maximum": max(values),
        }
        for name, values in observed.items()
    }
    for name in CANONICAL_METRICS & metrics.keys():
        metric = metrics[name]
        if metric["minimum"] != metric["maximum"]:
            raise RuntimeError(
                f"{case.name}: canonical metric {name} changed between "
                f"samples ({metric['minimum']} != {metric['maximum']})"
            )
    objects = {str(path.relative_to(case.objects[0].parents[2]))
               if len(path.parents) > 2 else path.name: object_sizes(path)
               for path in case.objects}
    if len(objects) == 1 and "verifier_processed_insns" in metrics:
        static_insns = next(iter(objects.values())).get("static_insns")
        if static_insns:
            processed = metrics["verifier_processed_insns"]["samples"]
            metrics["verifier_static_insns"] = {
                "unit": "insns",
                "samples": [static_insns] * len(processed),
                "median": static_insns,
                "minimum": static_insns,
                "maximum": static_insns,
            }
            expansion = [value / static_insns for value in processed]
            metrics["verifier_expansion"] = {
                "unit": "ratio",
                "samples": expansion,
                "median": statistics.median(expansion),
                "minimum": min(expansion),
                "maximum": max(expansion),
            }
    result = {
        "status": "pass",
        "command": case.command,
        "marker": case.marker,
        "metrics": metrics,
        "objects": objects,
        "last_output": probe_output + outputs[-1],
    }
    if artifacts:
        result["repeatability"] = {
            **artifacts[0],
            "samples": [artifact["sha256"] for artifact in artifacts],
        }
    return result


def build_tree(build: Path, profile: str, jobs: int) -> float:
    configure = [
        "cmake", "-S", str(ROOT), "-B", str(build),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBPF_CAPSULE_BUILD_EXAMPLES=ON",
        f"-DBPF_CAPSULE_TARGET_KERNEL={profile}",
    ]
    print("==> configure", " ".join(configure), flush=True)
    subprocess.run(configure, cwd=ROOT, check=True)
    command = ["cmake", "--build", str(build), "-j", str(jobs)]
    print("==> build", " ".join(command), flush=True)
    begin = time.monotonic()
    subprocess.run(command, cwd=ROOT, check=True)
    return time.monotonic() - begin


def git_metadata() -> dict:
    executable = shutil.which("git")
    if not executable or not (ROOT / ".git").exists():
        return {"commit": None, "dirty": None, "diff_stat": ""}

    def git(*arguments: str) -> str:
        result = subprocess.run(
            git_command(executable, *arguments), cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        return result.stdout.strip()

    return {
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
        "diff_stat": git("diff", "HEAD", "--shortstat"),
    }


def git_command(executable: str, *arguments: str) -> list[str]:
    # A flake app executes from an immutable store copy owned by root. New Git
    # quite reasonably distrusts that repository for configuration, but these
    # commands only fingerprint it. Scope the exception to this exact tree and
    # invocation instead of mutating the user's global Git configuration.
    return [executable, "-c", f"safe.directory={ROOT}", *arguments]


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_version(command: list[str]) -> str | None:
    try:
        process = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False)
    except OSError:
        return None
    return process.stdout.splitlines()[0].strip() if process.stdout else None


def source_metadata() -> dict:
    """Fingerprint the exact build input, including untracked source files."""
    metadata = {
        "git": git_metadata(),
        "tree_sha256": None,
        "flake_lock_sha256": file_sha256(ROOT / "flake.lock"),
        "toolchain": {
            "llvm": command_version(["llvm-config", "--version"]),
            "clang": command_version(["clang", "--version"]),
            "libbpf": command_version(["pkg-config", "--modversion", "libbpf"]),
            "cmake": command_version(["cmake", "--version"]),
        },
    }
    git = shutil.which("git")
    if not git or not (ROOT / ".git").exists():
        return metadata
    listed = subprocess.run(
        git_command(git, "ls-files", "--cached", "--others",
                    "--exclude-standard", "-z"),
        cwd=ROOT, stdout=subprocess.PIPE, check=True).stdout
    digest = hashlib.sha256()
    for encoded in sorted(filter(None, listed.split(b"\0"))):
        relative = os.fsdecode(encoded)
        path = ROOT / relative
        digest.update(encoded)
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(f"{path.stat().st_mode & 0o777:o}".encode())
            digest.update(b"\0")
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
        digest.update(b"\0")
    metadata["tree_sha256"] = digest.hexdigest()
    return metadata


def compare(report: dict,
            baseline_path: Path) -> tuple[list[str], list[str]]:
    baseline = json.loads(baseline_path.read_text())
    failures: list[str] = []
    timing_observations: list[str] = []
    if baseline.get("profile") != report["profile"]:
        failures.append(
            f"baseline profile {baseline.get('profile')} != {report['profile']}"
        )
        return failures, timing_observations

    selected = set(report.get("selection", []))
    for name in baseline.get("tests", {}):
        if selected and name not in selected:
            continue
        if name not in report["tests"]:
            failures.append(f"baseline case is missing from this run: {name}")

    for name, current in report["tests"].items():
        old = baseline.get("tests", {}).get(name)
        if not old:
            continue
        current_metrics = current["metrics"]
        old_metrics = old.get("metrics", {})

        # Timing is deliberately observational. Absolute values are not
        # portable across hosts, and no percentage is universally large
        # enough to be a regression. A developer compares paired old/new runs
        # under the protocol in benchmarks/PERFORMANCE.md.
        for metric_name, new_metric in current_metrics.items():
            old_metric = old_metrics.get(metric_name)
            if (not old_metric or
                    new_metric.get("unit") not in {"ns", "ms", "s"}):
                continue
            new = float(new_metric["median"])
            previous = float(old_metric["median"])
            if previous:
                change = new / previous - 1.0
                timing_observations.append(
                    f"{name}.{metric_name}: {new:g} vs {previous:g} "
                    f"({change * 100:+.1f}%)"
                )
        for metric_name in CANONICAL_METRICS:
            new_metric = current["metrics"].get(metric_name)
            old_metric = old.get("metrics", {}).get(metric_name)
            if bool(new_metric) != bool(old_metric):
                state = "added" if new_metric else "missing"
                failures.append(
                    f"{name}.{metric_name}: canonical metric {state}"
                )
            elif (new_metric and
                  new_metric["median"] != old_metric["median"]):
                failures.append(
                    f"{name}.{metric_name}: {new_metric['median']} != "
                    f"{old_metric['median']} (canonical metric changed)"
                )
        old_objects = old.get("objects", {})
        for object_name, sizes in current["objects"].items():
            old_sizes = old_objects.get(object_name)
            if not old_sizes:
                continue
            if (new_hash := sizes.get("sha256")) != old_sizes.get("sha256"):
                failures.append(
                    f"{name}.{object_name}.sha256: {new_hash} != "
                    f"{old_sizes.get('sha256')} (compiler product changed)"
                )
            # Program compactness is executable/constant text and JIT size.
            # The complete ELF also contains host-side DWARF, BTF and
            # relocations whose encoding can change without altering anything
            # loaded or executed; retain file_bytes in reports, but do not let
            # packaging metadata masquerade as a BPF code-size regression.
            for size_name in ("code_bytes",):
                new = sizes.get(size_name)
                previous = old_sizes.get(size_name)
                if new is None:
                    continue
                if new != previous:
                    failures.append(
                        f"{name}.{object_name}.{size_name}: {new} != "
                        f"{previous} (canonical metric changed)"
                    )
    return failures, timing_observations


def show_summary(report: dict) -> None:
    print("\nRegression summary")
    print(f"{'test':18} {'BPF time':>11} {'native':>11} {'ratio':>7} "
          f"{'load':>8} {'calls':>9} {'verified':>10} {'V/static':>9} "
          f"{'code':>10} {'ELF':>10}")
    print("-" * 113)
    for name, result in report["tests"].items():
        metrics = result["metrics"]

        def value(key: str) -> str:
            metric = metrics.get(key)
            if not metric:
                return "-"
            number_value = metric["median"]
            return f"{number_value:g} {metric['unit']}"

        def ratio_value() -> str:
            metric = metrics.get("slowdown") or metrics.get("transform_tax")
            return f"{metric['median']:.2f}x" if metric else "-"

        kernel = value("kernel_ms") if "kernel_ms" in metrics else value("kernel_ns")
        native = value("native_ms") if "native_ms" in metrics else value("native_ns")
        load = value("load_s") if "load_s" in metrics else value("load_ms")
        calls = "-"
        if "entries" in metrics and "drains" in metrics:
            calls = (f"{metrics['entries']['median']:g}+"
                     f"{metrics['drains']['median']:g}")
        verified = "-"
        if "verifier_processed_insns" in metrics:
            verified = f"{metrics['verifier_processed_insns']['median']:g}"
        verifier_expansion = "-"
        if "verifier_expansion" in metrics:
            verifier_expansion = f"{metrics['verifier_expansion']['median']:.2f}x"
        code_size = "-"
        file_size = "-"
        if result["objects"]:
            sizes = list(result["objects"].values())[-1]
            if "code_bytes" in sizes:
                code_size = f"{sizes['code_bytes'] / 1024:.1f} KiB"
            file_size = f"{sizes['file_bytes'] / 1024:.1f} KiB"
        print(f"{name:18} {kernel:>11} {native:>11} {ratio_value():>7} "
              f"{load:>8} {calls:>9} {verified:>10} {verifier_expansion:>9} "
              f"{code_size:>10} {file_size:>10}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build-regression")
    parser.add_argument("--profile", type=kernel_version, default="6.9")
    parser.add_argument("--samples", type=int, default=1,
                        help="fresh processes per workload (default: 1)")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 4))
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--build-seconds", type=float,
                        help="externally measured build time with --no-build")
    parser.add_argument("--case", action="append", default=[],
                        help="run only this case; repeat as needed")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--read-report", type=Path,
                        help="print an existing JSON report and exit")
    parser.add_argument("--source-metadata", type=Path,
                        help="build-input metadata captured outside a test VM")
    parser.add_argument("--write-source-metadata", type=Path,
                        help="write build-input metadata and exit")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--doom-wad", type=optional_path,
                        default=os.environ.get("DOOM_WAD"))
    parser.add_argument("--doom-frames", type=int, default=80)
    parser.add_argument("--llama2-model", type=optional_path,
                        default=os.environ.get("LLAMA2_MODEL"))
    parser.add_argument("--llama2q-model", type=optional_path,
                        default=os.environ.get("LLAMA2Q_MODEL"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.write_source_metadata:
        args.write_source_metadata.parent.mkdir(parents=True, exist_ok=True)
        args.write_source_metadata.write_text(
            json.dumps(source_metadata(), indent=2) + "\n")
        return 0

    if args.read_report:
        saved = json.loads(args.read_report.read_text())
        show_summary(saved)
        comparison = saved.get("comparison")
        if comparison:
            print(f"\nBaseline comparison: {comparison['status'].upper()}")
            for observation in comparison.get(
                    "timing_observations", comparison.get("warnings", [])):
                print(f"  timing: {observation}")
            for failure in comparison.get("failures", []):
                print(f"  failure: {failure}")
            return 1 if comparison["status"] == "fail" else 0
        print("\nBaseline comparison: not run (this report becomes the baseline)")
        return 0

    if args.samples < 1 or args.jobs < 1:
        parser.error("--samples and --jobs must be positive")
    build = args.build.resolve()
    build_seconds = args.build_seconds
    if not args.no_build:
        build_seconds = build_tree(build, args.profile, args.jobs)

    cases = make_cases(build, args)
    if args.case:
        wanted = set(args.case)
        cases = [case for case in cases if case.name in wanted]
        missing = wanted - {case.name for case in cases}
        if missing:
            parser.error("unknown or unavailable cases: " + ", ".join(sorted(missing)))

    report = {
        "schema": 3,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": args.profile,
        "samples": args.samples,
        "selection": args.case,
        "system": {
            "uname": " ".join(os.uname()),
            "machine": os.uname().machine,
            "cpu_count": os.cpu_count(),
        },
        "git": git_metadata(),
        "source": (json.loads(args.source_metadata.read_text())
                   if args.source_metadata else source_metadata()),
        "runtime_toolchain": {
            "bpftool": command_version(["bpftool", "version"]),
            "libbpf": command_version(["pkg-config", "--modversion", "libbpf"]),
        },
        "build": {"path": str(build), "seconds": build_seconds},
        "tests": {},
    }

    try:
        for case in cases:
            samples = max(args.samples, 2 if case.repeatability_dir else 1)
            report["tests"][case.name] = run_case(
                case, samples, args.verbose)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"\nREGRESSION-FAIL: {error}", file=sys.stderr)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        return 1

    failures: list[str] = []
    timing_observations: list[str] = []
    if args.baseline:
        try:
            failures, timing_observations = compare(report, args.baseline)
        except (OSError, json.JSONDecodeError) as error:
            print(f"error: unusable baseline {args.baseline}: {error}",
                  file=sys.stderr)
            return 1
        report["comparison"] = {
            "baseline": str(args.baseline),
            "status": "fail" if failures else "pass",
            "failures": failures,
            "timing_observations": timing_observations,
        }

    show_summary(report)
    output = args.output or build / "bpf-capsule-regression.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nJSON report: {output}")

    if args.baseline:
        if timing_observations:
            print("\nPaired timing observations:")
            for observation in timing_observations:
                print(f"  {observation}")
        if failures:
            print("\nCanonical metric changes:", file=sys.stderr)
            for failure in failures:
                print(f"  {failure}", file=sys.stderr)
            return 1
        print(f"Baseline comparison: PASS ({args.baseline})")

    print("BPF-CAPSULE-REGRESSION-PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
