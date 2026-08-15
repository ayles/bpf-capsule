#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build and run the reproducible arena/map BPF Capsule VM matrix."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
REGRESSION = ROOT / "benchmarks/regression.py"
PROFILES = (
    ("6.9", "matrix-arena", "vm-arena"),
    ("5.15", "matrix-515", "vm-515"),
)
ARTIFACTS = (
    "examples/fib/fib",
    "examples/zlib/zlib",
    "examples/zlib/zlib_bpf_lib.o",
    "examples/wasm3/wasm3",
    "examples/wasm3/wasm3_bpf_lib.o",
    "examples/lua/lua",
    "examples/lua/lua_bpf.o",
    "examples/lua/script.lua",
    "examples/lua-xdp/lua_xdp_bpf.o",
    "examples/lua-xdp/packet_filter.lua",
    "examples/lua-xdp/packet_observer.lua",
    "tests/lua-xdp/lua_xdp_test_host",
    "benchmarks/lua-xdp/lua_xdp_benchmark",
    "examples/quickjs/quickjs",
    "examples/quickjs/quickjs_bpf_lib.o",
    "examples/sqlite/sqlite",
    "examples/sqlite/sqlite_bpf_lib.o",
    "examples/rust/rust",
    "examples/rust/rust_bpf.o",
    "benchmarks/overhead/overhead_host",
    "benchmarks/overhead/overhead_direct.o",
    "benchmarks/overhead/overhead_transformed.o",
    "benchmarks/overhead/overhead_transformed_exact.o",
    "benchmarks/overhead/rust_overhead_host",
    "benchmarks/overhead/rust_overhead_direct.o",
    "benchmarks/overhead/rust_overhead_transformed.o",
    "examples/llama2/llama2",
    "examples/llama2/llama2_bpf_lib.o",
    "examples/llama2/llama2q",
    "examples/llama2/llama2q_bpf_lib.o",
    "examples/llama2/llama2-tiny.bin",
    "examples/llama2/llama2q-tiny.bin",
    "examples/doom/doom",
    "examples/doom/doom_bpf_lib.o",
    "tests/integration/compiler_test_host",
    "tests/integration/compiler_test_bpf.o",
    "tests/integration/standalone_expr_host",
    "tests/integration/standalone_expr_bpf.o",
    "tests/atomics/atomic_runtime_host",
    "tests/atomics/atomic_runtime_bpf.o",
    "tests/arena-init/arena_init_host",
    "tests/arena-init/arena_init_bpf.o",
    "tests/context-interop/context_interop_test_host",
    "tests/context-interop/context_interop_borrowed_bpf.o",
    "tests/context-interop/context_interop_yield_bpf.o",
    "tests/fiber-scale/fiber_scale_host",
    "tests/fiber-scale/fiber_scale_bpf.o",
    "tests/memory/memory_test_host",
    "tests/memory/memory_test_bpf.o",
    "tests/nosuspend/nosuspend_test_host",
    "tests/nosuspend/nosuspend_test_bpf.o",
    "tests/rehash/rehash_test_host",
    "tests/rehash/rehash_test_bpf.o",
    "tests/spill-concurrency/physical_spill_host",
    "tests/spill-concurrency/physical_spill_bpf.o",
    "tests/errors/error_strings_host",
    "tests/errors/host_header_cpp",
    "tests/errors/drive_contract_host",
    "tests/libc/libc_test_host",
    "tests/libc/libc_test_bpf.o",
    "tests/verifier-metrics/verifier_load_probe",
    "tests/verifier-pointer/verifier_pointer_test_host",
    "tests/verifier-pointer/verifier_pointer_test_bpf.o",
    "tests/yield/yield_test_host",
    "tests/yield/yield_test_bpf.o",
    "tests/csmith/csmith_test_host",
    "tests/csmith/csmith_test_bpf.o",
)


def env_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, default))
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def normalize_nix_source(source: str) -> str:
    """Open immutable store trees as paths, never as ownership-sensitive Git."""
    if source.startswith("path:"):
        return source
    if source.startswith("git+file://"):
        path = source.removeprefix("git+file://")
        if path.startswith("/nix/store/"):
            return f"path:{path}"
    if source.startswith("/"):
        return f"path:{source}"
    return source


def nix_build(source: str, attribute: str, log: Path,
              out_link: Path | None = None) -> Path:
    command = ["nix", "build", f"{source}#{attribute}"]
    if out_link is None:
        command += ["--no-link", "--print-out-paths"]
    else:
        command += ["--out-link", str(out_link)]
    with log.open("w") as output:
        process = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                 stderr=output, check=False)
    if process.returncode:
        sys.stderr.write(log.read_text())
        raise RuntimeError(f"nix build failed for {attribute}")
    if out_link is not None:
        return out_link.resolve()
    paths = [Path(line) for line in process.stdout.splitlines() if line]
    if len(paths) != 1:
        raise RuntimeError(f"nix build returned {len(paths)} paths for {attribute}")
    return paths[0]


def valid_baseline(path: Path) -> bool:
    try:
        reports = [json.loads((path / f"{profile}.json").read_text())
                   for profile, _, _ in PROFILES]
    except (OSError, json.JSONDecodeError):
        return False
    return ((path / "matrix-pass").is_file() and
            all(report.get("schema") == 3 for report in reports) and
            all(report.get("comparison", {}).get("status") != "fail"
                for report in reports))


def newest_baseline(root: Path, current: Path) -> Path | None:
    candidates = [path for path in root.iterdir()
                  if path.is_dir() and path != current and valid_baseline(path)]
    return max(candidates, key=lambda path: (path / "6.9.json").stat().st_mtime,
               default=None)


def copy_required(source_root: Path, destination_root: Path) -> None:
    for relative in ARTIFACTS:
        source = source_root / relative
        if not source.is_file():
            raise RuntimeError(f"matrix package lacks {relative}")
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def optional_file(variable: str, default: Path | None) -> Path | None:
    value = os.environ.get(variable)
    if value == "none":
        return None
    path = Path(value) if value else default
    if path is not None and not path.is_file():
        raise RuntimeError(f"{variable} does not name a file: {path}")
    return path


def stage_profile(profile: str, package: Path, stage: Path, report: str,
                  build_seconds: float, metadata: Path,
                  baseline: Path | None) -> None:
    build = stage / "build"
    copy_required(package / "libexec/bpf-capsule", build)
    (stage / "benchmarks").mkdir(parents=True, exist_ok=True)
    shutil.copy2(REGRESSION, stage / "benchmarks/regression.py")
    shutil.copy2(ROOT / "tests/vm/guest.py", stage / "guest.py")
    quickjs_script = stage / "examples/quickjs/script.js"
    quickjs_script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "examples/quickjs/script.js", quickjs_script)
    shutil.copy2(metadata, stage / "source-metadata.json")

    arguments = [
        "--build", "/tmp/shared/build",
        "--profile", profile,
        "--samples", str(env_int("BPF_CAPSULE_SAMPLES", 1)),
        "--no-build",
        "--build-seconds", str(build_seconds),
        "--source-metadata", "/tmp/shared/source-metadata.json",
        "--output", f"/tmp/shared/{report}",
    ]
    defaults = {
        "DOOM_WAD": optional_file(
            "DOOM_WAD",
            Path(os.environ["BPF_CAPSULE_DEFAULT_DOOM_WAD"])
            if os.environ.get("BPF_CAPSULE_DEFAULT_DOOM_WAD") else None),
        "LLAMA2_MODEL": optional_file(
            "LLAMA2_MODEL",
            build / "examples/llama2/llama2-tiny.bin"),
        "LLAMA2Q_MODEL": optional_file(
            "LLAMA2Q_MODEL",
            build / "examples/llama2/llama2q-tiny.bin"),
    }
    flags = {
        "DOOM_WAD": "--doom-wad",
        "LLAMA2_MODEL": "--llama2-model",
        "LLAMA2Q_MODEL": "--llama2q-model",
    }
    for variable, source in defaults.items():
        if source is None:
            continue
        # Store-resident defaults already appear below build; external
        # overrides are copied into the writable share.
        try:
            relative = source.relative_to(stage)
            guest_path = f"/tmp/shared/{relative}"
        except ValueError:
            destination = stage / "data" / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            guest_path = f"/tmp/shared/data/{source.name}"
        arguments += [flags[variable], guest_path]
    if baseline is not None:
        destination = stage / "baseline.json"
        shutil.copy2(baseline / report, destination)
        arguments += ["--baseline", "/tmp/shared/baseline.json"]
    (stage / "config.json").write_text(json.dumps(arguments, indent=2) + "\n")


def cpu_capacity(cpu: int) -> int:
    for name in ("cpu_capacity", "cpufreq/cpuinfo_max_freq"):
        try:
            return int((Path(f"/sys/devices/system/cpu/cpu{cpu}") / name)
                       .read_text().strip())
        except OSError:
            pass
    return 0


def automatic_cpus() -> list[int]:
    allowed = sorted(os.sched_getaffinity(0))
    ranked = sorted(allowed, key=lambda cpu: (cpu_capacity(cpu), -cpu),
                    reverse=True)
    return sorted(ranked[:min(6, len(ranked))])


def selected_cpus() -> list[int]:
    configured = os.environ.get("BPF_CAPSULE_VM_CPUS")
    if not configured:
        return automatic_cpus()
    result: list[int] = []
    for part in configured.split(","):
        ends = [int(value) for value in part.split("-", 1)]
        result.extend(range(ends[0], ends[-1] + 1))
    return sorted(set(result))


def write_governor(path: Path, value: str) -> bool:
    try:
        path.write_text(value + "\n")
        return True
    except OSError:
        sudo = shutil.which("sudo")
        if not sudo:
            return False
        process = subprocess.run([sudo, "-n", "tee", str(path)],
                                 input=value + "\n", text=True,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False)
        return process.returncode == 0


@contextlib.contextmanager
def performance_governor(cpus: list[int]):
    saved: dict[Path, str] = {}
    for cpu in cpus:
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        try:
            value = path.read_text().strip()
        except OSError:
            continue
        if write_governor(path, "performance"):
            saved[path] = value
    try:
        yield bool(saved)
    finally:
        for path, value in saved.items():
            write_governor(path, value)


def run_vm(command: list[str], environment: dict[str, str], log: Path,
           timeout: int) -> int:
    with log.open("w") as output:
        process = subprocess.Popen(command, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            return 124


def comparison_failed(report: dict) -> bool:
    return report.get("comparison", {}).get("status") == "fail"


def run_profile(profile: str, artifact_name: str, vm_name: str,
                source: str, results: Path, metadata: Path,
                baseline: Path | None, cpus: list[int], timeout: int) -> Path:
    suffix = profile.replace(".", "")
    started = time.monotonic()
    package = nix_build(source, artifact_name,
                        results / f"{profile}-build.log")
    build_seconds = time.monotonic() - started
    print(f"\n{profile}: artifacts ready in {build_seconds:.1f} s", flush=True)

    stage = results / f"stage-{suffix}"
    report = f"{profile}.json"
    stage_profile(profile, package, stage, report, build_seconds,
                  metadata, baseline)
    vm = nix_build(source, vm_name, results / f"{profile}-nix.log",
                   results / f"vm-{suffix}")
    command = [str(vm / "bin/run-nixos-vm")]
    if cpus:
        command = ["taskset", "-c", ",".join(map(str, cpus)), *command]
    environment = os.environ.copy()
    environment.update({
        "NIX_DISK_IMAGE": str(results / f"{profile}.qcow2"),
        "SHARED_DIR": str(stage),
    })
    status = run_vm(command, environment, results / f"{profile}-vm.log",
                    timeout)
    if status:
        tail = (results / f"{profile}-vm.log").read_text(errors="replace")
        sys.stderr.write("\n".join(tail.splitlines()[-100:]) + "\n")
        raise RuntimeError(f"{profile} VM failed with status {status}")
    if not (stage / report).is_file() or not (stage / "status").is_file():
        raise RuntimeError(f"{profile} VM produced no complete report")
    destination = results / report
    shutil.copy2(stage / report, destination)
    document = json.loads(destination.read_text())
    if ((stage / "status").read_text().strip() != "0" and
            not comparison_failed(document)):
        raise RuntimeError(f"{profile} workload failed")
    subprocess.run([sys.executable, str(REGRESSION), "--read-report",
                    str(destination)], check=False)
    return destination


def main() -> int:
    source = normalize_nix_source(
        os.environ.get("BPF_CAPSULE_NIX_SOURCE", str(ROOT)))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    results_root = Path(os.environ.get(
        "BPF_CAPSULE_RESULTS_ROOT", ROOT / "benchmark-results")).resolve()
    results = Path(os.environ.get(
        "BPF_CAPSULE_RESULTS_DIR", results_root / stamp)).resolve()
    if results.exists() and any(results.iterdir()):
        raise RuntimeError(f"refusing to reuse non-empty results: {results}")
    results.mkdir(parents=True, exist_ok=True)
    metadata = results / "source-metadata.json"
    subprocess.run([sys.executable, str(REGRESSION),
                    "--write-source-metadata", str(metadata)], check=True)
    document = json.loads(metadata.read_text())
    document["nix_source"] = source
    metadata.write_text(json.dumps(document, indent=2) + "\n")

    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    cpus = selected_cpus()
    timeout = env_int("BPF_CAPSULE_VM_TIMEOUT", 7200)
    baseline: Path | None = None
    requested = os.environ.get("BPF_CAPSULE_BASELINE_DIR")
    if requested:
        baseline = Path(requested).resolve()
    elif (kvm and os.environ.get("BPF_CAPSULE_NO_BASELINE") != "1" and
          results_root.is_dir()):
        baseline = newest_baseline(results_root, results)
    print(f"Results: {results}")
    print(f"Acceleration: {'KVM' if kvm else 'TCG (correctness only)'}")
    print(f"Pinned CPUs: {','.join(map(str, cpus)) if cpus else 'none'}")
    print(f"Performance baseline: {baseline or 'none'}")

    reports: list[Path] = []
    try:
        with performance_governor(cpus) as held:
            if held:
                print("CPU governor: performance (restored on exit)")
            for profile, artifact, vm in PROFILES:
                reports.append(run_profile(
                    profile, artifact, vm, source, results, metadata,
                    baseline if kvm else None, cpus, timeout))
        data = [json.loads(path.read_text()) for path in reports]
        digests = [report.get("tests", {}).get("doom", {})
                   .get("repeatability", {}).get("sha256") for report in data]
        if any(digests) and (not all(digests) or digests[0] != digests[1]):
            raise RuntimeError(f"cross-profile Doom output differs: {digests}")
        failed = [report["profile"] for report in data
                  if comparison_failed(report)]
        if failed:
            raise RuntimeError(
                f"baseline regression in {', '.join(failed)}")
        (results / "matrix-pass").touch()
        for disk in results.glob("*.qcow2"):
            disk.unlink()
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            ValueError) as error:
        print(f"\nMATRIX-FAIL: {error}", file=sys.stderr)
        print(f"Artifacts: {results}", file=sys.stderr)
        return 1

    if all(digests):
        print(f"Cross-profile Doom output: {digests[0]}")
    print(f"\nMATRIX-PASS: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
