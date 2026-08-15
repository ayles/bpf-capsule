# Regression benchmarks

`regression.py` is the single entry point for correctness and performance
tracking. It configures and builds every proof program, runs each workload in a
fresh process, requires its correctness marker, and records:

- native and BPF execution time plus their ratio;
- direct-BPF versus transformed-BPF cost for the C and Rust classifiers;
- verifier/load time and JIT size where the host exposes them;
- ELF text, data, BSS and complete object sizes;
- entry/drain counts, process wall time, kernel/profile and Git state.

The concise table is followed by a machine-readable JSON report. The release
regression command builds the 6.9 arena and 5.15 map compile profiles, boots a
clean current kernel for the arena objects and a clean 5.15-series kernel for
the map objects, and runs every available case:

```sh
nix flake check
```

This is the reproducible correctness gate: it builds fresh artifacts and boots
disposable current-kernel and Linux 5.15-series VMs. The policy/coordinator unit tests are
part of the same command and do not require a BPF-capable kernel themselves.
For retained reports and comparison with the newest local baseline, run:

```sh
nix run .#benchmarks
```

The newest complete local matrix is selected automatically as the baseline. A
first run establishes it. Correctness markers and output must match, and every
canonical non-timing metric must match exactly: BPF object hashes, entry/drain counts, verifier
processed/static instruction counts and expansion, executable BPF bytes, and
JIT bytes. An intentional change requires reviewing and replacing the
baseline; there is no percentage allowance. Complete ELF size remains
reported but is not canonical because DWARF, BTF and relocation encoding can
change without changing loaded code.

Execution and load timings are always printed with paired old/new deltas but
never make comparison pass or fail. Follow the same-host old/new protocol in
[`PERFORMANCE.md`](PERFORMANCE.md) before drawing a performance conclusion.
Reports, build logs, VM logs and the exact staged inputs are retained under a
timestamped `benchmark-results` directory. Set `BPF_CAPSULE_BASELINE_DIR` to
compare with a baseline directory restored from a previous run (for example a
CI artifact), or `BPF_CAPSULE_NO_BASELINE=1` to deliberately establish a new
machine baseline.

Each VM run is bounded by `BPF_CAPSULE_VM_TIMEOUT` (seconds, default 7200); a
guest that exceeds it is killed and its profile fails cleanly. On a fully
successful matrix run the per-run qcow2 disk images (about 2 GB each) are
deleted; a failed run keeps them for debugging.

On heterogeneous CPUs (big.LITTLE), set `BPF_CAPSULE_VM_CPUS` to a fixed CPU
list (for example `6-11`, passed to `taskset -c`) so every matrix measures on
the same core type. When it is set and passwordless sudo is available, those
cores are also held at the performance governor for the duration: the suite's
sub-millisecond cases run far below the utilization `schedutil` needs to
leave the idle frequency, so an unpinned run can measure identical code up to
2x slower depending on nothing but thermal history. Previous governors are
restored on exit.

Every case uses the requested sample count. Doom uses at least two fresh
processes because identical output across processes is a correctness check,
not timing stabilization. Set `BPF_CAPSULE_SAMPLES` or pass `--samples` when
collecting repeated timing observations.

For a faster development iteration on the running kernel only:

```sh
nix develop -c python3 benchmarks/regression.py --profile 6.9
```

The default build directory is `build-regression`. Reuse an existing build and
collect three fresh-process samples with:

```sh
nix develop -c python3 benchmarks/regression.py \
  --build build-regression --no-build --samples 3
```

Pass a prior JSON report to compare canonical metrics and print paired timing
observations:

```sh
nix develop -c python3 benchmarks/regression.py --no-build \
  --baseline results/aarch64-linux-6.9.json
```

Timing comparisons are meaningful only under the protocol in
[`PERFORMANCE.md`](PERFORMANCE.md). The report records the machine and kernel
so a mismatched comparison is visible.

`--profile 5.15` generates the compatibility object, but an authoritative 5.15
result must run inside the `.#vm-515` environment described in
[`tests/vm`](../tests/vm/README.md). The same runner is used inside that VM;
there is no second benchmark implementation.

Set `BPF_CAPSULE_SAMPLES` to control measurement repetition in the VM matrix;
this affects the harness, never compiler decisions or generated code. For a
local `regression.py` build, use its `--jobs` option to select build
parallelism. Matrix artifacts are immutable Nix packages rather than mutable
build trees.

The Doom and both llama cases run by default. The matrix fetches the free
Freedoom Phase 1
WAD through `tools/fetch-doom-wad.sh` (pinned by SHA-256, cached locally)
unless `DOOM_WAD` points at another IWAD or is set to `none` to skip the
case. Doom initialization and every subsequent frame reject `CAPSULE_PENDING`;
there is no continuation loop to measure. Real-library hosts that do contain
such a loop report and require zero userspace drains on both targets. The
llama tests use tiny valid fp32 and Q8 checkpoints generated locally by
`tools/generate-llama-fixtures.py`. `LLAMA2_MODEL` and `LLAMA2Q_MODEL`
replace them with real checkpoints; setting either variable to `none` skips
that case. No checkpoint is downloaded or committed.

Pixel output remains enabled. The runner hashes every PPM name and byte from a
clean output directory and requires identical output from at least two fresh
processes, independently of the requested global sample count. The outer
matrix also requires the 6.9 arena and 5.15 map profiles to produce the
same digest.
