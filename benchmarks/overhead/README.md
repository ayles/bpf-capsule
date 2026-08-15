# Integer C and Rust eBPF overhead benchmarks

These tests separate inherent eBPF/JIT cost from the cost introduced by this
project's transformation pipeline. The C `workload.h` and no-std Rust
`rust_workload.rs` workloads are each compiled three ways:

1. as ordinary optimized native code in `overhead_host`;
2. by stock Clang directly to eBPF in `overhead_direct.o`, without the project
   passes or runtime;
3. through the complete project pipeline in `overhead_transformed.o`.

The C benchmark additionally compares the default portable max-512 object
with a max-64 object at the same pre-load selected count (`min(nproc, 64)`).
It times both the complete workload and an empty Capsule call, and reports
fixed-tier backing capacity after pre-load resizing. Timing is observational;
see [`benchmarks/PERFORMANCE.md`](../PERFORMANCE.md) for the comparison
protocol.

Each workload classifies 16 fixed 128-byte Ethernet packets. It handles VLAN
and IPv4 headers, TCP/UDP ports, bounded TCP options, and computes a 48-byte
payload fingerprint. The timed logic is integer-only and performs no
allocation, logging, floating-point emulation, or BPF helper calls. The Rust
test uses one Rust source file for all three variants rather than comparing a
Rust transform against a separately written C baseline.

Both eBPF variants run through `BPF_PROG_TEST_RUN`. The host reports the best
of five trials and subtracts an identically loaded empty program's wall time
to remove syscall/test-run overhead. It also checks the digest against native
execution and reports `jited_prog_len`, proving that the kernel JIT was used.

The project regression runner builds and runs both variants, validates their
results, and includes these metrics in the common JSON report:

```sh
nix develop -c python3 benchmarks/regression.py --profile 6.9
```

Use `--case overhead-c --case overhead-rust` to run only these two benchmarks
from an existing build. See [`benchmarks/README.md`](../README.md) for baseline
comparison and the two-kernel VM matrix.

The transform's own cost is isolated by comparing the transformed program to
the direct-eBPF build of the same source (both run in-kernel), and the eBPF
cost is isolated by comparing the direct build to native. Automatic native
retention of bounded loops and compact scalar call islands is intended to keep
the continuation machinery off this workload's hot path. Current figures are
produced by the reproducible two-kernel matrix (see
[`benchmarks/README.md`](../README.md)); run paired revisions rather than
quoting a fixed ratio because results depend on the host and execution kernel.
