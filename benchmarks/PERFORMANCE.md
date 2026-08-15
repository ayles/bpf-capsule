# Performance measurement

Timing values are observations, not regression-test constants. They depend on
the host, CPU state, kernel, JIT, toolchain and surrounding load. Do not add an
absolute time or percentage threshold to a test, benchmark executable or the
regression runner.

To evaluate a performance change, measure the old and new revisions on the
same machine with the same kernel/profile, toolchain, build options, inputs,
CPU set and governor. Prefer separate clean worktrees, alternate old and new
runs close together, and use the same explicit sample count. Keep both JSON
reports and record anything that can affect CPU or kernel state. The runner
prints paired timing values and deltas, but a person must judge their noise and
repeatability.

Use deltas of `bpf_prog_info.run_time_ns` with kernel BPF statistics enabled
for both `BPF_PROG_TEST_RUN` and live attached workloads. Sum the entry and
continuation-program deltas belonging to one logical operation. This is the
project's canonical in-kernel execution-time source. The duration returned in
`bpf_test_run_opts` is useful for diagnosing one test-run call, but is not the
cross-example timing contract. Process wall time remains an end-to-end
diagnostic, not a proxy for executed BPF time. External tools such as `perf`
and `bpftool prog profile` are optional diagnostics, not required benchmark
dependencies.

Userspace eBPF VM instruction counts can be useful as an additional stable
compiler metric. They are not a performance substitute: a VM does not model
the kernel JIT, helpers, maps, cache behavior or backend-specific memory
costs.

Non-timing compiler/runtime metrics are canonical. Entry and drain counts,
verifier processed/static instruction counts and their expansion ratio,
executable BPF bytes, and JIT bytes must exactly match the selected baseline.
Any change, including an improvement, fails comparison until it is reviewed
and the baseline is deliberately replaced. Complete ELF size stays
informational because it includes debug, BTF and relocation representation
that is not loaded executable code.
