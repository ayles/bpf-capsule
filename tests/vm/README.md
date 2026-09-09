# Kernel proof matrix

The compiler's unprivileged CTest suite proves exact IR, MIR, ELF, packaging,
and host-ABI contracts. The NixOS tests defined in [`nix/vm`](../../nix/vm)
provide the missing kernel evidence: they boot an isolated kernel and run every
installed GTest binary as root.
Each binary embeds the exact BPF object it loads, so there is no second staging
protocol or list of hand-maintained object names.

On both architectures, the 5.15 and 6.6 profiles boot those kernel series;
other profiles boot the latest pinned kernel and test code-generation shapes,
not their exact minimum kernel versions. Arm64 adds the 5.18 v3 atomic path,
6.9 fixed memory with atomic allocator locking, and 6.10 arena with signed-load
lowering. x86-64 tests v3 atomics on 5.15 and reaches arena at 6.9. The 7.1
`gotox` shape runs when the pinned kernel is new enough. Eligible profiles also
test `freplace` through the Lua contract, including its host allocator entry.
Host-allocation tests cover concurrent requests, cross-side frees and fiber
exhaustion.

Examples run on both Linux 5.15 and the default arena profile, checking results
and continuation counts; the script examples and DOOM also run natively with
`--native`, and their output or frames must match the kernel run exactly. The default arena VM also runs both CPython forms,
including live XDP traffic and simultaneous packet test runs on two CPUs.
GitHub CI runs on x86-64; `nix flake check` on arm64 runs the corresponding
native ARM matrix.
