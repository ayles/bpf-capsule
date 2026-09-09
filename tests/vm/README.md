# Kernel proof matrix

The compiler's unprivileged CTest suite proves exact IR, MIR, ELF, packaging,
and host-ABI contracts. The NixOS tests defined in [`nix/vm`](../../nix/vm)
provide the missing kernel evidence: they boot an isolated kernel and run every
installed GTest binary as root.
Each binary embeds the exact BPF object it loads, so there is no second staging
protocol or list of hand-maintained object names.

Every kernel version at which a target capability appears is its own profile:
5.15, 5.18, 6.0, 6.6, 6.9, 6.10 and 7.0. Each boots the closest packaged
kernel that can run the code it generates, so 5.18 and 6.0 prove their code
shapes on 6.1 rather than an exact minimum. Arm64 gains v3 atomics at 5.18,
`freplace` at 6.0 and arena at 6.10; x86-64 has both from its floor and
reaches arena at 6.9. Eligible profiles also test `freplace` through the Lua
contract, including its host allocator entry. Host-allocation tests cover
concurrent requests, cross-side frees and fiber exhaustion.

Every profile also builds and runs the examples, checking results and
continuation counts; the script examples and DOOM run natively with
`--native` too, and their output or frames must match the kernel run exactly.
Profiles with arena, `freplace` and full atomics run both CPython forms,
including live XDP traffic and simultaneous packet test runs on two CPUs.
GitHub CI runs on x86-64; `nix flake check` on arm64 runs the corresponding
native ARM matrix.
