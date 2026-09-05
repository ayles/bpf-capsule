# Kernel proof matrix

The compiler's unprivileged CTest suite proves exact IR, MIR, ELF, packaging,
and host-ABI contracts. The NixOS tests defined in [`nix/vm`](../../nix/vm)
provide the missing kernel evidence: they boot an isolated kernel and run every
installed GTest binary as root.
Each binary embeds the exact BPF object it loads, so there is no second staging
protocol or list of hand-maintained object names.

The flake pairs the fixed-memory code generators with Linux 5.15 and 6.6.
Newer targets run on the current pinned kernel. Arm64 additionally exercises
the 5.18 v3 managed-atomics path, 6.9 fixed memory with the atomic allocator
lock, and the 6.10 arena path with signed-load lowering; x86-64 exercises v3
managed atomics on the 5.15 kernel and reaches the arena path at 6.9. The
example VM uses the architecture's arena profile. Profiles with BPF trampoline
support also load compiler-generated `freplace` roots through the Lua contract,
including the fixed-memory tier. The Linux 7.1 `gotox` target is compiled and
runs in the matrix when the pinned kernel is 7.1 or newer.
