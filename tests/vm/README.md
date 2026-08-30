# Kernel proof matrix

The compiler's unprivileged CTest suite proves exact IR, MIR, ELF, packaging,
and host-ABI contracts. These NixOS tests provide the missing kernel evidence:
they boot an isolated kernel and run every installed GTest binary as root.
Each binary embeds the exact BPF object it loads, so there is no second staging
protocol or list of hand-maintained object names.

The flake pairs the two fixed-memory code generators with Linux 5.15 and 6.6.
Arena targets run on the current pinned kernel: on aarch64 the arena feature
set used by Capsule arrived in pieces after the nominal Linux 6.9 ABI floor.
The Linux 7.1 `gotox` target is always compiled and joins the runtime matrix
automatically once the pinned nixpkgs supplies a 7.1-or-newer kernel.
