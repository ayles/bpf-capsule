# Clean-kernel regression VMs

`check.nix` defines the standard functional current-kernel (arena tier) and
Linux 5.15 (map tier) VM
tests. They consume immutable Nix packages directly and require no host BPF or
KVM setup:

```sh
nix flake check
```

For real-machine timings rather than functional VM checks, run
`nix run .#benchmarks`.

The optional benchmark app uses `vm-arena.nix` and `vm.nix` to boot the same
profiles with hardware acceleration. Its writable share contains only copies
of the immutable artifacts, a JSON argument list and result files. Kernel,
build and Nix logs are retained in the reported cache directory.

Nix fetches the pinned, freely redistributable Freedoom Phase 1 WAD and creates
tiny deterministic llama fp32 and Q8 fixtures. The benchmark app accepts
`DOOM_WAD`, `LLAMA2_MODEL` and `LLAMA2Q_MODEL` overrides; `none` skips that
case. The functional checks always use the pinned fixtures.
