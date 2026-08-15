# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{ arenaKernelPackages, lib, ... }:
{
  imports = [ ./vm.nix ];

  # The arena tier compiles for the 6.9 arena feature ABI, but on arm64 the
  # arena features it relies on land across several kernels (basic arena JIT
  # 6.10; sign-extending arena loads and sleepable-alloc-from-XDP only ~7.0 —
  # 6.12 rejects both). The full arena tier this compiler emits therefore needs
  # ~7.0 on arm64, so it is proved on the current kernel rather than a literal
  # 6.x that supports only a subset.
  boot.kernelPackages = lib.mkForce arenaKernelPackages;
}
