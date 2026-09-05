# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{ lib }:
{
  kernel ? null,
  arch,
}:
let
  supportedArch = lib.elem arch [
    "aarch64"
    "x86_64"
  ];
  # Defaults are the oldest kernels with the fast arena backend on the build
  # architecture. Explicit compatibility builds still select their floor.
  defaultKernel = if arch == "aarch64" then "6.10" else "6.9";
  selectedKernel = if kernel == null then defaultKernel else kernel;
  atLeast = lib.versionAtLeast selectedKernel;
  cpu = if atLeast "6.6" then "v4" else "v3";
  # Arena was initially x86-64-only in 6.9; arm64 support followed in 6.10.
  arena = atLeast (if arch == "aarch64" then "6.10" else "6.9");
  fullAtomics = atLeast "6.9";
  # The x86-64 JIT supported the complete v3 atomic set before our kernel
  # floor; arm64 added everything beyond atomic add in Linux 5.18.
  managedAtomics = arch == "x86_64" || atLeast "5.18";
  # Program extensions need architecture-specific BPF trampolines: x86-64
  # had them before Capsule's kernel floor, arm64 gained them in Linux 6.0.
  freplace = atLeast (if arch == "aarch64" then "6.0" else "5.6");
  nativeArenaSignedLoads = arena && atLeast "7.0";
  indirectJumps = arena && atLeast "7.1";
in
assert lib.assertMsg supportedArch "BPF Capsule has no target profile for ${arch}";
assert lib.assertMsg (atLeast "5.15") "BPF Capsule requires Linux 5.15 or newer";
{
  inherit arena freplace managedAtomics;
  kernel = selectedKernel;

  linkOptions = [
    "-mcpu=${cpu}"
    "--memory=${if arena then "arena" else "fixed"}"
  ]
  ++ lib.optional managedAtomics "--managed-atomics"
  ++ lib.optional fullAtomics "--allocator-lock=atomic"
  ++ lib.optional nativeArenaSignedLoads "--native-arena-signed-loads"
  ++ lib.optional indirectJumps "--indirect-jumps"
  ++ lib.optional (arch != "aarch64") "--native-shift63";
}
