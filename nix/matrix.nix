# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Examples, benchmarks and checks built against one shared SDK. A kernel number
# here is a code-generation capability floor; the VM may boot a newer kernel.
{
  lib,
  stdenv,
  callPackage,
  llvmPackages,
  bpfCapsule,
  linuxPackages_5_15,
  linuxPackages_6_1,
  linuxPackages_6_6,
  linuxPackages_6_12,
  linuxPackages_latest,
}:
let
  profileFor =
    targetKernel:
    import ./target-profile.nix { inherit lib; } {
      kernel = targetKernel;
      arch = stdenv.hostPlatform.parsed.cpu.name;
    };
  defaultProfile = profileFor null;
  defaultKernel = defaultProfile.kernel;
  examplesFor =
    targetKernel:
    let
      profile = profileFor targetKernel;
      names = [
        "fib"
        "zlib"
        "sqlite"
        "lua"
        "lua-xdp"
        "wasm3"
        "llama2"
        "quickjs"
        "rust"
        "doom"
      ]
      # CPython's large sparse heap is practical only with arena memory. The
      # fixed tier still exercises freplace through the Lua contract tests.
      ++ lib.optionals (profile.arena && profile.freplace && profile.managedAtomics) [
        "python"
        "python-xdp"
      ];
    in
    lib.genAttrs names (
      example:
      callPackage ./example.nix {
        inherit
          llvmPackages
          bpfCapsule
          example
          targetKernel
          ;
      }
    );
  suiteFor = targetKernel: callPackage ./tests.nix { inherit llvmPackages bpfCapsule targetKernel; };
  # Every kernel version at which a target feature flips, mapped to the
  # closest nixpkgs kernel that can boot the code that profile generates.
  # A profile is a capability floor: 5.18 and 6.0 have no packaged kernel,
  # so their code runs on the next one that does.
  profileKernels = {
    "5.15" = linuxPackages_5_15;
    "5.18" = linuxPackages_6_1;
    "6.0" = linuxPackages_6_1;
    "6.6" = linuxPackages_6_6;
    "6.9" = linuxPackages_6_12;
    "6.10" = linuxPackages_6_12;
    "7.0" = linuxPackages_latest;
  };
  suites = lib.mapAttrs (kernel: _: suiteFor kernel) profileKernels;
  benchmarkSuite = callPackage ./benchmark-suite.nix {
    inherit bpfCapsule llvmPackages;
    targetKernel = defaultKernel;
  };
  # The historical 5.15 and 6.6 kernels are available from nixpkgs. Newer
  # profiles run on linuxPackages_latest and therefore prove their generated
  # code shape, not the exact stated kernel floor.
  vm =
    profileKernel: kernelPackages:
    callPackage ./vm/check.nix {
      inherit profileKernel kernelPackages;
      disableDeviceTree = (profileFor profileKernel).arena && stdenv.hostPlatform.isAarch64;
      tests = suites.${profileKernel};
    };
  examplesVm =
    profileKernel: kernelPackages:
    callPackage ./vm/examples.nix {
      inherit profileKernel kernelPackages;
      disableDeviceTree = (profileFor profileKernel).arena && stdenv.hostPlatform.isAarch64;
      examples = examplesFor profileKernel;
    };
in
{
  # The examples for the oldest arena profile of this architecture (6.9 on
  # x86-64, 6.10 on arm64): the profile the checks and the benchmarks use.
  examples = examplesFor defaultKernel;
  # The examples for the oldest supported kernel, runnable everywhere; CPython
  # needs arena memory and is absent here.
  examplesOldest = examplesFor "5.15";
  # Every profile, keyed by its kernel floor without the dot: `lua-71`.
  examplesByKernel = lib.mapAttrs' (
    kernel: _: lib.nameValuePair (lib.replaceStrings [ "." ] [ "" ] kernel) (examplesFor kernel)
  ) suites;
  inherit benchmarkSuite;

  # Everything exported through the flake's standard `checks` output: every
  # profile's compiler tests, its in-kernel tests, and its examples, so a
  # feature that only one kernel floor enables cannot regress unnoticed.
  checks =
    lib.concatMapAttrs (
      kernel: kernelPackages:
      let
        key = lib.replaceStrings [ "." ] [ "" ] kernel;
      in
      {
        "suite-${key}" = suites.${kernel};
        "vm-${key}" = vm kernel kernelPackages;
        "examples-vm-${key}" = examplesVm kernel kernelPackages;
      }
    ) profileKernels
    // {
      suite-default = suites.${defaultKernel};
      benchmark-suite = benchmarkSuite;
    };
}
