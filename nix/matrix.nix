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
  linuxPackages_6_6,
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
    lib.genAttrs
      [
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
      (
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
  suites = {
    "5.15" = suiteFor "5.15";
    "5.18" = suiteFor "5.18";
    "6.6" = suiteFor "6.6";
    "6.9" = suiteFor "6.9";
    "6.10" = suiteFor "6.10";
    "7.0" = suiteFor "7.0";
    "7.1" = suiteFor "7.1";
  };
  benchmarkSuite = callPackage ./benchmark-suite.nix {
    inherit bpfCapsule;
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
  # The examples as ordinarily run: the oldest arena profile for this
  # architecture (6.9 on x86-64, 6.10 on arm64).
  examples = examplesFor defaultKernel;
  inherit benchmarkSuite;

  # Everything exported through the flake's standard `checks` output.
  checks = {
    suite-515 = suites."5.15";
    suite-66 = suites."6.6";
    suite-69 = suites."6.9";
    suite-70 = suites."7.0";
    suite-71 = suites."7.1";
    suite-default = suites.${defaultKernel};
    benchmark-suite = benchmarkSuite;
    vm-515 = vm "5.15" linuxPackages_5_15;
    vm-66 = vm "6.6" linuxPackages_6_6;
    vm-69 = vm "6.9" linuxPackages_latest;
    vm-70 = vm "7.0" linuxPackages_latest;
    examples-vm-515 = examplesVm "5.15" linuxPackages_5_15;
    examples-vm-default = examplesVm defaultKernel linuxPackages_latest;
  }
  // lib.optionalAttrs (stdenv.hostPlatform.parsed.cpu.name == "aarch64") {
    suite-518 = suites."5.18";
    suite-610 = suites."6.10";
    vm-518 = vm "5.18" linuxPackages_latest;
    vm-610 = vm "6.10" linuxPackages_latest;
  }
  // lib.optionalAttrs (lib.versionAtLeast linuxPackages_latest.kernel.version "7.1") {
    vm-71 = vm "7.1" linuxPackages_latest;
  };
}
