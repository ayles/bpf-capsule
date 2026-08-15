# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  pkgs,
  source,
  artifacts,
  freedoomWad,
  kernelPackages,
  profile,
}:
let
  build = "${artifacts}/libexec/bpf-capsule";
in
pkgs.testers.runNixOSTest {
  name = "bpf-capsule-${builtins.replaceStrings [ "." ] [ "" ] profile}";

  nodes.machine =
    { pkgs, lib, ... }:
    {
      boot.kernelPackages = kernelPackages;
      boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 0;
      virtualisation = {
        memorySize = 6144;
        cores = 6;
        graphics = false;
      };
      environment.systemPackages = with pkgs; [
        bpftools
        elfutils
        libbpf
        python3
        zlib
      ];
      system.stateVersion = "23.11";
    }
    // lib.optionalAttrs (profile == "6.9") {
      hardware.deviceTree.enable = false;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed(
      "ulimit -l unlimited; "
      "${pkgs.python3}/bin/python3 ${source}/benchmarks/regression.py "
      "--build ${build} --profile ${profile} --samples 1 --no-build "
      "--build-seconds 0 --output /tmp/bpf-capsule-report.json "
      "--doom-wad ${freedoomWad}/freedoom1.wad "
      "--llama2-model ${build}/examples/llama2/llama2-tiny.bin "
      "--llama2q-model ${build}/examples/llama2/llama2q-tiny.bin"
    )
    machine.succeed("test -s /tmp/bpf-capsule-report.json")
    # Surface the structured measurements in the build log so a green gate is
    # inspectable without rerunning the workloads. Printed via succeed()/cat
    # (portable across NixOS test-driver versions); the report is a convenience
    # artifact, not the correctness gate (the regression.py succeed() above is).
    print(machine.succeed("cat /tmp/bpf-capsule-report.json"))
    machine.shutdown()
  '';
}
