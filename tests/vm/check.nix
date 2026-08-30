# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  pkgs,
  artifacts,
  kernelPackages,
  targetKernel,
  arena ? false,
}:
pkgs.testers.runNixOSTest {
  name = "bpf-capsule-${builtins.replaceStrings [ "." ] [ "" ] targetKernel}";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      boot.kernelPackages = kernelPackages;
      virtualisation = {
        memorySize = 6144;
        cores = 6;
        graphics = false;
      };
      environment.systemPackages = with pkgs; [
        bpftools
        libbpf
      ];
      system.stateVersion = "23.11";
    }
    // lib.optionalAttrs arena {
      # QEMU's generated device tree is enough. Enabling NixOS device-tree
      # synthesis on aarch64 has historically dropped the arena kfunc set.
      hardware.deviceTree.enable = false;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    print(machine.succeed("uname -a"))
    print(machine.succeed(
      "set -eu; ulimit -l unlimited; "
      "test_dir=${artifacts}/libexec/bpf-capsule/tests; "
      "test -x $test_dir/smoke_test; "
      "for test_program in $test_dir/*_test; do "
      "  echo RUN:$test_program; "
      "  $test_program --gtest_color=no; "
      "done"
    ))
    machine.shutdown()
  '';
}
