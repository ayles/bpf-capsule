# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# One NixOS VM booting the given kernel and running a Bash script as root.
{
  pkgs,
  kernelPackages,
  name,
  script,
  runtimeInputs ? [ ],
  disableDeviceTree ? false,
}:
let
  runner = pkgs.writeShellApplication {
    inherit name runtimeInputs;
    text = script;
  };
in
pkgs.testers.runNixOSTest {
  inherit name;

  nodes.machine =
    { lib, pkgs, ... }:
    {
      boot.kernelPackages = kernelPackages;
      virtualisation = {
        memorySize = 6144;
        cores = 6;
        graphics = false;
      };
      system.stateVersion = "23.11";
    }
    // lib.optionalAttrs disableDeviceTree {
      # QEMU's generated device tree is enough. Enabling NixOS device-tree
      # synthesis on aarch64 has historically dropped the arena kfunc set.
      hardware.deviceTree.enable = false;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    print(machine.succeed("${runner}/bin/${name}"))
    machine.shutdown()
  '';
}
