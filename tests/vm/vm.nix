# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{ config, pkgs, lib, modulesPath, ... }:
{
  imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

  boot.kernelPackages = pkgs.linuxPackages_5_15;

  virtualisation = {
    memorySize = 6144;
    cores = 6;
    diskSize = 2048;
    graphics = false;
  };

  services.getty.autologinUser = "root";
  users.users.root.password = "";
  security.sudo.wheelNeedsPassword = false;

  environment.systemPackages = with pkgs; [
    libbpf
    bpftools
    elfutils
    python3
    zlib
  ];

  # The generated runner mounts $SHARED_DIR at /tmp/shared. The static Python
  # guest driver consumes a JSON argument list; no generated shell or quoting
  # convention is part of the matrix protocol.
  systemd.services.vmscript = {
    wantedBy = [ "multi-user.target" ];
    unitConfig.RequiresMountsFor = "/tmp/shared";
    path = with pkgs; [
      bash
      coreutils
      gnugrep
      gnused
      libbpf
      bpftools
      elfutils
      python3
    ];
    serviceConfig = {
      Type = "oneshot";
      TimeoutStartSec = "0";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      ExecStart = "${pkgs.python3}/bin/python3 /tmp/shared/guest.py";
      ExecStopPost = "${pkgs.systemd}/bin/systemctl --force poweroff";
    };
  };

  boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 0;

  system.stateVersion = "23.11";
}
