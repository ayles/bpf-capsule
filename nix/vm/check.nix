# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Run every installed GTest binary of one tests package as root in a real
# kernel. Each binary embeds the exact BPF object it loads.
{
  pkgs,
  tests,
  kernelPackages,
  profileKernel,
  disableDeviceTree ? false,
}:
import ./run.nix {
  inherit pkgs kernelPackages disableDeviceTree;
  name = "bpf-capsule-profile-${profileKernel}-linux-${kernelPackages.kernel.version}";
  runtimeInputs = [ pkgs.coreutils ];
  script = ''
    ulimit -l unlimited
    uname -a

    test_dir=${tests}/libexec/bpf-capsule/tests
    [[ -x "$test_dir/smoke_test" ]]
    for test_program in "$test_dir"/*_test; do
      printf 'RUN:%s\n' "$test_program"
      "$test_program" --gtest_color=no
    done
  '';
}
