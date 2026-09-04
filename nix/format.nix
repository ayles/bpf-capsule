# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Formatting is a check because nothing else runs the formatters. Generated,
# vendored, and IR/MIR fixtures are deliberately outside their input sets.
{
  lib,
  runCommand,
  llvmPackages,
  gersemi,
  nixfmt,
}:
runCommand "bpf-capsule-format"
  {
    nativeBuildInputs = [
      llvmPackages.clang-unwrapped
      gersemi
      nixfmt
    ];
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../.clang-format
        ../.gersemirc
        ../CMakeLists.txt
        ../cmake
        ../src
        ../tools
        ../tests
        ../examples
        ../benchmarks
        (lib.fileset.fileFilter (file: file.hasExt "nix") ../.)
      ];
    };
  }
  ''
    export HOME="$TMPDIR"
    cd "$src"
    find src tools tests examples benchmarks \
      \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) -print0 \
      | xargs -0 clang-format --dry-run -Werror
    gersemi --check .
    find . -name '*.nix' -print0 | xargs -0 nixfmt --check
    touch "$out"
  ''
