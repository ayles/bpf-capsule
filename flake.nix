# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        llvmPackages = pkgs.llvmPackages_23;
        bpfCapsule = pkgs.callPackage ./nix/bpf-capsule.nix { inherit llvmPackages; };
        matrix = pkgs.callPackage ./nix/matrix.nix {
          inherit llvmPackages bpfCapsule;
        };
        benchmarks = pkgs.callPackage ./nix/benchmarks.nix { suite = matrix.benchmarkSuite; };
      in
      {
        packages = {
          default = bpfCapsule;
          bpf-capsule = bpfCapsule;
          bpf-capsule-cc = bpfCapsule // {
            pname = "bpf-capsule-cc";
            name = "bpf-capsule-cc-${bpfCapsule.version}";
          };
          bpf-capsule-ld = bpfCapsule // {
            pname = "bpf-capsule-ld";
            name = "bpf-capsule-ld-${bpfCapsule.version}";
          };
          llama2-q8 = matrix.examplesOldest.llama2 // {
            pname = "llama2-q8";
            name = "llama2-q8-${matrix.examplesOldest.llama2.version}";
          };
          inherit benchmarks;
        }
        # Plain names build for the oldest supported kernel, so `nix run` works
        # on any supported machine; CPython exists only on arena profiles.
        // matrix.examples
        // matrix.examplesOldest
        # `<example>-<kernel floor>` selects a profile: lua-71, doom-515.
        // pkgs.lib.concatMapAttrs (
          kernel: examples:
          pkgs.lib.mapAttrs' (name: package: pkgs.lib.nameValuePair "${name}-${kernel}" package) examples
        ) matrix.examplesByKernel;

        checks = matrix.checks // {
          format = pkgs.callPackage ./nix/format.nix { inherit llvmPackages; };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [
            bpfCapsule
            matrix.checks.suite-default
            matrix.benchmarkSuite
            matrix.examples.wasm3
            matrix.examples.rust
          ];
          packages = [ pkgs.gersemi ];
        };
      }
    );
}
