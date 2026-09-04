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
          llama2-q8 = matrix.examples.llama2 // {
            pname = "llama2-q8";
            name = "llama2-q8-${matrix.examples.llama2.version}";
          };
          inherit benchmarks;
        }
        // matrix.examples;

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
