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
        lib = pkgs.lib;
        llvmPkgs = pkgs.llvmPackages_23;
        latestKernel = pkgs.linuxPackages_latest.kernel.version;
        mkPackage = arguments: pkgs.callPackage ./package.nix ({ llvmPackages = llvmPkgs; } // arguments);
        mkTests = targetKernel: mkPackage {
          inherit targetKernel;
          buildTests = true;
        };
        mkExamples = targetKernel: mkPackage {
          inherit targetKernel;
          buildExamples = true;
        };
        exampleNames = [
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
        ];
        examplePackages = lib.genAttrs exampleNames (example: mkPackage {
          inherit example;
          targetKernel = "6.9";
        });
        exampleApp = package: executable: description: {
          type = "app";
          program = "${package}/libexec/bpf-capsule/examples/${executable}";
          meta = { inherit description; };
        };
        llamaFixtures = pkgs.runCommand "bpf-capsule-llama-fixtures" {
          nativeBuildInputs = [ pkgs.python3 ];
        } ''
          ${pkgs.python3}/bin/python3 ${./tests/vm/generate-llama-fixtures.py} "$out"
        '';
        freedoomArchive = pkgs.fetchurl {
          url = "https://github.com/freedoom/freedoom/releases/download/v0.13.0/freedoom-0.13.0.zip";
          hash = "sha256-P5smTz485QO0+39r3LH0Gdk8e1RvTfPodN2Hjbloj1k=";
        };
        doomWad = pkgs.runCommand "bpf-capsule-freedoom1-wad" {
          nativeBuildInputs = [ pkgs.unzip ];
        } ''
          mkdir -p "$out"
          unzip -p ${freedoomArchive} 'freedoom-0.13.0/freedoom1.wad' > "$out/freedoom1.wad"
          echo '7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d  '"$out/freedoom1.wad" | sha256sum --check --status
        '';
        testPackages = {
          tests-515 = mkTests "5.15";
          tests-66 = mkTests "6.6";
          tests-69 = mkTests "6.9";
          tests-70 = mkTests "7.0";
          tests-71 = mkTests "7.1";
        };
        vmCheck = targetKernel: kernelPackages: artifacts: arena:
          import ./tests/vm/check.nix {
            inherit pkgs targetKernel kernelPackages artifacts arena;
          };
        exampleVmCheck = targetKernel: kernelPackages: examples: arena:
          import ./tests/vm/examples.nix {
            inherit pkgs targetKernel kernelPackages examples arena llamaFixtures doomWad;
          };
      in
      {
        packages = {
          default = mkPackage { };
          examples-515 = mkExamples "5.15";
          examples-69 = mkExamples "6.9";
        } // testPackages // examplePackages;

        apps = rec {
          default = fib;
          fib = exampleApp examplePackages.fib "fib/fib" "Run the recursive Fibonacci example";
          zlib = exampleApp examplePackages.zlib "zlib/zlib" "Run zlib inside BPF";
          sqlite = exampleApp examplePackages.sqlite "sqlite/sqlite" "Run SQLite inside BPF";
          lua = exampleApp examplePackages.lua "lua/lua" "Run Lua inside BPF";
          lua-xdp = exampleApp examplePackages.lua-xdp "lua-xdp/lua-xdp" "Attach the Lua XDP observer";
          wasm3 = exampleApp examplePackages.wasm3 "wasm3/wasm3" "Run wasm3 inside BPF";
          llama2 = exampleApp examplePackages.llama2 "llama2/llama2" "Run llama2.c inside BPF";
          llama2-q8 = exampleApp examplePackages.llama2 "llama2/llama2q" "Run quantized llama2.c inside BPF";
          quickjs = exampleApp examplePackages.quickjs "quickjs/quickjs" "Run QuickJS inside BPF";
          rust = exampleApp examplePackages.rust "rust/rust" "Run the no_std Rust example";
          doom = exampleApp examplePackages.doom "doom/doom" "Run PureDOOM inside BPF";
        };

        checks = {
          build-515 = testPackages.tests-515;
          build-66 = testPackages.tests-66;
          build-69 = testPackages.tests-69;
          build-70 = testPackages.tests-70;
          build-71 = testPackages.tests-71;
          examples-515 = mkExamples "5.15";
          examples-69 = mkExamples "6.9";
          examples-vm-515 = exampleVmCheck "5.15" pkgs.linuxPackages_5_15 (mkExamples "5.15") false;
          examples-vm-69 = exampleVmCheck "6.9" pkgs.linuxPackages_latest (mkExamples "6.9") true;
          vm-515 = vmCheck "5.15" pkgs.linuxPackages_5_15 testPackages.tests-515 false;
          vm-66 = vmCheck "6.6" pkgs.linuxPackages_6_6 testPackages.tests-66 false;
          # The 6.9 and 7.0 compiler profiles exercise different arena
          # legalization pipelines. Both run on the pinned current kernel;
          # see tests/vm/README.md for the aarch64 compatibility reason.
          vm-69 = vmCheck "6.9" pkgs.linuxPackages_latest testPackages.tests-69 true;
          vm-70 = vmCheck "7.0" pkgs.linuxPackages_latest testPackages.tests-70 true;
        } // lib.optionalAttrs (lib.versionAtLeast latestKernel "7.1") {
          vm-71 = vmCheck "7.1" pkgs.linuxPackages_latest testPackages.tests-71 true;
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cmake
            ninja
            pkg-config
            bpftools
            llvmPkgs.libllvm
            llvmPkgs.clang-unwrapped
            cargo
            rustc
            csmith
            python3
          ];
          buildInputs = with pkgs; [
            libbpf
            gtest
            gbenchmark
            zlib
          ];
        };
      }
    );
}
