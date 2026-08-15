# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:

    # eBPF objects and the NixOS test VMs are Linux-only, and the nixosSystem
    # vm-* outputs cannot even evaluate on darwin, so the flake offers only
    # Linux systems.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # The arena tier compiles for the 6.9 arena feature ABI, but on arm64
        # the individual arena features land across several kernels: the JIT
        # gained basic arena in 6.10, and sign-extending arena loads plus
        # sleepable-alloc-from-XDP only work from ~7.0 (6.12 rejects both).
        # The full arena tier this compiler emits therefore requires ~7.0 on
        # arm64, so the arena leg is proved on the current kernel rather than a
        # literal 6.x that supports only a subset.
        arenaKernelPackages = pkgs.linuxPackages_latest;
        # One LLVM installation supplies clang, opt, llc, the pass plugin, and
        # formatting. Mixing majors is rejected by the CMake package.
        llvmPkgs = pkgs.llvmPackages_22;
        mkDirectApp =
          {
            package,
            executable,
            description ? "Run a BPF Capsule example",
          }:
          {
            type = "app";
            program = "${package}/${executable}";
            meta.description = description;
          };
        mkToolApp =
          {
            name,
            text,
            runtimeInputs ? [ ],
            description,
          }:
          let
            tool = pkgs.writeShellApplication { inherit name text runtimeInputs; };
          in
          {
            type = "app";
            program = "${tool}/bin/${name}";
            meta.description = description;
          };
        # Keep this release and digest in sync with tools/fetch-doom-wad.sh;
        # Nix records the same archive digest there in hexadecimal form.
        freedoomArchive = pkgs.fetchurl {
          url = "https://github.com/freedoom/freedoom/releases/download/v0.13.0/freedoom-0.13.0.zip";
          hash = "sha256-P5smTz485QO0+39r3LH0Gdk8e1RvTfPodN2Hjbloj1k=";
        };
        freedoomWad =
          pkgs.runCommand "freedoom1-wad-0.13.0"
            {
              nativeBuildInputs = with pkgs; [
                findutils
                unzip
              ];
            }
            ''
              mkdir -p "$out"
              unzip -q ${freedoomArchive} -d extracted
              wad=$(find extracted -name freedoom1.wad -print -quit)
              test -n "$wad"
              install -m644 "$wad" "$out/freedoom1.wad"
            '';
      in
      rec {
        packages.default = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
        };
        packages.matrix-arena = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          buildExamples = true;
          targetKernel = "6.9";
        };
        packages.matrix-515 = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          buildExamples = true;
          targetKernel = "5.15";
        };
        # The default all-examples build is exactly the oldest supported tier.
        packages.examples = packages.matrix-515;
        packages.freedoom-wad = freedoomWad;
        packages.fib = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "fib";
          targetKernel = "6.9";
        };
        packages.zlib = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "zlib";
          targetKernel = "6.9";
        };
        packages.wasm3 = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "wasm3";
          targetKernel = "6.9";
        };
        packages.lua = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "lua";
          targetKernel = "6.9";
        };
        packages.lua-xdp = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "lua-xdp";
          targetKernel = "6.9";
        };
        packages.quickjs = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "quickjs";
          targetKernel = "6.9";
        };
        packages.sqlite = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "sqlite";
          targetKernel = "6.9";
        };
        packages.rust = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "rust";
          targetKernel = "6.9";
        };
        packages.llama2 = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "llama2";
          targetKernel = "6.9";
        };
        packages.doom = pkgs.callPackage ./package.nix {
          llvmPackages = llvmPkgs;
          example = "doom";
          targetKernel = "6.9";
        };
        packages.vm-515 =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [ ./tests/vm/vm.nix ];
          }).config.system.build.vm;
        packages.vm-arena =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            specialArgs = { inherit arenaKernelPackages; };
            modules = [ ./tests/vm/vm-arena.nix ];
          }).config.system.build.vm;
        checks.matrix-arena = import ./tests/vm/check.nix {
          inherit pkgs freedoomWad;
          source = self;
          artifacts = packages.matrix-arena;
          kernelPackages = arenaKernelPackages;
          profile = "6.9";
        };
        checks.matrix-515 = import ./tests/vm/check.nix {
          inherit pkgs freedoomWad;
          source = self;
          artifacts = packages.matrix-515;
          kernelPackages = pkgs.linuxPackages_5_15;
          profile = "5.15";
        };
        checks.matrix-coordinator =
          pkgs.runCommand "bpf-capsule-matrix-coordinator"
            {
              nativeBuildInputs = [ pkgs.python3 ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              python3 -m unittest discover -s ${self}/tests/matrix -p 'test_*.py' -v
              python3 ${self}/benchmarks/test_regression.py -v
              touch "$out"
            '';
        checks.matrix-artifacts =
          pkgs.runCommand "bpf-capsule-matrix-artifacts"
            {
              nativeBuildInputs = [ pkgs.python3 ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              python3 ${self}/tests/matrix/check_artifacts.py \
                ${packages.matrix-arena} ${packages.matrix-515}
              touch "$out"
            '';
        checks.cmake-format =
          pkgs.runCommand "bpf-capsule-cmake-format"
            {
              nativeBuildInputs = [ pkgs.cmake-format ];
            }
            ''
              cd ${self}
              find . -type f \( -name CMakeLists.txt -o -name '*.cmake' \) -print0 \
                | sort -z \
                | xargs -0 cmake-format --check
              touch "$out"
            '';
        checks.source-format =
          pkgs.runCommand "bpf-capsule-source-format"
            {
              nativeBuildInputs = [
                llvmPkgs.clang-tools
                pkgs.cargo
                pkgs.rustfmt
              ];
            }
            ''
              cd ${self}
              find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' \) \
                ! -path './examples/wasm3/zlib_wasm_module.h' \
                ! -path './src/libc/tlsf.c' \
                ! -path './src/libc/tlsf.h' \
                -print0 \
                | sort -z \
                | xargs -0 clang-format --dry-run --Werror
              cargo fmt --manifest-path src/rust/bpf-capsule-rt/Cargo.toml --check
              cargo fmt --manifest-path examples/rust/Cargo.toml --check
              touch "$out"
            '';
        apps = rec {
          default = fib;
          benchmarks = mkToolApp {
            name = "bpf-capsule-benchmarks";
            description = "Benchmark BPF Capsule on current and Linux 5.15 kernels";
            runtimeInputs = with pkgs; [
              coreutils
              git
              nix
              python3
              util-linux
            ];
            text = ''
              export BPF_CAPSULE_NIX_SOURCE=path:${self}
              export BPF_CAPSULE_DEFAULT_DOOM_WAD=${freedoomWad}/freedoom1.wad
              export BPF_CAPSULE_RESULTS_ROOT="''${BPF_CAPSULE_RESULTS_ROOT:-''${XDG_CACHE_HOME:-$HOME/.cache}/bpf-capsule/matrix}"
              exec ${pkgs.python3}/bin/python3 ${self}/benchmarks/matrix.py "$@"
            '';
          };
          fuzz = mkToolApp {
            name = "bpf-capsule-fuzz";
            description = "Differentially fuzz BPF Capsule with Csmith";
            runtimeInputs = with pkgs; [ nix ];
            text = ''
              exec nix develop path:${self} -c \
                python3 ${self}/tests/csmith/fuzz.py "$@"
            '';
          };
          fib = mkDirectApp {
            package = packages.fib;
            executable = "libexec/bpf-capsule/examples/fib/fib";
            description = "Run the minimal recursive Fibonacci BPF Capsule example";
          };
          zlib = mkDirectApp {
            package = packages.zlib;
            executable = "libexec/bpf-capsule/examples/zlib/zlib";
          };
          wasm3 = mkDirectApp {
            package = packages.wasm3;
            executable = "libexec/bpf-capsule/examples/wasm3/wasm3";
          };
          lua = mkDirectApp {
            package = packages.lua;
            executable = "libexec/bpf-capsule/examples/lua/lua";
          };
          lua-xdp = mkDirectApp {
            package = packages.lua-xdp;
            executable = "libexec/bpf-capsule/examples/lua-xdp/lua-xdp";
          };
          lua-xdp-test = mkDirectApp {
            package = packages.lua-xdp;
            executable = "libexec/bpf-capsule/tests/lua-xdp/lua_xdp_test_host";
          };
          lua-xdp-benchmark = mkDirectApp {
            package = packages.lua-xdp;
            executable = "libexec/bpf-capsule/benchmarks/lua-xdp/lua_xdp_benchmark";
          };
          quickjs = mkDirectApp {
            package = packages.quickjs;
            executable = "libexec/bpf-capsule/examples/quickjs/quickjs";
          };
          sqlite = mkDirectApp {
            package = packages.sqlite;
            executable = "libexec/bpf-capsule/examples/sqlite/sqlite";
          };
          rust = mkDirectApp {
            package = packages.rust;
            executable = "libexec/bpf-capsule/examples/rust/rust";
          };
          llama2 = mkDirectApp {
            package = packages.llama2;
            executable = "libexec/bpf-capsule/examples/llama2/llama2";
          };
          llama2-q8 = mkDirectApp {
            package = packages.llama2;
            executable = "libexec/bpf-capsule/examples/llama2/llama2q";
          };
          doom = mkDirectApp {
            package = packages.doom;
            executable = "libexec/bpf-capsule/examples/doom/doom";
          };
        };
        devShells.default = packages.default.overrideAttrs (
          final: prev: {
            nativeBuildInputs =
              prev.nativeBuildInputs
              ++ (with pkgs; [
                gdb
                creduce
                csmith
                llvmPkgs.clang-tools
                ninja
                python3
                cargo
                cmake-format
                rustc
              ]);
          }
        );
      }
    );
}
