# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# One example, built against the SDK for the profile selected from a kernel
# floor and the build architecture. `targetKernel` remains overridable by a
# caller composing these package functions directly.
{
  lib,
  stdenv,
  cmake,
  pkg-config,
  fetchzip,
  bpftools,
  libbpf,
  elfutils,
  zlib,
  zstd,
  gnumake,
  patch,
  python314,
  which,
  cargo,
  rustc,
  llvmPackages,
  bpfCapsule,
  example,
  targetKernel ? null,
}:
let
  targetProfile = import ./target-profile.nix { inherit lib; } {
    kernel = targetKernel;
    arch = stdenv.hostPlatform.parsed.cpu.name;
  };
  isPython = lib.elem example [
    "python"
    "python-xdp"
  ];
  # CPython needs independent verifier budgets; hardware capabilities still
  # come only from targetProfile, just as for the other examples.
  linkOptions = targetProfile.linkOptions ++ lib.optional isPython "--freplace";
  exampleSource = ../examples + "/${example}";
  sources = import ./port-sources.nix { inherit fetchzip; };
  # CPython's port fetches its compression libraries itself; they have no port
  # directory of their own.
  pythonSources = [
    "cpython"
    "zlib"
    "bzip2"
    "xz"
    "zstd"
    "sqlite"
  ];
  # Select the same port definitions for CMake and the sandbox fileset.
  upstream = {
    fib = [ ];
    zlib = [ "zlib" ];
    sqlite = [ "sqlite" ];
    lua = [ "lua" ];
    lua-xdp = [ "lua" ];
    wasm3 = [
      "wasm3"
      "zlib"
    ];
    llama2 = [ "llama2" ];
    quickjs = [ "quickjs" ];
    rust = [ ];
    doom = [ "puredoom" ];
    python = pythonSources;
    python-xdp = pythonSources;
  };
in
assert lib.assertMsg (upstream ? ${example}) "unknown BPF Capsule example: ${example}";
stdenv.mkDerivation {
  pname = example;
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions (
      [ exampleSource ]
      ++ map (name: ../ports + "/${name}") (
        lib.filter (name: builtins.pathExists (../ports + "/${name}")) upstream.${example}
      )
    );
  };

  cmakeDir = "../examples/${example}";

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    bpftools
    llvmPackages.libllvm
  ]
  ++ lib.optionals (example == "wasm3") [
    # The interpreted module is ordinary wasm32 output of the SDK's LLVM.
    llvmPackages.clang-unwrapped
    llvmPackages.lld
  ]
  ++ lib.optionals (example == "rust") [
    cargo
    rustc
  ]
  ++ lib.optionals isPython [
    gnumake
    patch
    python314
    which
  ];
  buildInputs = [
    bpfCapsule
    libbpf
    elfutils
    zlib
    zstd
  ];

  cmakeBuildType = "Release";
  cmakeFlags = [
    "-DCMAKE_PREFIX_PATH=${bpfCapsule}"
    "-DBPF_CAPSULE_LINK_OPTIONS=${lib.concatStringsSep ";" linkOptions}"
  ]
  ++ map (
    name: "-DFETCHCONTENT_SOURCE_DIR_${lib.toUpper name}=${sources.${name}}"
  ) upstream.${example};
  # bin/<example>.bpf.o is the final BPF object for inspection; keep it intact.
  stripExclude = [ "*.bpf.o" ];

  meta = {
    description = "BPF Capsule example: ${example} for Linux ${targetProfile.kernel}";
    # Cover the SDK code and the upstream sources compiled into each object.
    license =
      with lib.licenses;
      [
        asl20
        llvm-exception
        bsd2
        bsd3
        isc
      ]
      ++ {
        fib = [ ];
        zlib = [ lib.licenses.zlib ];
        sqlite = [ publicDomain ];
        lua = [ mit ];
        lua-xdp = [ mit ];
        wasm3 = [
          mit
          zlib
        ];
        llama2 = [ mit ];
        quickjs = [ mit ];
        rust = [ mit ];
        doom = [ gpl2Only ];
        python = [
          psfl
          mit
          lib.licenses.zlib
          bzip2
          bsd0
          publicDomain
        ];
        python-xdp = [
          psfl
          mit
          lib.licenses.zlib
          bzip2
          bsd0
          publicDomain
        ];
      }
      .${example};
    platforms = lib.platforms.linux;
  };
}
