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
  exampleSource = ../examples + "/${example}";
  # The pinned upstream revisions the examples' CMake files would fetch
  # themselves. The sandbox has no network, so they are inputs here.
  zlibSource = fetchzip {
    url = "https://github.com/madler/zlib/archive/da607da739fa6047df13e66a2af6b8bec7c2a498.tar.gz";
    hash = "sha256-Sthd9RsydSLaITNlBp6g1X35WKZdS4h7gr0QhRqdGoI=";
  };
  sqliteSource = fetchzip {
    url = "https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip";
    hash = "sha256-ij7Yw6LuWXeetH3Zs6ir+4HdQTpynPlSIMspl0nTuUI=";
  };
  luaSource = fetchzip {
    url = "https://www.lua.org/ftp/lua-5.5.1.tar.gz";
    hash = "sha256-vb3Nt5dMPL/G6L1MmJPGQnQT3F8p6iK6Gu2F/cG00ho=";
  };
  wasm3Source = fetchzip {
    url = "https://github.com/wasm3/wasm3/archive/0cd38327f0c721e75172f4f1eeb55854dc0517af.tar.gz";
    hash = "sha256-0LFsyAhT51rhXORnxMQ8/Jt22F6neE5aZZSxF5c7HBw=";
  };
  llama2Source = fetchzip {
    url = "https://github.com/karpathy/llama2.c/archive/350e04fe35433e6d2941dce5a1f53308f87058eb.tar.gz";
    hash = "sha256-pFYN2JnKl/fgofqZvwG42YUkXqDrzTo4PjWbHhDvml8=";
  };
  quickjsSource = fetchzip {
    url = "https://github.com/bellard/quickjs/archive/04be246001599f5995fa2f2d8c91a0f198d3f34c.tar.gz";
    hash = "sha256-IGq2a2MQtp45hrPL/1CyF87vS8hfMbtKK1NVN6+n+Tk=";
  };
  puredoomSource = fetchzip {
    url = "https://github.com/Daivuk/PureDOOM/archive/355cfbd16fac119718879239336ee2ea408886bd.tar.gz";
    hash = "sha256-wW3psXtWuyxByUlelkTFp3BwWjp5W+uUaHeUEqr+sWw=";
  };
  # What each example compiles besides its own sources.
  upstream = {
    fib = [ ];
    zlib = [ "-DFETCHCONTENT_SOURCE_DIR_ZLIB=${zlibSource}" ];
    sqlite = [ "-DFETCHCONTENT_SOURCE_DIR_SQLITE=${sqliteSource}" ];
    lua = [ "-DFETCHCONTENT_SOURCE_DIR_LUA=${luaSource}" ];
    lua-xdp = [ "-DFETCHCONTENT_SOURCE_DIR_LUA=${luaSource}" ];
    wasm3 = [
      "-DFETCHCONTENT_SOURCE_DIR_WASM3=${wasm3Source}"
      "-DFETCHCONTENT_SOURCE_DIR_ZLIB=${zlibSource}"
    ];
    llama2 = [ "-DFETCHCONTENT_SOURCE_DIR_LLAMA2=${llama2Source}" ];
    quickjs = [ "-DFETCHCONTENT_SOURCE_DIR_QUICKJS=${quickjsSource}" ];
    rust = [ ];
    doom = [ "-DFETCHCONTENT_SOURCE_DIR_PUREDOOM=${puredoomSource}" ];
  };
in
assert lib.assertMsg (upstream ? ${example}) "unknown BPF Capsule example: ${example}";
stdenv.mkDerivation {
  pname = example;
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = exampleSource;
    fileset = exampleSource;
  };

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    bpftools
  ]
  ++ lib.optionals (example == "wasm3") [
    # The interpreted module is ordinary wasm32 output of the SDK's LLVM.
    llvmPackages.clang-unwrapped
    llvmPackages.lld
  ]
  ++ lib.optionals (example == "rust") [
    cargo
    rustc
    llvmPackages.libllvm
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
    "-DBPF_CAPSULE_LINK_OPTIONS=${lib.concatStringsSep ";" targetProfile.linkOptions}"
  ]
  ++ upstream.${example};
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
        rust = [ ];
        doom = [ gpl2Only ];
      }
      .${example};
    platforms = lib.platforms.linux;
  };
}
