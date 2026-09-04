# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Standalone benchmark binaries, built against the shared SDK for one profile.
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
  gbenchmark,
  bpfCapsule,
  targetKernel ? null,
}:
let
  targetProfile = import ./target-profile.nix { inherit lib; } {
    kernel = targetKernel;
    arch = stdenv.hostPlatform.parsed.cpu.name;
  };
  luaSource = fetchzip {
    url = "https://www.lua.org/ftp/lua-5.5.1.tar.gz";
    hash = "sha256-vb3Nt5dMPL/G6L1MmJPGQnQT3F8p6iK6Gu2F/cG00ho=";
  };
in
stdenv.mkDerivation {
  pname = "bpf-capsule-benchmark-suite-${
    builtins.replaceStrings [ "." ] [ "" ] targetProfile.kernel
  }";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../benchmarks;
    fileset = ../benchmarks;
  };

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    bpftools
  ];
  buildInputs = [
    bpfCapsule
    libbpf
    elfutils
    zlib
    zstd
    gbenchmark
  ];

  cmakeBuildType = "Release";
  cmakeFlags = [
    "-DCMAKE_PREFIX_PATH=${bpfCapsule}"
    "-DBPF_CAPSULE_LINK_OPTIONS=${lib.concatStringsSep ";" targetProfile.linkOptions}"
    "-DFETCHCONTENT_SOURCE_DIR_LUA=${luaSource}"
  ];
  meta = {
    description = "BPF Capsule benchmarks for Linux ${targetProfile.kernel}";
    license = with lib.licenses; [
      asl20
      llvm-exception
      mit
      bsd2
      bsd3
      isc
    ];
    platforms = lib.platforms.linux;
  };
}
