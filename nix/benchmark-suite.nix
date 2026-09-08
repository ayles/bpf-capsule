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
  llvmPackages,
  bpfCapsule,
  targetKernel ? null,
}:
let
  targetProfile = import ./target-profile.nix { inherit lib; } {
    kernel = targetKernel;
    arch = stdenv.hostPlatform.parsed.cpu.name;
  };
  sources = import ./port-sources.nix { inherit fetchzip; };
in
stdenv.mkDerivation {
  pname = "bpf-capsule-benchmark-suite-${
    builtins.replaceStrings [ "." ] [ "" ] targetProfile.kernel
  }";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../benchmarks
      ../ports/lua
    ];
  };
  cmakeDir = "../benchmarks";

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    bpftools
    llvmPackages.libllvm
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
    "-DFETCHCONTENT_SOURCE_DIR_LUA=${sources.lua}"
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
