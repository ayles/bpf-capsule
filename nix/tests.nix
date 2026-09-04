# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The test suite, built against the SDK for the profile selected from a kernel
# floor and the build architecture. Unprivileged tests run here; the in-kernel
# tests are installed for the NixOS VM checks to run as root in a real kernel.
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
  gtest,
  csmith,
  llvmPackages,
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
  pname = "bpf-capsule-tests-${builtins.replaceStrings [ "." ] [ "" ] targetProfile.kernel}";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      (lib.fileset.difference ../tests ../tests/vm)
      # The lua-xdp integration test compiles that example's runtime.
      ../examples/lua-xdp
    ];
  };
  cmakeDir = "../tests";

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    bpftools
    csmith
    # llvm-as, llvm-dis, llvm-readelf and friends for the contract scripts.
    llvmPackages.libllvm
  ];
  buildInputs = [
    bpfCapsule
    llvmPackages.libllvm
    libbpf
    elfutils
    zlib
    zstd
    gtest
    # Csmith's target-side runtime headers accompany its native generator.
    csmith
  ];

  cmakeBuildType = "Release";
  cmakeFlags = [
    "-DCMAKE_PREFIX_PATH=${bpfCapsule}"
    "-DBPF_CAPSULE_LINK_OPTIONS=${lib.concatStringsSep ";" targetProfile.linkOptions}"
    "-DFETCHCONTENT_SOURCE_DIR_LUA=${luaSource}"
  ];
  # Privileged suites skip themselves without root; the VM checks run them.
  doCheck = true;
  enableParallelChecking = true;
  checkPhase = ''
    runHook preCheck
    ctest --output-on-failure -j "$NIX_BUILD_CORES"
    runHook postCheck
  '';
  meta = {
    description = "BPF Capsule tests for Linux ${targetProfile.kernel}";
    # Test binaries embed Lua (MIT), TLSF (BSD-3-Clause) and the Csmith runtime
    # header (BSD-2-Clause).
    license = with lib.licenses; [
      asl20
      llvm-exception
      mit
      bsd3
      bsd2
    ];
    platforms = lib.platforms.linux;
  };
}
