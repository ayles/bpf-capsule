# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The SDK: bpf-capsule-cc, bpf-capsule-ld, the host library, headers, the
# guest runtime sources, Picolibc, and the CMake integration. Target profiles,
# examples, and tests are consumers of this package and live elsewhere.
{
  lib,
  stdenv,
  cmake,
  pkg-config,
  fetchzip,
  linuxHeaders,
  llvmPackages,
  libbpf,
  elfutils,
  zlib,
  zstd,
}:
let
  picolibcSource = fetchzip {
    url = "https://github.com/picolibc/picolibc/archive/refs/tags/1.8.12.tar.gz";
    hash = "sha256-a2XLUN2U49Lpsyizzb2cQpMbww0cmOUUKdgIj6OHhpQ=";
  };
  tlsfSource = fetchzip {
    url = "https://github.com/mattconte/tlsf/archive/deff9ab509341f264addbd3c8ada533678591905.tar.gz";
    hash = "sha256-uyOuzKbKnWyKwgRX1jlszwwT3n05spS9lSmUvv5WS2M=";
  };
in
stdenv.mkDerivation {
  pname = "bpf-capsule";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../CMakeLists.txt
      ../cmake
      ../src
      ../tools
      ../LICENSE
      ../README.md
      ../DESIGN.md
      ../PLATFORM.md
    ];
  };

  strictDeps = true;
  nativeBuildInputs = [
    cmake
    pkg-config
    # bpf-capsule-cc records this clang as its default; the reference keeps
    # it in the closure.
    llvmPackages.clang-unwrapped
  ];
  buildInputs = [
    llvmPackages.libllvm
    libbpf
    elfutils
    zlib
    zstd
    linuxHeaders
  ];

  cmakeBuildType = "Release";
  cmakeFlags = [
    "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
    "-DFETCHCONTENT_SOURCE_DIR_PICOLIBC=${picolibcSource}"
    "-DFETCHCONTENT_SOURCE_DIR_TLSF=${tlsfSource}"
    "-DBPF_CAPSULE_LINUX_UAPI_INCLUDE_DIR=${linuxHeaders}/include"
    "-DBPF_CAPSULE_LINUX_UAPI_ARCH_INCLUDE_DIR=${linuxHeaders}/include"
    "-DBPF_CAPSULE_LINUX_UAPI_GENERIC_INCLUDE_DIR=${linuxHeaders}/include"
  ];

  meta = {
    description = "Compile ordinary C, C++, and no_std Rust into verifier-loadable eBPF";
    # Picolibc contains BSD, ISC, and public-domain code; TLSF is BSD-3-Clause.
    license = with lib.licenses; [
      asl20
      llvm-exception
      bsd2
      bsd3
      isc
    ];
    platforms = lib.platforms.linux;
  };
}
