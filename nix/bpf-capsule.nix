# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The SDK: bpf-capsule-cc, bpf-capsule-ld, the host library, headers, the
# guest runtime and libc sources, and the CMake integration. Target profiles,
# examples, and tests are consumers of this package and live elsewhere.
{
  lib,
  stdenv,
  cmake,
  pkg-config,
  fetchzip,
  llvmPackages,
  libbpf,
  elfutils,
  zlib,
  zstd,
}:
let
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
  ];

  cmakeBuildType = "Release";
  cmakeFlags = [
    "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
    "-DFETCHCONTENT_SOURCE_DIR_TLSF=${tlsfSource}"
  ];

  meta = {
    description = "Compile ordinary C, C++, and no_std Rust into verifier-loadable eBPF";
    # The libc adapts musl (MIT) and includes TLSF (BSD-3-Clause).
    license = with lib.licenses; [
      asl20
      llvm-exception
      mit
      bsd3
    ];
    platforms = lib.platforms.linux;
  };
}
