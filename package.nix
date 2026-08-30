# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  llvmPackages,
  stdenv,
  cmake,
  lib,
  bpftools,
  libbpf,
  elfutils,
  zstd,
  zlib,
  pkg-config,
  fetchzip,
  gtest,
  gbenchmark,
  csmith,
  cargo,
  rustc,
  runCommand,
  buildTests ? false,
  buildBenchmarks ? buildTests,
  buildExamples ? false,
  targetKernel ? "5.15",
}:
let
  # Host tools use Nix's complete system compiler wrapper. bpf-capsule-cc
  # discovers the pinned unwrapped Clang separately; the host compiler has no
  # bearing on generated BPF and must retain its ordinary libc startup paths.
  zlibSource = fetchzip {
    url = "https://github.com/madler/zlib/archive/e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca.tar.gz";
    hash = "sha256-tA199foI8bwi/j8AHZQ8Y5QzxPoyoo7NZMeBHO12okk=";
  };
  sqliteSource = fetchzip {
    url = "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip";
    hash = "sha256-bJoMjirsBjm2Qk9KPiy3yV3+8b/POlYe76/FQbciHro=";
  };
  luaSource = fetchzip {
    url = "https://www.lua.org/ftp/lua-5.4.8.tar.gz";
    hash = "sha256-6TMsVp2D3WtvnwyhvwodjQH3kvTXz1rSMWwiHazvKys=";
  };
  wasm3Source = fetchzip {
    url = "https://github.com/wasm3/wasm3/archive/6b8bcb1e07bf26ebef09a7211b0a37a446eafd52.tar.gz";
    hash = "sha256-QkXOBJ5luml6VCYLowQKv0K4mI7S2gy7bx5Jc86s/x8=";
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
  csmithCase = runCommand "bpf-capsule-csmith-seed-17.c" { nativeBuildInputs = [ csmith ]; } ''
    mkdir -p "$out"
    csmith --seed 17 --no-argc --no-float --concise \
      --max-funcs 10 --max-block-depth 5 --max-block-size 5 \
      --output "$out/case.c"
  '';
in
stdenv.mkDerivation {
  pname = "bpf-capsule-${builtins.replaceStrings [ "." ] [ "" ] targetKernel}";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./tools
      ./cmake
      ./tests
      ./benchmarks
      ./examples
      ./thirdparty
      ./CMakeLists.txt
      ./README.md
      ./DESIGN.md
      ./LICENSE
    ];
  };

  cmakeBuildType = "Release";
  hardeningDisable = [
    "stackprotector"
    "zerocallusedregs"
  ];
  cmakeFlags = [
    "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
    "-DBPF_CAPSULE_TARGET_KERNEL=${targetKernel}"
    "-DBPF_CAPSULE_BUILD_TESTS:BOOL=${lib.boolToString buildTests}"
    "-DBPF_CAPSULE_BUILD_BENCHMARKS:BOOL=${lib.boolToString buildBenchmarks}"
    "-DBPF_CAPSULE_BUILD_EXAMPLES:BOOL=${lib.boolToString buildExamples}"
    "-DBPF_CAPSULE_INSTALL_TEST_ARTIFACTS:BOOL=${lib.boolToString buildTests}"
  ] ++ lib.optionals buildTests [
    "-DBPF_CAPSULE_CSMITH_CASE=${csmithCase}/case.c"
    "-DBPF_CAPSULE_CSMITH_INCLUDE_DIR=${csmith}/include"
  ] ++ lib.optionals (buildTests || buildExamples) [
    "-DLUA_BPF_SOURCE_DIR=${luaSource}"
  ] ++ lib.optionals buildExamples [
    "-DBPF_CAPSULE_EXAMPLES:STRING=all"
    "-DZLIB_BPF_SOURCE_DIR=${zlibSource}"
    "-DSQLITE_BPF_SOURCE_DIR=${sqliteSource}"
    "-DWASM3_BPF_SOURCE_DIR=${wasm3Source}"
    "-DLLAMA2_BPF_SOURCE_DIR=${llama2Source}"
    "-DQUICKJS_BPF_SOURCE_DIR=${quickjsSource}"
    "-DPUREDOOM_SOURCE_DIR=${puredoomSource}"
  ];

  nativeBuildInputs = [
    cmake
    pkg-config
    llvmPackages.libllvm
    llvmPackages.clang-unwrapped
    bpftools
  ] ++ lib.optionals buildExamples [
    cargo
    rustc
  ];
  buildInputs = [
    libbpf
    elfutils
    zstd
  ] ++ lib.optionals buildTests [
    gtest
  ] ++ lib.optionals buildBenchmarks [
    gbenchmark
  ] ++ lib.optionals buildExamples [
    zlib
  ];

  doCheck = buildTests;
  enableParallelChecking = true;
  checkPhase = ''
    runHook preCheck
    ctest --output-on-failure -j "$NIX_BUILD_CORES"
    runHook postCheck
  '';

  meta = {
    description = "Compile ordinary C, C++, and no_std Rust into verifier-loadable eBPF";
    license = [
      lib.licenses.asl20
      lib.licenses.llvm-exception
    ] ++ lib.optionals buildExamples [
      lib.licenses.bsd3
      lib.licenses.gpl2Only
      lib.licenses.mit
      lib.licenses.publicDomain
      lib.licenses.zlib
    ];
    platforms = lib.platforms.linux;
  };
}
