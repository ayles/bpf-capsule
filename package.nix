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
  example ? null,
  targetKernel ? "5.15",
}:
let
  allExamples = [
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
  buildsExamples = buildExamples || example != null;
  builds = name: buildExamples || example == name;
  # Host tools use Nix's complete system compiler wrapper. bpf-capsule-cc
  # discovers the pinned unwrapped Clang separately; the host compiler has no
  # bearing on generated BPF and must retain its ordinary libc startup paths.
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
  csmithCase = runCommand "bpf-capsule-csmith-seed-17.c" { nativeBuildInputs = [ csmith ]; } ''
    mkdir -p "$out"
    csmith --seed 17 --no-argc --no-float --concise \
      --max-funcs 10 --max-block-depth 5 --max-block-size 5 \
      --output "$out/case.c"
  '';
in
assert lib.assertMsg (example == null || lib.elem example allExamples)
  "unknown BPF Capsule example: ${toString example}";
stdenv.mkDerivation {
  pname = if example != null then "bpf-capsule-${example}"
          else "bpf-capsule-${builtins.replaceStrings [ "." ] [ "" ] targetKernel}";
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
    "-DBPF_CAPSULE_BUILD_EXAMPLES:BOOL=${lib.boolToString buildsExamples}"
    "-DBPF_CAPSULE_INSTALL_TEST_ARTIFACTS:BOOL=${lib.boolToString buildTests}"
  ] ++ lib.optionals buildsExamples [
    "-DBPF_CAPSULE_EXAMPLES:STRING=${if example != null then example else "all"}"
  ] ++ lib.optionals buildTests [
    "-DBPF_CAPSULE_CSMITH_CASE=${csmithCase}/case.c"
    "-DBPF_CAPSULE_CSMITH_INCLUDE_DIR=${csmith}/include"
  ] ++ lib.optionals (buildTests || builds "lua" || builds "lua-xdp") [
    "-DLUA_BPF_SOURCE_DIR=${luaSource}"
  ] ++ lib.optionals (builds "zlib" || builds "wasm3") [
    "-DZLIB_BPF_SOURCE_DIR=${zlibSource}"
  ] ++ lib.optionals (builds "sqlite") [
    "-DSQLITE_BPF_SOURCE_DIR=${sqliteSource}"
  ] ++ lib.optionals (builds "wasm3") [
    "-DWASM3_BPF_SOURCE_DIR=${wasm3Source}"
  ] ++ lib.optionals (builds "llama2") [
    "-DLLAMA2_BPF_SOURCE_DIR=${llama2Source}"
  ] ++ lib.optionals (builds "quickjs") [
    "-DQUICKJS_BPF_SOURCE_DIR=${quickjsSource}"
  ] ++ lib.optionals (builds "doom") [
    "-DPUREDOOM_SOURCE_DIR=${puredoomSource}"
  ];

  nativeBuildInputs = [
    cmake
    pkg-config
    llvmPackages.libllvm
    llvmPackages.clang-unwrapped
    bpftools
  ] ++ lib.optionals (builds "wasm3") [
    llvmPackages.lld
  ] ++ lib.optionals (builds "rust") [
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
  ] ++ lib.optionals (builds "zlib" || builds "wasm3") [
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
    ] ++ lib.optionals buildsExamples [
      lib.licenses.bsd3
      lib.licenses.mit
      lib.licenses.publicDomain
      lib.licenses.zlib
    ] ++ lib.optionals (builds "doom") [
      lib.licenses.gpl2Only
    ];
    platforms = lib.platforms.linux;
  };
}
