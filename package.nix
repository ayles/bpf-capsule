# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
{
  llvmPackages,
  cmake,
  lib,
  bpftools,
  libbpf,
  elfutils,
  zstd,
  pkg-config,
  overrideCC,
  fetchzip,
  python3,
  cargo,
  rustc,
  csmith,
  runCommand,
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
  selectedExamples =
    if example != null then [ example ]
    else if buildExamples then allExamples
    else [ ];
  buildsExamples = selectedExamples != [ ];
  builds = name: buildExamples || example == name;
  stdenv = overrideCC llvmPackages.stdenv (
    llvmPackages.stdenv.cc.override {
      cc = llvmPackages.clang-unwrapped;
    }
  );
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
assert lib.assertMsg (example == null || lib.elem example allExamples)
  "unknown BPF Capsule example: ${toString example}";
stdenv.mkDerivation {
  pname =
    if example != null then "bpf-capsule-${example}"
    else if buildExamples then
      "bpf-capsule-matrix-${lib.replaceStrings [ "." ] [ "" ] targetKernel}"
    else "bpf-capsule";
  # Keep in step with project(BpfCapsule VERSION ...) in CMakeLists.txt.
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./examples
      ./benchmarks
      ./tests
      ./cmake
      ./docs
      ./LICENSE
      ./NOTICE
      ./README.md
      ./DESIGN.md
      ./ARCHITECTURE.md
      ./SPEC.md
      ./CONTRIBUTING.md
      ./CMakeLists.txt
      ./tools/generate-llama-fixtures.py
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
  ] ++ lib.optionals buildsExamples [
    "-DBPF_CAPSULE_BUILD_EXAMPLES:BOOL=ON"
    "-DBPF_CAPSULE_EXAMPLES:STRING=${
      if buildExamples then "all"
      else lib.concatStringsSep ";" selectedExamples
    }"
  ] ++ lib.optionals buildExamples [
    "-DBPF_CAPSULE_INSTALL_TEST_ARTIFACTS:BOOL=ON"
    "-DBPF_CAPSULE_CSMITH_CASE=${csmithCase}/case.c"
    "-DBPF_CAPSULE_CSMITH_INCLUDE_DIR=${csmith}/include"
  ] ++ lib.optionals (builds "zlib") [
    "-DZLIB_BPF_SOURCE_DIR=${zlibSource}"
  ] ++ lib.optionals (builds "sqlite") [
    "-DSQLITE_BPF_SOURCE_DIR=${sqliteSource}"
  ] ++ lib.optionals (builds "lua" || builds "lua-xdp") [
    "-DLUA_BPF_SOURCE_DIR=${luaSource}"
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
    bpftools
  ] ++ lib.optionals (builds "llama2") [
    python3
  ] ++ lib.optionals (builds "rust") [
    cargo
    rustc
  ];

  buildInputs = [
    libbpf
    elfutils
    zstd
  ];

  postInstall = lib.optionalString (builds "llama2") ''
    fixture_dir=$out/libexec/bpf-capsule/examples/llama2
    ${python3}/bin/python3 $src/tools/generate-llama-fixtures.py "$fixture_dir"
  '';

  meta = {
    description = "Compiles ordinary C and no_std Rust into verifier-loadable eBPF";
    # Apache-2.0 WITH LLVM-exception; the pinned nixpkgs has no asl20-llvm
    # attribute, so express the base license and the exception separately.
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
