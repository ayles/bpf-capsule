# Contributing

BPF Capsule is an out-of-tree LLVM 22 compiler plus a small BPF/host runtime.
Changes are expected to preserve both the arena and Linux 5.15 map-backed
profiles; a successful native build alone is not sufficient evidence.

## Development build

Enter the pinned toolchain and build the compiler:

```sh
nix develop
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

To build the complete examples and focused tests for both memory profiles:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBPF_CAPSULE_BUILD_EXAMPLES=ON \
  -DBPF_CAPSULE_TARGET_KERNEL=5.15
cmake -S . -B build-arena \
  -DCMAKE_BUILD_TYPE=Release \
  -DBPF_CAPSULE_BUILD_EXAMPLES=ON \
  -DBPF_CAPSULE_TARGET_KERNEL=6.9
cmake --build build -j
cmake --build build-arena -j
```

Loading BPF requires privilege. Run the local proof suite with:

```sh
sudo -v
nix develop -c tests/run-proof-suite.sh build --doom-wad none
nix develop -c tests/run-proof-suite.sh build-arena --doom-wad none
```

The release authority is `nix flake check`, which boots the clean current and
5.15 VM profiles. `nix run .#benchmarks` additionally records real-library
execution time, verifier processed instructions, static instruction count,
JIT size, and load time. Do not substitute ELF/text size for verifier
processed instructions: they measure different constraints. Timing is a
same-host old/new observation and must never be a hardcoded regression gate;
follow [`benchmarks/PERFORMANCE.md`](benchmarks/PERFORMANCE.md). Canonical
non-timing metrics compare exactly, with no percentage allowance.

## Compiler changes

IR passes are grouped by family under `src/pass`; unified-memory lowering lives
in `memory.cpp`, while smaller legalization passes and plugin registration live
in `pass.cpp` unless they need a dedicated source file;
the late machine pass lives in `src/pass/unified_spills_mir.cpp`. Register a
new IR pass by:

1. giving it an individual parser name for focused tests;
2. placing it in the composite `bpf-capsule` pipeline in `pass.cpp` at the
   point where its input invariants hold;
3. documenting those input/output invariants in `ARCHITECTURE.md`; and
4. adding a focused positive or negative fixture under `tests/`.

The public CMake pipeline invokes only `--passes=bpf-capsule`. Repeated passes
inside that composite pipeline are intentional only when an intervening stage
can invalidate their result; explain any new repetition in code and in the
architecture document.

Use `emitError` with a function or source location for unsupported input.
Reserve `report_fatal_error` for broken compiler/runtime invariants after the
module has already been mutated. Every new rejection should have a negative
test which checks the specific diagnostic and rejects LLVM crash banners.

## Runtime and API changes

Public guest API belongs in `bpf_capsule.h`; the libbpf-based host API
belongs in `bpf_capsule_host.h`; the shared host<->guest records belong in
`bpf_capsule_abi.h`; and the runtime itself is `bpf_capsule.c`, compiled
into every object by the pipeline. Keep arena and fixed-map representation
details behind these boundaries. A public option or symbol needs a concrete application use, docs,
and coverage in both profiles.

Preserve the central memory invariant: static storage, the configured heap,
fiber software stacks, and relocated physical spills share one 32-bit Capsule
address space. The fixed tier may cache the current stack's ordinary ARRAY
region for speed, but it must not create a second stack memory model.

## Patch hygiene

Keep examples as small demonstrations. Differential checks and statistics
harnesses belong in `tests/` and `benchmarks/`. Run `clang-format` on C, C++,
and header changes, `cargo fmt` on Rust changes, and `cmake-format` on CMake
changes. The flake checks enforce all three while excluding generated and
vendored sources. Preserve SPDX headers, update current-state docs in the same
patch, and do not commit build outputs or generated skeletons.
