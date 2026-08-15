# BPF Capsule

BPF Capsule compiles ordinary C and `no_std` Rust programs into
verifier-loadable eBPF. It keeps normal bounded work as native BPF, virtualizes
only control flow that the verifier cannot accept directly, and moves only
native-stack overflow into compiler-managed memory. A fixed fiber pool permits
independent Capsule calls to execute concurrently while sharing program memory
and a synchronized allocator.

## What works

The same automatic pipeline currently compiles and runs:

- unmodified zlib inflate, Lua 5.4.8, QuickJS, SQLite 3.45.1, wasm3 v0.5.0,
  and llama2.c sources;
- Rust `no_std` plus `alloc` and compiler-builtins bitcode;
- pinned upstream PureDOOM with two documented allocator-dependent rendering
  fixes;
- recursive calls, indirect calls, deep call graphs, dynamic loops, defined
  variadic functions,
  aggregate ABI lowering, 128-bit integer legalization, and software float.

Every row above is gated in clean VMs on the current nixpkgs kernel (arena
tier) and the nixpkgs Linux 5.15 series (map tier). The full build-and-runtime
matrix has passed on both x86_64 and arm64. Those are execution kernels, while
`6.9` and `5.15` below name compile-time compatibility profiles. The arena tier
compiles for the 6.9 arena feature ABI, but on arm64 its features arrive across
several kernels — basic arena JIT in 6.10, and
sign-extending arena loads plus arena access from XDP only around 7.0 — so the
full arena tier this compiler emits is proved on a current kernel; a literal
6.1x arm64 kernel supports only a subset. Real-library hosts with a userspace
continuation loop report zero drains. Single-entry and attached paths instead
reject `CAPSULE_PENDING` and cannot drain; dedicated continuation tests
deliberately do. Setup may still use a distinct initialization or preparation
entry; that is a separate operation, not a continuation drain.

This is research software, not a security boundary. Managed code cannot create
threads or use general thread-local storage; concurrency comes from separate
BPF invocations leasing separate Capsule fibers. C++ exceptions,
operating-system calls from managed code, calls to declared-only variadic
externals, and general `setjmp`/`longjmp` semantics are also unsupported. Put a
fixed-signature wrapper around a variadic external.

> [!CAUTION]
> **COMPLEX ATOMICS IN CAPSULE CODE ARE NOT YET SUPPORTED.** Naturally aligned
> 8/16/32/64-bit atomic loads and stores with relaxed ordering are preserved.
> Read-modify-write operations (`fetch_add`, exchange, compare-exchange, and
> similar), fences, and stronger memory orderings are rejected at compile time;
> they are never silently changed into non-atomic accesses. Native-domain BPF
> atomics remain intact when the selected kernel target supports them. See the
> exact contract in [`docs/PROGRAMMING.md`](docs/PROGRAMMING.md#atomics).

## Architecture

```text
C / Rust bitcode
      |
      v
stock LLVM O2 and ABI/legalization passes
      |
      v
continuation + software-frame transform
      |
      +-- small proven loops/calls remain native
      `-- verifier-hostile control flow becomes explicit regions
      |
      v
automatic 6.9 arena or 5.15 map-backed memory lowering
      |
      v
stock LLVM BPF instruction selection/register allocation
      |
      v
late physical spill placement and old-verifier CFG repair
      |
      v
normal ELF/BTF eBPF object
```

LLVM remains unmodified. BPF Capsule is about 14k lines of LLVM-pass code plus
a roughly 700-line BPF runtime source. The installed plugin is under 1 MiB and
loads the system LLVM library only while compiling. Generated BPF objects do
not depend on LLVM at runtime.

The compatibility choice is the `BPF_CAPSULE_TARGET_KERNEL` CMake cache variable. It
is the oldest deployment kernel, expressed as `major.minor`; the compiler
enables every supported feature available by that version. The default is the
oldest tested kernel:

```text
-DBPF_CAPSULE_TARGET_KERNEL=5.15  fixed map-backed regions, BPF v3 instructions (default)
-DBPF_CAPSULE_TARGET_KERNEL=6.6   fixed map-backed regions, BPF v4 instructions
-DBPF_CAPSULE_TARGET_KERNEL=6.9   arena memory, BPF v4 instructions
```

Users do not select loop batches, continuation depth, native-stack budgets, or
verifier budgets. Two compile-time bounds describe object ABI geometry:

```text
-DBPF_CAPSULE_MAX_FIBERS=512
-DBPF_CAPSULE_FIBER_STACK_BYTES=262144
```

The first is only a verifier/control upper bound; the second remains a
compile-time constant so frame bounds stay provable. After opening an object,
`bpf_capsule_configure(object, config)` chooses the physical
capacity actually backed for that object before load. Unused fibers do not
allocate stacks, and allocator-free programs may select a zero-byte heap. Most
applications keep the one-fiber default or explicitly select a concurrency
count suited to their attachment and host. The compiled fiber ceiling may be
overridden from 1 through 65,535; practical memory and verifier costs normally
make much smaller bounds appropriate.
The fixed tier always uses its fast 32-region prefix and an ARRAY tail; the
arena tier uses page-granular sparse backing. Internal compiler debug flags are
unsupported and may change at any time.

## Build

The reproducible path uses Nix and LLVM 22:

```sh
nix build
```

The compiler remains the small default output. A separate mixed-license
example bundle is built entirely from hash-pinned Nix sources, and the common
demos have direct apps. These apps execute the installed host binary unchanged:
they do not elevate privileges or add fixture arguments. From a source checkout,
representative invocations are:

```sh
sudo nix run .#fib
sudo nix run .#zlib
sudo nix run .#wasm3
sudo nix run .#lua -- "$PWD/examples/lua/lua/script.lua"
sudo nix run .#quickjs -- "$PWD/examples/quickjs/script.js"
sudo nix run .#sqlite
sudo nix run .#rust
sudo nix run .#llama2 -- MODEL
sudo nix run .#llama2-q8 -- MODEL
sudo nix run .#doom -- WAD tty
```

Use an equivalent capability-based launcher instead of `sudo` where available;
consult each host's usage message for optional arguments. These apps build the
fast Linux 6.9 arena profile. The build default is
the Linux 5.15 compatibility floor, so `nix build .#examples` and a plain
CMake configure produce 5.15 objects unless a newer `BPF_CAPSULE_TARGET_KERNEL` is
selected. `nix build .#examples` only builds and installs the complete
example bundle without executing BPF.

For development:

```sh
nix develop
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Without Nix, provide CMake 3.21+, LLVM/Clang 22, libbpf 1.4 or newer, libelf, zlib, zstd,
pkg-config, and a C/C++ toolchain from the same LLVM installation. The arena
layout is independent of whether libbpf places initialized arena data at the
left or right edge of its mapping; see [`DESIGN.md`](DESIGN.md).

The compiler build is intentionally small by default. Enable the proof suite
to fetch pinned upstream sources and expose its targets:

```sh
cmake -S . -B build-demo \
  -DCMAKE_BUILD_TYPE=Release \
  -DBPF_CAPSULE_BUILD_EXAMPLES=ON
cmake --build build-demo --target zlib -j
sudo build-demo/examples/zlib/zlib
```

The same build for the compatibility floor is selected with
`-DBPF_CAPSULE_TARGET_KERNEL=5.15`. A caller-supplied `*_BPF_SOURCE_DIR` cache
variable (`PUREDOOM_SOURCE_DIR` for Doom) overrides the pinned download. An
offline build supplies those directories; Nix does this automatically.

## Use from CMake

After installation:

```cmake
find_package(BpfCapsule CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)
set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)

bpf_capsule_bitcode(
    program_bc
    SOURCES driver.c library.c
    INCLUDE_DIRECTORIES /path/to/library/headers
    COMPILE_OPTIONS -g
)
bpf_capsule_object(
    program_bpf
    OUTPUT program.bpf.o
    BITCODE ${program_bc}
)
bpf_capsule_skeleton(
    program_skeleton
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/program.skel.h
    OBJECT ${CMAKE_CURRENT_BINARY_DIR}/program.bpf.o
    NAME program
    DEPENDS program_bpf
)
```

The stock libbpf skeleton embeds the completed object in the host executable;
applications ship and invoke one file rather than pairing a loader with a raw
`.o`. Raw objects remain useful compiler artifacts for inspection and
low-level tests.

The runtime (`bpf_capsule.c`) is compiled into the object automatically; it owns the maps
and trampoline used by generated code. The copy-paste template for using an
installed package from your own repository — a recursive-descent expression
evaluator whose recursion depth the input chooses, built purely against
`find_package(BpfCapsule)` — is in
[`examples/standalone`](examples/standalone). The minimal installed-package
smoke project is in [`tests/cmake-package`](tests/cmake-package);
[`tests/cmake-package/run.sh`](tests/cmake-package/run.sh) installs the tree
to a temporary prefix, builds both consumers against it, and executes the
standalone evaluator in BPF.

The entry/control/memory contract—including explicit native-to-Capsule calls,
post-load global initialization, continuation driving, abort handling, and
which data userspace can access—is documented in
[`docs/PROGRAMMING.md`](docs/PROGRAMMING.md).

## Correctness and performance regressions

The checked workload is compiled natively, directly to stock eBPF where that
is possible, and through BPF Capsule. One command builds the complete suite in
Nix, boots clean current and 5.15-series kernels, and requires byte-for-byte or
result equivalence. Real-library hosts that contain a continuation loop report
and enforce exactly zero drains; single-entry cases reject pending execution
structurally:

```sh
nix flake check
```

Programs that require managed control flow, checked memory or software float
have workload-dependent overhead. The two-kernel VM matrix prints paired
timings for human review and compares deterministic verifier, object, dispatch,
and result metrics exactly. It is documented in
[`benchmarks/README.md`](benchmarks/README.md); generated reports are the
regression authority rather than numbers copied into this README.

Performance is host-specific and intentionally separate from the functional
Nix checks. This command uses KVM when available and records runtime,
verifier/JIT cost, object size and entry counts against the newest complete
same-machine report:

```sh
nix run .#benchmarks
```

See [`DESIGN.md`](DESIGN.md) for the detailed compiler and runtime invariants.
Run the complete correctness/performance report with
[`benchmarks/regression.py`](benchmarks/regression.py).

The runnable command index and expected success markers are in
[`docs/EXAMPLES.md`](docs/EXAMPLES.md).

Potential future channels, nonlocal exits/C++ unwinding, and performance work
are design notes rather than current API; see the future-work sections in
[`DESIGN.md`](DESIGN.md).

## Repository map

- `src/pass`: LLVM IR and late machine passes.
- `src/runtime`: the BPF-side memory and continuation runtime.
- `src/libc`: freestanding libc, allocator, integer, math, and soft-float
  support that applications may compile into managed bitcode.
- `src/rust`: the `no_std` panic/runtime shim used by Rust bitcode.
- `cmake`: the single public build pipeline and installed package config.
- `examples`: downstream-style programs and pinned source fetches.
- `benchmarks`: direct-eBPF and native overhead comparisons.
- `tests`: the `cmake-package` install smoke project, generic compiler-shape
  integration tests in `tests/integration`, clean-kernel definitions, and the
  proof-suite driver.
- `tools`: reproducible example data and fixture helpers.
- `docs`: the programming contract, example guide, and third-party notices.

## License

The compiler, runtime, build integration, and project-authored examples use
Apache-2.0 with the LLVM exception. The Doom example is GPL-2.0-only; the
shared host API header it includes is dual-licensed for compatibility. Other
third-party material retains its own license. See
[`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md) for exact source pins,
generated exceptions, and notices.
