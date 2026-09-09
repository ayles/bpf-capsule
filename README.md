# BPF Capsule

[![CI](https://github.com/ayles/bpf-capsule/actions/workflows/ci.yml/badge.svg)](https://github.com/ayles/bpf-capsule/actions/workflows/ci.yml)

BPF Capsule compiles C, C++, and `no_std` Rust into ordinary libbpf-loadable
eBPF objects. It lets programs with recursion, indirect calls,
deep stacks, data-dependent loops, dynamic allocation, and large linked
libraries run in the kernel without a custom kernel or a userspace VM.

It already runs PureDOOM, CPython, Lua, QuickJS, SQLite, zlib, wasm3,
llama2.c, and Rust `core`/`alloc` inside BPF. The CPython and Lua integrations
also run user-supplied packet observers directly from XDP.

## How can large programs run in the kernel?

An ordinary BPF entry starts a Capsule computation with `capsule_call()` (or
`capsule_call_ctx()` when managed code needs the entry's verifier-owned
context).
The compiler follows the root function, its callees, and possible callback
targets to find the complete computation. After optimization and limited
inlining, it cuts the computation into small, self-contained execution
regions. A region is a bounded piece of ordinary control flow that runs until
a transformed call, return, yield, or loop boundary.

Each active computation leases a **fiber**. Its control record stores a packed
resume region ID, software stack and frame pointers, completion status, and
continuation generation. A region is a suspension-free piece of code; its ID
is an integer, not an address. The low eight bits select a physical step and
the next sixteen identify the region inside that step.

Each fiber also owns a fixed slice of a **software stack** in Capsule memory.
Arguments, call linkage, and values that must survive a region boundary live
there. This is separate from BPF's 512-byte `r10` stack, which the generated
code still uses within the normal limit while executing the current region.

At a call between regions, the caller stores its live values and a complete
call frame — return region ID, result slot, fixed arguments and any variadic
tail — in the software stack, publishes the callee's entry region ID, and
returns to the dispatcher. The callee later writes the result there, publishes
the caller's resume region ID, and returns through the dispatcher too. A loop
that cannot stay inside one region runs a bounded chunk, saves its loop-carried
values and resume region ID, and crosses the same boundary.

Every cross-region edge is therefore a return to the bounded driver. Recursive
source calls do not become recursive BPF calls, and dynamic loops become
repeated bounded chunks. The verifier checks bounded region units and
constant-trip dispatch loops; runtime repetition reconstructs the original
program flow.

In PureDOOM, engine initialization, the game tick, and software rendering
execute in BPF; userspace supplies external input and presents the resulting
framebuffer.

## Features

- **One address space, on both sides.** Capsule pointers have the same 64-bit
  value in BPF and userspace. Globals, heap, and software stacks occupy one
  host-visible window. Arena profiles map it with `bpf_arena`; fixed-memory
  profiles preserve the same address model over ordinary maps. A host can
  read and write memory directly, exchange large buffers, and follow pointers
  returned by BPF without address translation or object serialization.
  The host can also allocate and free through the guest allocator with
  `bpf_capsule_malloc()` / `bpf_capsule_free()`.
- **Resumable fibers.** Fibers have independent control state and stack slices
  while sharing program globals and the heap. If the drive budget ends,
  `capsule_call()` returns `CAPSULE_PENDING` and a generation-checked
  continuation to the BPF caller; a later entry can resume it with
  `capsule_continue()`. Capsule code can stop intentionally with
  `capsule_yield()`. Context computations use the matching `*_ctx` calls; the
  context is supplied afresh by the current BPF invocation and is never stored
  in the fiber.
- **The missing machine pieces are built in software.** Dynamic allocation,
  function pointers, software floating point, and wide-integer operations make
  useful libraries possible on a CPU target that has no FPU and almost no
  stack. Picolibc supplies the C library and libm; a small Capsule platform
  layer supplies fiber-local `errno`, TLSF allocation, and replaceable I/O and
  OS stubs.
- **Large programs can span ordinary BPF extensions.** On kernels with BPF
  trampoline support, the linker's `--freplace` option can place physical step
  functions from an otherwise oversized program in extension programs embedded
  in the same ELF. The host attaches them once before initialization; source
  calls, fibers, memory, and continuations keep exactly the same model.

`bpf-capsule-cc` compiles C and C++ to LLVM bitcode; Cargo supplies bitcode for
Rust. `bpf-capsule-ld` links and optimizes the whole program, performs the
Capsule transformation, and emits the final BPF object.

Generated objects load through ordinary libbpf on unmodified x86-64 and arm64
kernels. The test matrix starts at Linux 5.15; newer profiles use `bpf_arena`
and indirect root selection where the kernel and JIT support them.

[DESIGN.md](DESIGN.md) is the technical description of the current system: the
execution model, fibers, software calling convention, memory backends,
compiler pipeline, and verifier constraints.
[PLATFORM.md](PLATFORM.md) sketches the planned optional virtual filesystem,
stdio, clocks, and other Unix-like services for existing libraries.

## Build

Tests and examples are separate CMake projects built against the installed
SDK. With Nix:

```sh
nix build                                # the SDK: bpf-capsule-cc, bpf-capsule-ld, host library
sudo nix run .#doom -- /path/to/doom.wad tty
sudo nix run .#lua -- examples/lua/benchmark.lua
nix run .#lua -- --native examples/lua/benchmark.lua
nix flake check                          # the complete test matrix
nix run .#benchmarks                     # local in-kernel measurements
```

The plain example packages are built for the oldest supported kernel, 5.15,
so they run on any supported machine. A kernel floor suffix selects a faster
profile where the kernel and JIT support it: `.#lua-71`, `.#doom-69`,
`.#sqlite-610`. The CPython examples need arena memory and exist only from
`python-610` on arm64 and `python-69` on x86-64; their plain names build the
oldest of those.

Every script example (`lua`, `quickjs`, `sqlite`, `python`) runs the same
program natively with `--native` and reports its execution time either way:
`kernel execution` is the in-kernel run time from BPF's own accounting,
`native execution` the CPU time of the same code in the process. `llama2`
prints both from one run, and `doom` reports per-frame statistics for
whichever engine drew the frames. Each example directory carries a
`benchmark.*` workload for that comparison:

```console
$ sudo taskset -c 0 nix run .#lua -- examples/lua/benchmark.lua
$ taskset -c 0 nix run .#lua -- --native examples/lua/benchmark.lua
```

`BPF_CAPSULE_MAX_DRAINS` caps the continuations a run may use; without it a
run continues until it finishes.

Without Nix, building the SDK requires CMake 3.24 or newer, C17 and C++20
compilers, LLVM and Clang 23 from the same installation, pkg-config, and
libbpf 1.4 or newer. Linux UAPI headers and `patch` are also needed while
building the SDK; generating a libbpf skeleton additionally requires `bpftool`.
Install the SDK to a prefix, then point a consumer project at it:

```sh
cmake -S . -B build/sdk -DCMAKE_BUILD_TYPE=Release
cmake --build build/sdk
cmake --install build/sdk --prefix "$PWD/build/prefix"
cmake -S examples/fib -B build/fib -DCMAKE_PREFIX_PATH="$PWD/build/prefix"
cmake --build build/fib
```

Without CMake, compile application, guest runtime, and platform
sources with `bpf-capsule-cc`, then pass their `.bc` files and the installed
`libclang_rt.builtins.a` and Picolibc `libc.a` to `bpf-capsule-ld`. The compiler
locates its guest headers and sysroot automatically; the TLSF wrapper also needs the installed
TLSF include directory. Runtime feature defines must match the linker's memory
and allocator capabilities, which it checks at link time. The CMake helper
supplies these sources, includes, and defines automatically.

## Use from CMake

A minimal consumer is:

```cmake
find_package(BpfCapsule CONFIG REQUIRED)

bpf_capsule_object(guest_bpf OUTPUT guest.bpf.o SOURCES guest_bpf.c)
bpf_capsule_skeleton(guest_skeleton OUTPUT guest.skel.h OBJECT "${guest_bpf}" NAME guest)

add_executable(guest guest_host.c)
target_link_libraries(guest PRIVATE BpfCapsule::host guest_skeleton)
```

`bpf_capsule_object` compiles the guest sources, adds the Capsule runtime,
compiler runtime, platform layer, and Picolibc, and returns the completed
object's path. Pass that path to `bpf_capsule_skeleton`; its linkable target
carries the generated header and embeds the object in the host executable.

Reusable guest libraries are indexed bitcode archives:

```cmake
bpf_capsule_library(codec SOURCES codec.c)
target_include_directories(codec PUBLIC include)
target_compile_definitions(codec PRIVATE CODEC_TABLES=1)
bpf_capsule_object(guest_bpf OUTPUT guest.bpf.o SOURCES guest_bpf.c LIBRARIES codec)
```

The library is an ordinary CMake target with the usual `PRIVATE`, `PUBLIC`,
and `INTERFACE` scopes; `LIBRARIES` gives an object its usage requirements
and its archive. The third-party libraries used by the examples, tests, and
benchmarks live in `ports/`, one directory per upstream with its source pin,
patches, target, and license installation.

The host lifecycle brackets libbpf's own load: call
`bpf_capsule_configure()` before loading the object,
`bpf_capsule_initialize()` afterward, and `bpf_capsule_release()` before
destroying it. An object linked with `--freplace` also needs
`bpf_capsule_attach_freplace()` between load and initialization. Drive each
entry through the Capsule result protocol.

The API is defined by the
[host header](src/runtime/host/bpf_capsule_host.h),
[guest header](src/runtime/guest/bpf_capsule.h), and
[shared types](src/runtime/guest/bpf_capsule_types.h). The compiler/runtime
[object ABI](src/runtime/internal/bpf_capsule_abi.h) is private.

## Limits

The Capsule environment has a C library but no operating system:

- OS-facing functions such as `open`, `fork`, and `clock_gettime` fail with an
  ordinary error by default; their weak platform definitions can be replaced
  by an application-provided in-memory or context-backed implementation;
- there are no processes or threads; `_Thread_local` storage is fiber-local:
  each fiber owns an instance that persists across the calls made on it and
  is restored to its initial value by `capsule_reset`;
- `errno` is fiber-local and the allocator is concurrency-safe, but other
  libc interfaces with implicit mutable state (for example `strtok` or
  `localtime`) must not be shared by simultaneously running fibers;
- C `setjmp`/`longjmp` works within a live Capsule invocation, but C++
  exceptions, RTTI, and general cleanup unwinding are disabled;
- an entry context may be lent explicitly with `capsule_call_ctx()` and read in
  managed code with `capsule_borrowed_ctx()`; verifier-owned pointers derived
  from it may not be stored in Capsule state across a region boundary;
- all program and fiber capacities remain finite compile-time or load-time
  bounds.

The CPython examples pack the pure-Python standard library and statically link
the available C modules, including compression (`zlib`, `bz2`, `lzma`, `zstd`),
in-memory `sqlite3`, XML, decimal arithmetic and hashing. Filesystem access,
sockets, native dynamic extensions and OS-dependent modules remain unavailable.
`python-xdp` uses one isolated subinterpreter per fiber: a fiber is CPython's
thread, with real locks and `_Thread_local` state, but it cannot create
threads (`pthread_create` returns `EAGAIN`). A packet observer must finish
within one BPF invocation; if it suspends while waiting for a shared CPython
lock or exhausts the drive budget, the example reports the fault and stops
observing.
The batch example reserves 128 MiB of interpreter heap; XDP reserves 32 MiB per
fiber, plus input storage. Both choose a fresh hash seed on the host.

The loader requests strict alignment for all BPF programs in the object,
including native entry code and extensions. Non-arena memory accesses must
have verifier-provable alignment; Capsule splits underaligned fixed-tier
accesses using LLVM's alignment information.

Supported scalar atomics use hardware operations, with no lock-based fallback
for objects wider than 64 bits. Bare linker defaults target Linux 5.15 on both
architectures; full atomic support requires explicit target capabilities,
available on arm64 from Linux 5.18.

Unsupported forms are compile errors. BPF Capsule is research software and is
not a security boundary.

## Performance

Native-relative performance varies with the workload, architecture, and
kernel. Integer and pointer-heavy code such as DOOM or SQLite runs a few
times slower than native userspace, interpreters around an order of magnitude,
and floating-point-heavy code such as llama2.c's FP32 model several tens of
times, because every float operation is a software call. The examples measure
this themselves: run one with and without `--native`; the
[benchmarks](benchmarks) directory adds micro-benchmarks of the transformation
itself.

The project is licensed under Apache-2.0 with the LLVM exception. Fetched and
vendored components retain their upstream licensing notices. The exception
covers Capsule code embedded in compiler output, including output linked with
GPLv2 programs.
