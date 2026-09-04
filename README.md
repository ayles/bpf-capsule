# BPF Capsule

[![CI](https://github.com/ayles/bpf-capsule/actions/workflows/ci.yml/badge.svg)](https://github.com/ayles/bpf-capsule/actions/workflows/ci.yml)

BPF Capsule compiles freestanding C, C++, and `no_std` Rust into ordinary
libbpf-loadable eBPF objects. It lets programs with recursion, indirect calls,
deep stacks, data-dependent loops, dynamic allocation, and large linked
libraries run in the kernel without a custom kernel or a userspace VM.

It already runs PureDOOM, Lua, QuickJS, SQLite, zlib, wasm3, llama2.c, and
Rust `core`/`alloc` inside BPF.

## How can large programs run in the kernel?

An ordinary BPF entry starts a Capsule computation with `capsule_call()` (or
`capsule_call_ctx()` when managed code needs the entry's verifier-owned
context).
The compiler follows the root function, its callees, and possible callback
targets to find the complete computation. After optimization and limited
inlining, it cuts the computation into small, self-contained execution
regions. A region is a bounded piece of ordinary control flow that runs until
a transformed call, return, yield, or loop boundary.

Each active computation leases a **fiber**. Its control record stores the
current region number, software stack and frame pointers, completion status,
and continuation generation. The runtime calls the region number the **PC**,
but it is a dense compiler-assigned resume-point ID, not a machine instruction
address.

Each fiber also owns a fixed slice of a **software stack** in Capsule memory.
Arguments, call linkage, and values that must survive a region boundary live
there. This is separate from BPF's 512-byte `r10` stack, which the generated
code still uses within the normal limit while executing the current region.

At a call between regions, the caller stores its live values and a complete
call frame — return region, result slot, fixed arguments and any variadic
tail — in the software stack, publishes the callee's entry region, and returns
to the dispatcher. The callee later writes the result there, publishes the
caller's resume region, and returns through the dispatcher too. A loop that
cannot stay inside one region runs a bounded chunk, saves its loop-carried
values and resume region, and crosses the same boundary.

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
  exchange large buffers and follow pointers returned by BPF without address
  translation or object serialization.
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
  useful freestanding libraries possible on a CPU target that has no FPU and
  almost no stack.

`bpf-capsule-cc` compiles C and C++ to LLVM bitcode; Cargo supplies bitcode for
Rust. `bpf-capsule-ld` links and optimizes the whole program, performs the
Capsule transformation, and emits the final BPF object.

Generated objects load through ordinary libbpf on unmodified x86-64 and arm64
kernels. The test matrix starts at Linux 5.15; newer profiles use `bpf_arena`
and indirect region dispatch where the kernel and JIT support them.

[DESIGN.md](DESIGN.md) is the technical description of the current system: the
execution model, fibers, software calling convention, memory backends,
compiler pipeline, and verifier constraints.

## Build

Tests and examples are separate CMake projects built against the installed
SDK. With Nix:

```sh
nix build                                # the SDK: bpf-capsule-cc, bpf-capsule-ld, host library
sudo nix run .#doom -- /path/to/doom.wad tty
nix flake check                          # the complete test matrix
nix run .#benchmarks                     # local in-kernel measurements
```

The Nix example packages target Linux 6.9 or newer on x86-64 and 6.10 or
newer on arm64. Compatibility profiles back to 5.15 are covered by the test
matrix.

Without Nix, building the SDK requires CMake 3.24 or newer, C17 and C++20
compilers, LLVM and Clang 23 from the same installation, pkg-config, and
libbpf 1.4 or newer. Generating a libbpf skeleton also requires `bpftool`.
Install the SDK to a prefix, then point a consumer project at it:

```sh
cmake -S . -B build/sdk -DCMAKE_BUILD_TYPE=Release
cmake --build build/sdk
cmake --install build/sdk --prefix "$PWD/build/prefix"
cmake -S examples/fib -B build/fib -DCMAKE_PREFIX_PATH="$PWD/build/prefix"
cmake --build build/fib
```

The tools also work directly. `bpf-capsule-cc` compiles the application, the
installed `runtime/bpf_capsule.c`, and each installed libc source into ordinary
bitcode in exactly the same way; pass all resulting `.bc` files to
`bpf-capsule-ld`. The libc compilation additionally needs its `include` and
TLSF directories on the include path. The default output targets conservative
v3 BPF with fixed-map memory. For an arena build, compile the runtime with
`BPF_CAPSULE_FEATURE_ARENA=1` and pass `--memory=arena` to the linker; an atomic
allocator similarly pairs `BPF_CAPSULE_FEATURE_FULL_ATOMICS=1` on libc with
`--allocator-lock=atomic`. The linker rejects mismatched inputs and options.

## Use from CMake

A minimal consumer is:

```cmake
find_package(BpfCapsule CONFIG REQUIRED)

bpf_capsule_object(guest_bpf OUTPUT guest.bpf.o SOURCES guest_bpf.c)
bpf_capsule_skeleton(guest_skeleton OUTPUT guest.skel.h OBJECT "${guest_bpf}" NAME guest)

add_executable(guest guest_host.c)
target_link_libraries(guest PRIVATE BpfCapsule::host guest_skeleton)
```

`bpf_capsule_object` compiles the guest sources, adds the Capsule runtime and
freestanding C library, and returns the completed object's path. Pass that path
to `bpf_capsule_skeleton`; its linkable target carries the generated header and
embeds the object in the host executable.

The host lifecycle brackets libbpf's own load: call
`bpf_capsule_configure()` before loading the object,
`bpf_capsule_initialize()` afterward, and `bpf_capsule_release()` before
destroying it. Drive each entry through the Capsule result protocol.

The API is defined by the
[host header](src/runtime/host/bpf_capsule_host.h),
[guest header](src/runtime/guest/bpf_capsule.h), and
[shared types](src/runtime/guest/bpf_capsule_types.h). The compiler/runtime
[object ABI](src/runtime/internal/bpf_capsule_abi.h) is private.

## Limits

The Capsule environment is freestanding:

- Capsule-transformed code has no operating-system calls, threads, or general
  TLS;
- C `setjmp`/`longjmp` works within a live Capsule invocation, but C++
  exceptions, RTTI, and general cleanup unwinding are disabled;
- an entry context may be lent explicitly with `capsule_call_ctx()` and read in
  managed code with `capsule_borrowed_ctx()`; verifier-owned pointers derived
  from it may not be stored in Capsule state across a region boundary;
- all program and fiber capacities remain finite compile-time or load-time
  bounds.

Unsupported forms are compile errors. BPF Capsule is research software and is
not a security boundary.

## Performance

Native-relative performance varies with the workload, architecture, and
kernel. Many current integrations run a few times to around an order of
magnitude slower than native userspace; frequent region handoffs and software
floating point can cost considerably more. The [benchmarks](benchmarks) provide
exact local measurements.

The project is licensed under Apache-2.0 with the LLVM exception. Fetched and
vendored components retain their upstream licensing notices.
