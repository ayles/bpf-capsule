# BPF Capsule

BPF Capsule compiles freestanding C, C++, and `no_std` Rust into ordinary
libbpf-loadable eBPF objects. It lets programs with recursion, indirect calls,
deep stacks, data-dependent loops, dynamic allocation, and large linked
libraries run in the kernel without a custom kernel or a userspace VM.

It already runs PureDOOM, Lua 5.4, QuickJS, SQLite, zlib, wasm3, llama2.c, and
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

At a call between regions, the caller stores its live values, arguments, and
return region in the software stack, publishes the callee's entry region, and
returns to the dispatcher. The callee later writes any result into the
caller's frame, publishes the caller's resume region, and returns through the
dispatcher too. A loop that cannot stay inside one region runs a bounded
chunk, saves its loop-carried values and resume region, and crosses the same
boundary.

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

Memory and dispatch are selected by the target profile:

| Target | Program memory | BPF CPU | Region dispatch |
| --- | --- | --- | --- |
| 5.15 | fixed map-backed regions | v3 | compare tree |
| 6.6 | fixed map-backed regions | v4 | compare tree |
| 6.9 | `bpf_arena`, compatibility lowering for signed loads | v4 | compare tree |
| 7.0 | `bpf_arena` | v4 | compare tree |
| 7.1 | `bpf_arena` | v4 | instruction-array `gotox` |

`BPF_CAPSULE_TARGET_KERNEL` selects the compatibility profile at compile time.
Guest pointers and the continuation ABI remain identical across profiles.

[DESIGN.md](DESIGN.md) is the technical description of the current system: the
execution model, fibers, software calling convention, memory backends,
compiler pipeline, and verifier constraints.

## Build

Build the compiler with the pinned Nix environment:

```sh
nix build
```

The example bundles fetch and build their third-party sources separately:

```sh
nix build .#examples-515
nix build .#examples-69
```

Each example is also directly runnable. For example:

```sh
sudo nix run .#lua-xdp -- "$PWD/examples/lua-xdp/packet_observer.lua" eth0
```

The compiler drivers are exposed explicitly as `.#bpf-capsule-cc` and
`.#bpf-capsule-ld`; there is no default app because the flake has no single
main executable.

Without Nix, provide CMake 3.21 or newer, LLVM and Clang 23 from the same
installation, libbpf 1.4 or newer, bpftool, pkg-config, libelf, zlib, and zstd.

For source changes, enter `nix develop`, configure and build with CMake, then
run both test labels and the release matrix:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build -L '^unprivileged$' --output-on-failure
sudo "$(command -v ctest)" --test-dir build -L '^privileged$' --output-on-failure
nix flake check
```

Useful configuration variables are:

```text
BPF_CAPSULE_TARGET_KERNEL       5.15, 6.6, 6.9, 7.0, or 7.1
BPF_CAPSULE_FIBER_STACK_BYTES   power-of-two software stack size
BPF_CAPSULE_MAX_FIBERS          compiled concurrency ceiling
BPF_CAPSULE_BUILD_EXAMPLES      build selected third-party examples
BPF_CAPSULE_EXAMPLES            semicolon-separated names, or all
```

CMake defaults to the 6.9 profile. The default Nix package explicitly builds
the 5.15 compatibility floor; named packages select the profile in their
suffix.

## Use from CMake

A minimal CMake consumer looks like this:

```cmake
find_package(BpfCapsule CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)

set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)
set(BPF_CAPSULE_TARGET_KERNEL 6.9)

bpf_capsule_bitcode(guest_bc
    SOURCES guest.c library.cpp
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include)

bpf_capsule_object(guest_object
    OUTPUT guest.bpf.o
    BITCODE ${guest_bc})

bpf_capsule_skeleton(guest_skeleton
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/guest.skel.h
    OBJECT ${CMAKE_CURRENT_BINARY_DIR}/guest.bpf.o
    NAME guest
    DEPENDS guest_object)
```

`bpf_capsule_object` adds the Capsule runtime automatically. The generated
libbpf skeleton embeds the completed object in the host executable. See the
[standalone expression evaluator](examples/standalone) for a complete consumer
of the installed package.

The host lifecycle brackets libbpf's own load:
`bpf_capsule_configure()` runs before it (capacities plus the reserved memory
window whose base is baked into the frozen config), and
`bpf_capsule_initialize()` runs after it (arena allocation and baked-pointer
fixups; entries fail closed until it has run). Drive each entry through the
Capsule result protocol. Call `bpf_capsule_release()` before libbpf destroys
the object; it releases the host mapping and reserved address-space window and
is safe after partial setup.

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
- Capsule atomic loads and stores support the checked, naturally aligned
  forms, while read-modify-write operations and compare-exchange on Capsule
  memory, fences, and unsupported orderings are rejected;
- freestanding `strtod` reports no conversion and `atof` returns zero; Lua
  cannot parse floating-point literals or strings, though arithmetic works;
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
vendored components retain their own license files.
