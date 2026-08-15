# BPF Capsule — Execution Model and Supported Subset

This is the honest boundary of what "unmodified libraries run in the kernel as
eBPF" means: what is compiled, how it is driven, what is accepted, what is
rejected at compile time, what terminates at run time, and on which kernels.

## What a Capsule is

The compiler takes freestanding C (and no_std Rust) and rewrites it, through an
out-of-tree LLVM pass pipeline, into an eBPF object the verifier accepts. Code
splits into two domains:

- **Native** domain: ordinary verifier-visible eBPF. The entry program and a
  small number of runtime leaves live here.
- **Capsule** domain: everything reachable from a `capsule_call()`. It is
  transformed into a software-stack continuation machine ("stackify") so a
  program with real call depth, data-dependent loops, and recursion fits the
  verifier's 512-byte stack and acyclic-CFG limits.

The entry program calls a **trampoline** whose nested bounded driver may
dispatch millions of **step groups** from the top **software frame** on a
leased **fiber** in one BPF invocation. Only work that outlives that compiled
span returns `CAPSULE_PENDING` and needs a later userspace **drain**.

## Program types and how they are driven

- Most examples and tests use `SEC("syscall")` entries driven synchronously.
  Lua-XDP and the context-interoperability tests also exercise `SEC("xdp")`
  entries with a live packet context.
- Hosts drive programs with `bpf_prog_test_run_opts`. Inputs are staged by
  updating control/data map sections (`.data.*` / `.bss.*`); outputs are read
  back from those explicitly sectioned control maps. Lua-XDP alone uses a
  per-CPU exchange map. XDP entries additionally receive packet bytes through
  `struct xdp_md`.
- The host selects active fibers and heap bytes before load with
  `bpf_capsule_configure()` (`bpf_capsule_host.h`), loads with libbpf's own
  object/skeleton call, then runs `bpf_capsule_finish_initialization()` once
  before the first entry.

## Loader contract

A Capsule object can be loaded by any BPF loader, not only libbpf; a
non-libbpf ecosystem (cilium/ebpf, aya) reimplements this contract in its own
language, with the C implementation in `bpf_capsule_host.h`
(`__bpf_capsule_plan` and `bpf_capsule_configure`) as the reference:

1. **Plan.** Read the object's `.rodata.bpfconfig` section (a
   `struct __bpf_capsule_object_config`, layout in `bpf_capsule_abi.h`) and
   first require a complete record whose `abi_magic` is
   `BPF_CAPSULE_ABI_MAGIC` and whose `abi_version` is
   `BPF_CAPSULE_ABI_VERSION`. Reject a short record as a foreign object and an
   incompatible discriminator as a malformed plan; do not read or modify a
   partial record. Then
   derive the layout from the requested fiber count, heap bytes, and
   host-reserved heap prefix: `heap_reserved = align_up(reserved_bytes, 16)`
   (the guest allocator sees only the remaining suffix) and
   `heap_end = heap_base + heap_bytes`. Let `stack_floor` be zero for arena
   objects and `32 × 2 MiB` for fixed-map objects; let `stack_alignment` be
   4 KiB and 2 MiB respectively. Then
   `stack_base = align_up(max(heap_end, stack_floor), stack_alignment)` and
   `memory_end = stack_base + fiber_count × stack_bytes_per_fiber`. The
   fixed backend gets `ceil(memory_end / 2 MiB) - 32` ARRAY entries. The
   arena gets `arena_image_pages + ceil(memory_end / 4 KiB)` pages. Every
   addition, multiplication, alignment and narrowing is overflow-checked.
   The record carries its own memory tier (`uses_arena`), so no other input
   exists.
2. **Apply, before load.** Store the finished record back into
   `.rodata.bpfconfig` and set `max_entries` on the backend maps:
   `bpf_capsule_fiber_leases` / `bpf_capsule_issued_fibers` /
   `bpf_capsule_free_fibers` (whichever exist) and
   `bpf_capsule_continuation_claims` to the fiber count,
   `bpf_heap_array` to the overflow-region count (fixed-map tier), `arena`
   to the page count (arena tier).
3. **Load** with the loader's ordinary mechanism. Loading with the compiled
   defaults needs neither step above: the object ships a complete valid
   layout.
4. **Initialize.** If the object has a `bpf_capsule_init` program, run it
   once (one `BPF_PROG_TEST_RUN`; a negative program return value is the
   failure errno) before the first entry.

Bulk memory access mirrors `bpf_capsule_memory_write/read()`: on the arena tier,
copy through the load-time arena mapping (its identity matters — guest
pointers are the low 32 bits of that mapping) after the
`__bpf_capsule_arena_control` record in `.data.bpfctrl` reports ready; on
the fixed-map tier, split copies at 2 MiB region boundaries across the
`.data.heapN`/`.bss.heapN` mappings and the mmapable `bpf_heap_array`
entries, and refresh a region's 8-byte shadow suffix whenever a write
touches the next region's first 8 bytes.

The object defends the contract itself: the first `capsule_call` re-validates
the applied plan and reports `CAPSULE_ERROR_BAD_PLAN` if a loader stored the
configuration without resizing the backing maps (or applied it partially),
so a half-applied plan fails loudly under any loader instead of faulting
later.

## Memory model — two tiers

- **Arena tier** (compiled for `-DBPF_CAPSULE_TARGET_KERNEL=6.9`): the software stack,
  heap, and relocated globals live in a `bpf_arena` mapping; accesses are one
  instruction via `addr_space_cast`. A runtime-chosen base is published in
  `bpf_capsule_arena_control.virtual_base`, so the layout is independent of any libbpf arena
  placement. The host API requires libbpf 1.4 or newer; its exact arena image
  placement is not part of this ABI.
- **Fixed-map tier** (`-DBPF_CAPSULE_TARGET_KERNEL=5.15`): the same virtual space is
  backed by statically sized BPF maps (a helper-free direct-map region up to
  the proven map budget, then an ARRAY-map overflow region). Accesses go
  through compiler-synthesized width-specific accessors.

The tier is selected purely from the kernel target; `src/pass/target.cpp` maps
version → features (arena ≥ 6.9, cpu-v4 ≥ 6.6) → strategy.

## Supported input subset

Accepted: freestanding C / no_std Rust with integer and pointer arithmetic,
aggregates, unions, bitfields, function pointers / indirect calls (threaded
interpreters), data-dependent loops and recursion (virtualized), 128-bit
integers (legalized), defined variadic functions and struct returns
(ABI-expanded), and scalar
`float`/`double` values (software-emulated; binary32 add/sub/mul are bit-exact).

**Rejected at compile time** (clean diagnostic, `emitError`):

- Atomic read-modify-write, compare-exchange, fences, or any ordered atomic in
  the Capsule domain — `bpf-lower-atomics` accepts only relaxed naturally
  aligned 1/2/4/8-byte integer/pointer loads and stores there. There is no RMW
  fallback on either tier. (Native-domain code and the runtime's map-lease
  linearization point are the only synchronization.)
- A verifier-owned pointer (the borrowed XDP context) stored into the software
  frame, returned across a Capsule boundary, or passed through a suspension.
- A scalable VLA element, an element wider than the fixed per-frame reserve,
  or a dynamic `alloca` that survives the VLA-lowering contract.
- Floating-point vectors and scalar floating-point types wider than 64 bits.
- Calls to declared-only variadic externals. Use a non-variadic wrapper with a
  fixed signature.

**Terminated at run time** (`CAPSULE_EXITED` with a negative framework code,
surfaced through `capsule_result`):

| value | code | meaning |
| ---: | --- | --- |
| -1 | `CAPSULE_ERROR_POOL_EXHAUSTED` | no configured fiber was available |
| -2 | `CAPSULE_ERROR_INVALID_CONTINUATION` | malformed continuation token |
| -3 | `CAPSULE_ERROR_STALE_CONTINUATION` | token was consumed or belongs to an older fiber lease |
| -4 | `CAPSULE_ERROR_NOT_PENDING` | continuation named a fiber with no suspended stack |
| -5 | `CAPSULE_ERROR_POOL_CORRUPT` | fiber-pool or continuation-claim invariant failed |
| -6 | `CAPSULE_ERROR_RETURN_MISMATCH` | caller-provided return storage disagrees with the compiled return ABI |
| -7 | `CAPSULE_ERROR_STACK_OVERFLOW` | software-stack overflow |
| -8 | `CAPSULE_ERROR_MEMORY_FAULT` | invalid Capsule-memory access |
| -9 | `CAPSULE_ERROR_INVALID_DISPATCH` | bad dispatch id (corruption or forged function value) |
| -10 | `CAPSULE_ERROR_INTRINSIC_GUARD` | an internal compiler marker survived lowering |
| -11 | `CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC` | unsupported FP intrinsic |
| -12 | `CAPSULE_ERROR_VLA_BOUNDS` | VLA element count exceeds its per-frame reserve |
| -13 | `CAPSULE_ERROR_UNREACHABLE` | source `unreachable` was executed |
| -14 | `CAPSULE_ERROR_TRAP` | source trap/debug trap was executed |
| -15 | `CAPSULE_ERROR_UNSUPPORTED_LIBC` | unavailable freestanding libc operation, including `setjmp`/`longjmp` |
| -16 | `CAPSULE_ERROR_ALLOCATOR_CORRUPT` | allocator metadata failed an internal consistency check |
| -17 | `CAPSULE_ERROR_BAD_PLAN` | loader applied an incomplete or inconsistent capacity plan |

These are the wire values for the current `BPF_CAPSULE_ABI_VERSION`. Recording
them makes object/loader reimplementations unambiguous; it does not freeze the
pre-1.0 ABI.

Runtime status is reported through `enum capsule_status` (`CAPSULE_OK`,
`CAPSULE_PENDING`, `CAPSULE_YIELD`, `CAPSULE_EXITED`) and the
`CAPSULE_ERROR_*` pool-state codes. `bpf_capsule_status_string()` and
`bpf_capsule_error_string()` return allocation-free text for every framework
value; other 64-bit errors belong to the application.

**Not supported**: threads, signals, C++ exceptions, general nonlocal exits
(`setjmp`/`longjmp` compile but terminate with `CAPSULE_ERROR_UNSUPPORTED_LIBC`
if executed), real syscalls, unbounded dynamic allocation beyond the
configured heap, and anything requiring FP hardware semantics beyond the
documented binary32 add/sub/mul guarantee.

## Supported kernels (tested only)

- **Map tier**: compiled for the Linux 5.15 compatibility floor and proved in
  the clean nixpkgs 5.15-series VM.
- **Arena tier**: compiled for the 6.9 arena feature ABI, but on arm64 the
  features arrive across later kernels — basic arena JIT in 6.10, and
  sign-extending arena loads plus arena access from XDP only around 7.0. The
  full arena tier is therefore proved in a clean VM using the current nixpkgs
  kernel rather than claiming that a literal 6.9 kernel implements it.

Large map-tier objects such as QuickJS, SQLite, and Doom can spend tens of
seconds in Linux 5.15's verifier and branch-adjustment/JIT load path. On a
small or busy VM this can also produce watchdog or RCU-stall warnings before a
successful load. That is verifier/load latency, not Capsule execution time;
judge it by the final load result and keep it separate from `run_time_ns`.

Every generated report records both the compile profile and the execution
kernel's complete `uname`; those reports, rather than a patch release pinned in
this specification, identify the kernel used for a verifier claim.

## Determinism and overhead

Every proof-suite workload is compared to a native reference and required to
match byte-for-byte (text output, framebuffer PPM tree, or checksum).
Real-library hosts with a continuation loop report an exact drain count and
the regression suite requires zero. Single-entry and attached cases reject
`CAPSULE_PENDING` and have no drain path. Dedicated continuation tests
deliberately drain. Overhead is workload-dependent and
measured by the benchmark matrix; the arena tier is the fast path and only
reaches full speed on a kernel with the complete arena feature set.

## Security posture

A Capsule program runs as root-privileged eBPF loaded by its host. This is not
a sandbox: the verifier bounds memory safety and termination of the loaded
program, but the host that loads and drives it has full privilege. The value is
that arbitrary bounded computation is made verifier-acceptable, not that
untrusted code is isolated.

## ABI compatibility policy

The magic and version fields make an object/loader mismatch fail explicitly;
they are not a promise that the pre-1.0 ABI is frozen. Until a stable release,
object layout and helper contracts may change with an ABI-version increment.
Rebuild BPF objects and hosts from the same BPF Capsule installation. A loader
must reject an unknown magic/version rather than guessing a compatible layout.
