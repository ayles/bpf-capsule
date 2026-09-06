# How Capsule works

For a reader who knows x86-64 and eBPF but nothing about Capsule.

## The problem, and the one idea

The eBPF verifier admits a program only if it can statically prove termination
and memory safety. Capsule targets the limits of its oldest supported kernels:
~1M instructions of exploration budget, an 8192-jump bound per explored path,
512 bytes of stack for the whole call chain, 8 call frames, 256 subprograms per
loaded program, no unbounded loops, and every pointer typed and bounds-proven.
Programs such as Lua, SQLite, zlib, and Doom exceed several limits at once.

The compiler transforms the whole program into bounded regions and persistent
state. Each region stores its resume point and returns to a bounded driver,
which enters the next region. Repetition happens inside one BPF invocation
through constant-bound driver loops and, when those end, across invocations
through continuations. Source-level call depth and loop counts therefore do
not become verifier call depth or unbounded BPF loops.

## Two worlds and the boundary

The compiler partitions every object into two domains and rejects overlap
(`bpf-capsule-domains`: a function reachable from both native code and a
`capsule_call` is a build error).

- **Native domain**: ordinary eBPF — entry programs, the dispatcher, and
  functions proven suspension-free. Plain BPF ABI, native stack, verified
  as usual.
- **Managed domain**: the transformed world where the program lives. Its
  persistent state does not live on the BPF stack, its source-level calls do
  not become BPF calls, and it can suspend at compiler-inserted points.

The ordinary boundary is `capsule_call(&output, f, args...)` in an entry
program. `capsule_call_ctx(ctx, &output, f, args...)` additionally lends the
entry's verifier-owned context without adding it to `f`'s source signature.
Output size, alignment, and type are checked against `f` at compile time. The
call lowers to: acquire a **fiber**, lay out the ordinary arguments in fiber
memory, set the fiber's PC to `f`'s entry, and drive. The drive
returns `struct capsule_result { int32 code; enum capsule_status status;
uint64 continuation; }`: `OK`, `EXITED` (one signed code space shaped like
a shell's `$?` — 0..255 guest codes, negatives reserved for the
framework), `YIELD`, or `PENDING` — the in-kernel drive budget ended before
the computation did. Pending is not an error: `continuation` (fiber id +
generation) is a resumable handle. A later BPF entry calls
`capsule_continue(&output, continuation)`; a context computation instead uses
`capsule_continue_ctx(ctx, &output, continuation)` and lends that invocation's
live context. The host invokes the entry until the computation finishes. The
erased return type is re-checked at runtime against a byte-count witness
stamped into the fiber by the original call. That is how a long-running
computation such as llama2 outlives one invocation.

## One window, one pointer representation

Before load, `bpf_capsule_configure()` reserves a 4GiB-aligned **memory
window**, initially PROT_NONE, with a small code-identity tail above the data
span. Its base becomes a frozen config value that the verifier constant-folds.
Every Capsule pointer is `window + displacement`, with the same value in BPF
and userspace:

- data lives in the first 4GiB: relocated globals, the heap at `heap_base`,
  then the per-fiber stack bank, slice-aligned so frame math can mask;
- code lives just above it: a managed function's address is
  `window + 4GiB + entry-pc`, non-managed function identities follow in
  the next 1MiB. Code and data cannot collide as 64-bit values, and since
  the window is 4GiB-aligned, an indirect call recovers the entry pc by
  truncating the token to its low word — free in BPF, whose 32-bit ALU
  zero-extends;
- `NULL` is 0, outside the window. The first page and unbacked remainder stay
  PROT_NONE, so host accesses to those addresses fault.

Explicitly sectioned globals retain their native BPF maps instead of moving
into this window; they can be shared with ordinary BPF code.

The two tiers differ only in what backs the window. Availability is a property
of both the kernel and its JIT: x86-64 gained arena support in Linux 6.9 and
arm64 in 6.10.

| Kernel floor | x86-64 memory | arm64 memory | BPF CPU | Region dispatch |
| --- | --- | --- | --- | --- |
| 5.15 | fixed maps | fixed maps | v3 | compare tree |
| 6.6 | fixed maps | fixed maps | v4 | compare tree |
| 6.9 | `bpf_arena`, signed-load lowering | fixed maps | v4 | compare tree |
| 6.10 | `bpf_arena`, signed-load lowering | `bpf_arena`, signed-load lowering | v4 | compare tree |
| 7.0 | `bpf_arena` | `bpf_arena` | v4 | compare tree |
| 7.1 | `bpf_arena` | `bpf_arena` | v4 | instruction-array `gotox` |

Nix maps these kernel/JIT profiles to explicit linker capabilities in
[`nix/target-profile.nix`](nix/target-profile.nix); the compiler drivers contain
no kernel-version table.

- **Arena tier**: libbpf maps the arena at the window base with MAP_FIXED;
  the kernel records it as `user_vm_start`. Guest memory accesses use arena
  instructions.
- **Fixed tier**: on targets without arena support, memory is stitched from
  disjoint 4MiB map values. Direct `.data`/`.bss` maps hold the initialized
  image and the start of memory; one overflow ARRAY holds the remaining
  regions. Generated accessors recover the offset by truncation and select
  the region with `offset >> 22`. Before routing, loads and stores whose LLVM
  alignment is smaller than their width are split into naturally aligned
  fragments, each routed to its own map. These transformations trust LLVM's
  alignment claims; falsely claiming a stronger alignment is undefined
  behavior, not a runtime-checked error.

Both tiers expose the same writable pages to host and guest after
`bpf_capsule_initialize()`. Ordinary dereferences and `memcpy` work on either
side; concurrent access needs synchronization. The loader requests
`BPF_F_STRICT_ALIGNMENT` for every program, including native entry code and
freplace extensions. The verifier must prove alignment for non-arena accesses;
arena pointers are exempt. Atomics still require natural alignment.

The direct-map count is fixed at link time and recorded in the config.
After reserving slots for other maps and data sections, the linker rounds the
remaining 64-map budget down to a power of two. Usually this selects 32 direct
maps, allocating **128MiB at load even for a small heap**; overflow ARRAY
storage scales with the configured heap and fiber stacks.
`--direct-map-regions=N` can reduce that baseline or choose any count within
the available budget. More direct memory avoids ARRAY lookups for accesses
in that range; heap capacity remains a separate load-time choice.

Pointer initializers are stored as displacements until initialization rebases
them. The arena initializer applies fixups in BPF; on fixed memory the host
uses the `.rodata.bpffix` table. Neither tier runs application code before
initialization publishes readiness.

## The machine model: a fiber is the CPU you don't have

BPF has no persistent registers across invocations, so Capsule keeps a
virtual CPU's state in memory. Per fiber, 40 bytes in `.bss.bpfctrl`
(host-visible):

```c
struct __bpf_capsule_fiber_control {
    enum capsule_status status; // 0 while running; EXITED/YIELD on a terminal event
    int32_t  code;              // signed termination code for EXITED
    uint64_t generation;        // continuation staleness check
    uint64_t sp;                // allocation frontier: a full pointer
    uint64_t fp;                // running frame boundary: a full pointer
    uint32_t pc;                // 0 idle, ~0 done, else entry/resume PC
    uint32_t return_size;       // erased-return-type witness for continue
};
```

`pc` is a dense compiler-assigned resume-point index, not an instruction
address. It also records lifecycle: 0 means idle, `BPF_CAPSULE_PC_DONE` means
complete but not yet reaped. `sp` and `fp` are full pointers into the fiber's
power-of-two stack slice. Exits and yields publish `{status, code}` with one
64-bit store; readers follow it through program order or the continuation
claim. Fibers have separate stacks but share globals and the heap.

## The managed ABI

Normal eBPF passes arguments in r1–r5 with a real call stack. The managed
world replaces all of it:

- **Frames** use the familiar downward x86 shape. `fp` points at the saved
  caller `fp`, the 32-bit resume PC occupies `fp+8`, and locals grow toward
  lower addresses. The caller owns everything above that linkage: an optional
  result slot followed by the actual arguments. There is no result register.
  Each function's local-frame size is an immediate in its prologue, checked
  against the slice floor (`fp & (slice-1)` is exact because the bank is
  slice-aligned) before `sp` moves, so overflow is a clean
  `CAPSULE_ERROR_STACK_OVERFLOW` at the offending entry.
- **Arguments** proceed toward higher addresses in source order, each with an
  eight-byte minimum slot and its stronger natural alignment preserved.
  Variadic arguments immediately follow the fixed prefix: `va_list` is an
  ordinary cursor, and `va_arg(T)` aligns and advances it by `T`. The callee
  receives no hidden count; as in C, its format, count or sentinel determines
  how many values it reads. Values such as `i128` occupy their full rounded
  size. Although Clang represents a C aggregate passed by value as a pointer
  with a `byval` attribute, the managed slot contains the object itself; the
  callee materializes that slot's address, with no pointer slot or second copy
  area. The compiler wrapper preserves the size and alignment of aggregate
  `va_arg` expressions until stackify for the same inline layout. Indirect
  calls use it too because every call instruction still carries its ABI
  signature, attributes, and actual operands. The complete outgoing size is
  known at that call site, so it is not stored in the frame or exposed through
  `va_list`.
- **The fiber slice has two owners.** Managed frames and variable-size
  allocations occupy its upper half. Eligible scalar spills created by BPF
  register allocation use a transient extent in the lower half, reused by
  every region. Stackify bounds source-level stack descent; the post-RA spill
  pass independently rejects a physical extent that cannot fit below
  the midpoint.
- **Dynamic allocations move `sp`.** Each site checks the element count and
  byte size before subtracting, then keeps the resulting pointer in a fixed
  frame slot so it survives suspension. `stacksave` records `sp` and
  `stackrestore` restores it. Return performs the software equivalent of
  `leave; ret`; the caller's resume region then reclaims its statically known
  outgoing area, including every actual variadic argument.
- **A managed call is a suspension**: the caller serializes its live
  values, writes its resume PC into the linkage and the callee's PC into
  the fiber control, and returns to the dispatcher; return is symmetric.
  This handoff is the machine's fundamental call cost and the reason the
  inline policy matters. Stackify also inlines a compact non-recursive helper
  with exactly one direct managed caller, removing the handoff without
  duplicating source IR.
- **Exit is not a return**: `exit(code)`, traps and unreachables publish
  `{status, code}` and surface as `EXITED`; they never unwind.

`setjmp` saves `{pc, sp, fp}` and its result slot in the caller's `jmp_buf`;
`longjmp` restores them and resumes at the saved region. General C++ cleanup
unwinding is not implemented.

The native ABI survives at the rim: entry programs, the dispatcher chain,
and the **nosuspend class**. `CAPSULE_NOSUSPEND` (public, in
`bpf_capsule.h`) marks a function the compiler must prove suspension-free
over its whole call closure — exact-constant-trip loops only, direct
resolved calls, bounded body and native frame — or fail the build naming
the reason. Proven functions compile as ordinary global BPF subprograms:
plain call cost, and the whole call completes inside a single BPF
invocation, which makes holding a lock across one legal. The runtime's
allocator is the canonical user: a native compare-exchange lease on capable
JITs (a map lease below the 6.9 profile), an O(1) TLSF metadata operation,
release — atomic with respect to suspension — while the managed `malloc()`
wrapper retries (and may suspend) around `BUSY`, so waiting happens without
the lock.

Function classes are declared by explicit attribute, never inferred from
names; symbol names are link-time contracts only.

The library boundary is conventional. Picolibc is a profile-neutral bitcode
archive, and the linker extracts only members reached by the application.
Capsule owns the smaller pieces that cannot be generic: compiler-emitted
soft-float and wide-integer helpers, fiber-local `errno`, the TLSF heap adapter,
and weak OS-facing functions that fail unless the application replaces them.
These sources are compiled like any other guest translation unit before the
whole-program link. `errno` follows the fiber and the heap is synchronized;
other libc APIs with implicit process-global state retain Picolibc's
single-threaded contract and cannot be shared concurrently across fibers. The
default platform has no environment or timezone database, so local time is UTC.

The bare linker defaults are fixed memory, BPF v3, and a map-based allocator
lease. Native read-modify-write operations are limited to relaxed,
non-fetching 32/64-bit add/subtract. `--managed-atomics` enables full BPF atomics
and supported scalar C11 atomics in Capsule memory; Nix selects it for x86-64
and for arm64 from Linux 5.18. Selecting `--allocator-lock=atomic` also requires
a JIT with compare-exchange support.

Managed 32/64-bit add, exchange, compare-exchange, and fixed-tier AND/OR/XOR
operations use BPF atomics after address routing; subtraction becomes addition.
NAND and arena bitwise operations use explicit compare-exchange loops; arena
loops avoid JIT fault-recovery restrictions on fetched bitwise instructions.
Eight- and 16-bit RMWs use the containing word while preserving neighbouring
bytes. Sectioned globals reject sub-word RMWs and loads/stores stronger than
relaxed.
Acquire/release and sequentially consistent accesses, plus thread fences, use
native RMWs; signal fences emit no instruction.
The final pass preserves fetch results by strengthening used relaxed RMWs
after optimization, avoiding LLVM 23's non-fetching instruction selection.

All atomic accesses require natural alignment. There is no lock-based fallback
for objects wider than 64 bits. Host/guest interoperability requires matching
object layouts and compatible hardware atomics, not separate library locks.

The load-time contract is a 64-byte frozen `.rodata` config (magic
`"BPCA"`, ABI version 6, layout, backend, fiber geometry, the window base,
and the direct-region count).
Frozen-map reads constant-fold in the verifier, so config fields are
load-time constants in the verified program. The active host lifecycle
brackets libbpf's own load: `bpf_capsule_configure()` (capacities + the window)
runs before it, and `bpf_capsule_initialize()` (arena allocation, pointer
fixups, readiness) runs after it. The object re-validates the whole plan at
runtime so a half-applied configuration fails loudly. Once all memory views
have been released, `bpf_capsule_release()` releases the reserved window
immediately before libbpf destroys the object.

## The transformation pipeline

`bpf-capsule-cc` uses clang to emit per-translation-unit bitcode.
`bpf-capsule-ld` resolves the complete application, runtime, and referenced
Picolibc archive members, then performs six logical phases:

1. **Normalize the source ABI.** Aggregate returns, `capsule_call`, exits,
   unsupported i128 operations, and floating point are lowered. Supported
   atomics retain their original semantics through whole-program optimization.
2. **Optimize the whole program.** The native and managed domains are checked,
   suspension barriers bracket ordinary LLVM O2, and the call graph is checked
   again after optimization has reshaped it. If O2 introduces another library
   call, the required archive member is resolved and this preparation is
   repeated from the untouched linked module before region formation.
3. **Expose verifier-scale work.** Large memory operations become bounded
   loops and managed atomics receive their target lowering. Stackify lays out
   arguments (including variadics) and turns calls, returns, yields, and
   unsuitable loop backedges into regions with persistent resume state.
4. **Clean the generated machine.** A narrow cleanup pass removes redundant
   state traffic introduced by Stackify, repairs irreducible control flow, and
   gives every otherwise undefined terminal value a deterministic form.
5. **Lower the address space.** The selected memory pass lays out the fixed or
   arena backend, materializes based pointers and function tokens, records
   initializer fixups, and emits fixed-tier accessors where required. Late
   target passes handle signed loads, atomic markers, shifts, jump tables, and
   BTF according to the selected capabilities.
6. **Generate BPF machine code.** A machine-level budget pass proves every
   native BPF call chain, post-register-allocation spill relocation moves
   eligible scalar overflow into the fiber stack, and MachineFlatten joins
   temporary allocation units into their output roots before final assembly
   and BTF.

The exact pass spelling lives in
[`tools/bpf-capsule-ld/main.cpp`](tools/bpf-capsule-ld/main.cpp); Nix maps a
kernel floor and JIT architecture to explicit capabilities in
[`nix/target-profile.nix`](nix/target-profile.nix). Executable behavioral
contracts live under [`tests/pass-contracts`](tests/pass-contracts/).

## Stackify: regions, loops, dispatch

Stackify cuts each managed function at every suspension point — managed
calls and unsuitable loop backedges — into **regions**, each with a resume PC.
Before assigning PCs it inlines compact single-use helpers when removing the
managed handoff outweighs losing a verifier boundary; shared, address-taken,
recursive, large, and entry-boundary functions remain separate. Loops then get
one of three fates, priced against an explicit verifier budget (`trips ×
estimated lowered-body cost × branch-path factor`):

- **Native**: a small verifier-proved trip bound and simple control flow —
  stays a real loop behind an induction guard the verifier can count.
- **Chunked**: unknown trips — run several iterations natively, serialize
  the loop-carried values into frame slots, suspend; resume reloads and
  continues. The compiler derives the count from body size, branch paths,
  and the selected memory representation's later expansion. Expensive bodies
  get shorter chunks; a body too large for two iterations is virtualized.
- **Virtualized**: suspend at every backedge — the universal fallback;
  suspension itself is the verifier boundary.

After region formation, each managed source function is normally one temporary
**allocation unit**; a source function is split only if its complete lowered
control flow would exceed one verifier path budget. LLVM selects instructions,
allocates registers, and lowers frames for each unit independently. The units
are compiler temporaries: MachineFlatten removes their calls, symbols, BTF
records, and function slots before the object is emitted.

The final owners are **merge roots**, which are real BPF subprograms. A small
verifier-ABI class merges directly into its public step. For a large class, the
compiler derives a balanced power-of-two root count from total lowered size,
capped by the units and remaining kernel function slots. This is necessary
because the kernel's stack-liveness fixed point revisits the whole containing
subprogram as new stack marks appear; one huge
root can therefore load far more slowly without reducing exploration work.
Applications do not select allocation-unit or root counts.

For programs which still cannot fit one loaded BPF program, `--freplace` uses
those same merge roots as the split boundary. Each physical root is cloned into
an extension program in a `freplace/<root>` section, while its ordinary symbol
stays in the base program as the typed BTF target and a fail-closed stub. Both
forms live in the same ELF. After libbpf loads the base programs,
`bpf_capsule_attach_freplace()` reopens those bytes for each applicable entry,
reuses every mutable map, loads only the matching extensions, and owns their
links until `bpf_capsule_release()`. Initialization fails with `ENOLINK` if an
object which requires replacements was not attached. The required BPF
trampolines exist throughout Capsule's x86-64 kernel range and on arm64 since
Linux 6.0. The scheme works on both memory tiers and changes no source-level
call or continuation boundary.

An extension is bound to one loaded target program. Consequently, an object
with several applicable entry programs loads a separate copy of every matching
root for each entry: verification work and kernel memory scale with entries
times roots. This is still preferable only when the unsplit entries do not fit
or are substantially more expensive to load.

Without the indirect-jump capability, the bounded driver enters a public step
and a balanced compare tree selects the region. Objects with multiple
allocation units first map the PC to its owning unit; a large verifier-ABI
class also adds one real root call between the public step and the region
tree. CPU v3 targets shard very large compare trees to stay within the BPF
branch range. A target with indirect jumps instead dispatches the PC through
an instruction array and `gotox`, without the ownership table. An explicit
`*_ctx` boundary uses a separate typed step. Managed code reads its hidden
argument through
`capsule_borrowed_ctx()`; the compiler rematerializes that accessor in each
region that uses it, so the context remains in BPF registers or native spills
and is never serialized into Capsule memory. Pointers derived from the context
must be derived and bounds-checked again after a region boundary.

The selected region runs, stores its next PC, and returns. The two nested
constant-trip driver loops provide roughly four million dispatches in one BPF
invocation; if that span ends first, the entry returns `PENDING`. Every loop in
the driver has a verifier-visible constant bound: that is the termination
proof.

## The verifier ledger

| eBPF constraint | Capsule's answer |
|---|---|
| No unbounded loops | chunked/virtualized loops; the only real backedges are exact-trip guarded or constant-bound driver loops |
| 1M verified instructions | automatically size-capped merge roots and once-verified global subprograms; chunk trips allocated from the candidates' memory-aware verifier-cost model |
| 8192-jump path bound | chunk length scaled down by branchiness |
| 512 B native stack | program data in fiber memory; post-RA spill relocation; machine-level budget proof for the rest |
| 8 call frames | source call depth becomes software frames; native runtime and root calls receive a separate machine-level budget proof |
| 256 subprograms | only roots, runtime and proven natives are real subprograms; region functions dissolve in machine-flatten |
| Typed pointers only | managed pointers are integers to the verifier, gaining access only through accessors (fixed) or licensed arena casts; code and data are disjoint 64-bit spans of one window |
| No FP, no i128 | software floating-point lowering; expand-i128 |
| Termination | every invocation provably ends; unboundedness is repetition via continuations |

## Cost

The structural costs are software-call handoffs, chunk-boundary dispatch,
relocated spills, fixed-tier memory accessors, and software floating point.
Their importance depends on the workload and target: current integrations
range from a few times to roughly an order of magnitude slower than native
userspace, with floating-point-heavy code able to cost more. The benchmark
programs report native-relative results on the machine where they run.
