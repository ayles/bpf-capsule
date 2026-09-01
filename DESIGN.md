# How Capsule works

For a reader who knows x86-64 and eBPF but nothing about Capsule.

## The problem, and the one idea

The eBPF verifier admits a program only if it can statically prove termination
and memory safety: ~1M verified instructions of exploration budget, an
8192-jump bound per explored path, 512 bytes of stack for the whole call
chain, 8 call frames, 256 subprograms per object, no unbounded loops, and
every pointer typed and bounds-proven. Programs such as Lua, SQLite, zlib,
and Doom exceed several of these limits at once.

Capsule applies the idea an OS uses to run indefinite processes on finite
hardware: don't make the artifact unbounded — make a bounded step, and
repeat it. The compiler transforms the whole program into bounded regions
plus persistent state that records "where was I". Execution runs one region,
stores the resume point, and returns; a driver re-enters for the next region.
The verifier sees only bounded paths through this machinery. Unboundedness
lives in repetition — inside one
BPF invocation through constant-bound driver loops, and across invocations
through host-resumable continuations. In compiler terms it is a
whole-program continuation-passing/coroutine transform with the
continuation stored in memory instead of on a call stack.

Everything else — the ABI, fibers, the software stack, the memory model —
is the machinery that makes this transform correct, fast, and loadable
through ordinary libbpf.

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

Before load, `bpf_capsule_configure()` — mandatory on every tier —
reserves the object's **memory window**: one PROT_NONE, 4GiB-aligned span
of address space covering a full 32-bit offset domain plus a small code
tail above it. Its base is baked into the object's frozen config, where
the guest's first-entry check demands it (loading without a capsule-aware
host does not run), and where the verifier constant-folds every read of
it.

Every capsule pointer on both tiers is `window + displacement` — the same
bits in the guest, in the verifier's constant tracking, and in the host
process:

- data lives in the window's first 4GiB: heap at `heap_base`, then the
  per-fiber stack bank, slice-aligned so frame math can mask;
- code lives just above it: a managed function's address is
  `window + 4GiB + entry-pc`, non-managed function identities follow in
  the next 1MiB. Code and data cannot collide as 64-bit values, and since
  the window is 4GiB-aligned, an indirect call recovers the entry pc by
  truncating the token to its low word — free in BPF, whose 32-bit ALU
  zero-extends;
- `NULL` is 0, far outside the window; the window's first page and its
  entire unbacked remainder are PROT_NONE, so a stray dereference of any
  capsule-shaped pointer faults instead of aliasing unrelated memory.

The two tiers differ only in what backs the window:

- **Arena tier (kernel >= 6.9)**: the window becomes the arena's
  kernel-pinned `user_vm_start` (libbpf maps the arena into it with
  MAP_FIXED at load). Guest accesses are single instructions; host access
  is plain memcpy through the same addresses.
- **Fixed tier (5.15–6.8)**: memory is stitched from 2MiB map-value
  regions (direct `.data` maps plus one ARRAY map, each with an 8-byte
  shadow suffix so unaligned loads may cross a region boundary), accessed
  through generated accessor subprograms that recover the offset by
  truncation and switch on `offset >> 21`. `bpf_capsule_initialize()`
  assembles a PROT_READ view of the regions inside the window, so
  guest-published pointers dereference on the host as-is (writes go
  through a helper that maintains the shadow suffix; a stray direct write
  faults).

Pointer-valued initializers (a Lua function table, a static string
pointer) cannot bake the load-time window base, so the compiler bakes bare
displacements and the mandatory post-load verb rebases them: the arena's
generated init program applies its fixup list in-kernel, and the fixed
tier ships a `.rodata.bpffix` slot table that `bpf_capsule_initialize()`
applies from the host before publishing a ready word — entries fail
closed on both tiers until initialization has run.

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

The execution register file is `pc`, `sp`, and `fp`; the remaining fields
belong to lifecycle and continuation handling. The PC is a dense
compiler-assigned resume-point index, never an address, and doubles as the
lifecycle word. `pc == 0` means that a fiber is idle, so a fresh zero-filled
map is already a valid pool, while `BPF_CAPSULE_PC_DONE` marks a computation
complete but not yet reaped. `sp` and `fp` hold full based pointers — the same
representation
everything else uses; the frame anchor on the arena tier is one
`inttoptr` of the loaded `fp`. `{status, code}` is the terminal event:
exits and yields publish both fields with one 64-bit store, and every
legal reader is ordered behind that store by program order or by the
continuation claim. Each fiber owns a fixed power-of-two slice of the
stack bank; multiple fibers are concurrent computations over one shared
heap, recycled through a pool.

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
allocator is the canonical user: a native compare-exchange lease, an O(1)
TLSF metadata operation, release — atomic with respect to suspension —
while the managed `malloc()` wrapper retries (and may suspend) around
`BUSY`, so waiting happens without the lock.

Function classes are declared by explicit attribute, never inferred from
names; symbol names are link-time contracts only.

The load-time contract is a 56-byte frozen `.rodata` config (magic
`"BPCA"`, version, layout, backend, fiber geometry, the window base).
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
`bpf-capsule-ld` links the complete application and runtime, then performs six
logical phases:

1. **Normalize the source ABI.** Variadics and aggregate returns become
   explicit memory operations. `capsule_call`, exits, atomics, unsupported
   i128 operations, and floating point are lowered or validated before LLVM
   can optimize across their boundaries.
2. **Optimize the whole program.** The native and managed domains are checked,
   suspension barriers bracket ordinary LLVM O2, and the call graph is checked
   again after optimization has reshaped it.
3. **Expose verifier-scale work.** Large memory operations become bounded
   loops, irreducible control flow is normalized, and Stackify turns managed
   calls, returns, yields, and unsuitable loop backedges into regions with
   persistent resume state.
4. **Clean the generated machine.** A narrow cleanup pass removes redundant
   state traffic introduced by Stackify, repairs irreducible control flow, and
   gives every otherwise undefined terminal value a deterministic form.
5. **Lower the address space.** The selected memory pass lays out the fixed or
   arena backend, materializes based pointers and function tokens, records
   initializer fixups, and emits fixed-tier accessors where required. Late
   target passes handle signed loads, atomic markers, shifts, jump tables, and
   BTF according to the selected profile.
6. **Generate BPF machine code.** A machine-level budget pass proves every
   native BPF call chain, post-register-allocation spill relocation moves
   eligible scalar overflow into the fiber stack, and MachineFlatten joins
   temporary allocation units into their output roots before final assembly
   and BTF.

The exact pass spelling and target composition live in
[`tools/bpf-capsule-ld/main.cpp`](tools/bpf-capsule-ld/main.cpp); executable
behavioral contracts live under [`tests/pass-contracts`](tests/pass-contracts/).

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
because the kernel's stack-liveness fixed point
revisits the whole containing subprogram as new stack marks appear; one huge
root can therefore load far more slowly without reducing exploration work.
Applications do not select allocation-unit or root counts.

On profiles before Linux 7.1, the bounded driver enters a public step and a
balanced compare tree selects the region. Objects with multiple allocation
units first map the PC to its owning unit; a large verifier-ABI class also adds
one real root call between the public step and the region tree. The 5.15
profile shards very large compare trees to stay within its branch range. The
7.1 profile instead dispatches the PC through an instruction array and
`gotox`, without the ownership table. An explicit `*_ctx` boundary uses a
separate typed step. Managed code reads its hidden argument through
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
| No FP, no i128 | bit-exact soft-float; expand-i128 |
| Termination | every invocation provably ends; unboundedness is repetition via continuations |

## Cost

The structural costs are software-call handoffs, chunk-boundary dispatch,
relocated spills, fixed-tier memory accessors, and software floating point.
Their importance depends on the workload and target: current integrations
range from a few times to roughly an order of magnitude slower than native
userspace, with floating-point-heavy code able to cost more. The benchmark
programs report native-relative results on the machine where they run.
