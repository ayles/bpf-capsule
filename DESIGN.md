# BPF Capsule design

This file records the current design constraints and the reasons behind them.

## Priorities

In order:

1. Unmodified libraries compile and run correctly, except for explicit and
   unavoidable exclusions such as C++ exceptions.
2. Non-emulated work runs as close to native speed as eBPF and its verifier
   permit. The compiler chooses scheduling, stack placement and region sizes;
   normal users do not tune compiler passes.
3. A useful computation can finish in one BPF invocation where feasible. For
   example, an XDP program should be able to launch a Lua classifier without a
   userspace drain loop.
4. Compilation is fast and the implementation is compact, readable and
   verifier-driven rather than a collection of workload-specific switches.

## Current implementation

The compiler has two automatic memory tiers:

- The 6.9 target profile uses `bpf_arena`; the managed continuation stack and
  heap are arena memory, so they are not constrained by the 512-byte native
  BPF stack. The execution kernel must implement the complete selected arena
  feature set; the functional gate uses the current nixpkgs kernel.
- The 5.15 target profile generates fixed map-backed heap regions. The
  automatic policy
  spends a proven direct-map budget first and places any remaining zero-filled
  capacity in one multi-entry ARRAY map. Scalar register spills which cannot
  safely fit on the native call chain move to the current fiber's unified stack;
  verifier pointers remain native or are rematerialized instead of being
  laundered through map memory.

### Fiber-indexed execution state

The concurrency unit is a Capsule fiber, identified by a small opaque integer.
It is not intrinsically a CPU: a continuation may resume on another CPU, and a
128-core machine need not allocate 128 complete software stacks when an
application permits only four concurrent computations. `capsule_call()`
atomically leases any free slot from the object; `CAPSULE_PENDING` and
`CAPSULE_YIELD` expose the slot as a continuation. `capsule_continue()` resumes it and
`capsule_reset()` cancels it. Completion and every error recycle the slot
automatically. Exhaustion is an ordinary `CAPSULE_EXITED` with the framework's negative code.

Persistent state belonging to one fiber is:

- software call depth and frames;
- abort and continuation state;
- managed return and outgoing-call staging slots;
- addressable source-frame storage;
- transient late physical register spills.

The last item is transient but still fiber-indexed: two CPUs can overlap inside
physical step functions, so sharing it would corrupt live registers. It is not a
separate allocation. The post-RA pass uses a low-end extent of the same unified
fiber stack while managed frames grow down from the high end, and checks for a
collision once on physical-step entry. Physical groups do not nest, so every
source function reuses offset zero; their spill demands never sum. The analysis
and offsets are dynamically sized, so the only limit is the configured fiber
stack itself rather than the former 8 KiB lane.

The compiled maximum is a verifier/control bound, not a storage reservation.
The host selects `fiber_count` after opening the object and before loading it;
both memory tiers then expose exactly that many fiber stacks. Arena backing is
page-granular; the fixed tier rounds physical backing up to its 2 MiB ARRAY
value size. The default maximum is 512 and the default selected count is one.
Dispatch and memory lowering do not special-case a one-fiber object. The cap
sizes only the 32-byte control array; configure resizes the preallocated
lease/recycle maps to the active count before load. Preallocation is required
because Linux 5.15 rejects `BPF_F_NO_PREALLOC` maps from sleepable programs.
Continuations contain the fiber ID and a 48-bit lease generation. A transient
HASH-map claim on the complete token is the single-consumer linearization
point for both tiers; it is removed before `capsule_continue()` or
`capsule_reset()` returns. This uses the same portable `BPF_NOEXIST` helper
semantics as the allocator and avoids relying on atomic opcodes missing from
some old-kernel JITs.
The release benchmark runs the same active count with compiled bounds 64 and
512 and prints the paired timing difference. Timing remains an observation,
not a host-independent pass/fail threshold.

Program globals, imported memory and the TLSF heap remain shared. The
freestanding allocator serializes each complete metadata operation with a
one-entry HASH-map lease. `BPF_NOEXIST` insertion is the cross-CPU
linearization point and works in the Linux 5.15 sleepable syscall programs
where `bpf_spin_lock` is rejected. Stackify flattens and proves the complete
critical operation as one bounded scalar BPF subprogram: it cannot suspend
after taking the lease, and releases it in the same invocation. Contention is
reported to the managed wrapper before mutation; only that outside retry loop
may suspend. This makes allocation thread-safe, not arbitrary mutable globals.

> [!CAUTION]
> **Capsule atomics are supported only where their semantics map exactly.**
> Naturally aligned relaxed scalar loads/stores of 8, 16, 32 or 64 bits remain
> one indivisible BPF access. Atomic read-modify-write, fences and stronger
> orderings are compile-time errors until an exact lowering exists. There is no
> non-atomic fallback, bounded lock retry, suspension-based lock or run-time
> atomic failure. Native-domain BPF atomics remain intact when the target kernel
> implements them. Fiber isolation alone is not threaded-language correctness.

Fiber count is an application concurrency/resource choice, unlike compiler
loop chunks or spill thresholds. `BPF_CAPSULE_MAX_FIBERS` selects the
compile-time upper bound (512 by default), while `bpf_capsule_configure()`
selects the actual pre-load count and heap bytes. On the modern tier, never-before-used
IDs are claimed atomically once and released IDs then use an O(1) LIFO BPF
stack. Reusing the most recently released fiber keeps sequential calls on
their warm fiber-local state. Linux 5.15 rejects that stack in the required
sleepable program type, so its
portable path performs a bounded scan over an active-lease HASH map only when
starting a call. Both paths either return one exclusively leased slot or report
pool exhaustion; users never select CPU or fiber IDs themselves.

### Memory representation

The compiler relocates ordinary program globals into one logical 32-bit
address space. The host chooses heap capacity and active stack count before
load. In the arena profile, the map has exactly enough virtual pages for the
initialized image plus the configured sparse range; only the latter's requested
pages are allocated during initialization. The addresses used by BPF and by
the userspace arena mapping refer to the same pages. In the 5.15 map profile,
the fast prefix is backed by directly relocatable 2 MiB global-data maps. Capacity past
the 32-region direct budget uses one mmapable ARRAY map with 2 MiB values.
Generated accessors select either representation and maintain an eight-byte
overlap for unaligned cross-boundary accesses. The configured allocator heap
follows static program storage and fiber stacks are the last logical range.
Arena initialization commits only the selected heap and stacks; the fixed tier
resizes the unified ARRAY tail to the 2 MiB regions covering the selected
capacity. This backing choice is invisible to managed pointers and
host memory I/O, which continue to use the same logical addresses.

Large host inputs are ordinary unsectioned globals in that logical address
space. An entry publishes a buffer's Capsule address and capacity through a
small sectioned control map; the host then uses
`bpf_capsule_memory_read()` or `bpf_capsule_memory_write()`. Those helpers hide
whether the object uses an arena or fixed regions, including the old-kernel
boundary overlap. The program allocator owns only its configured heap interval,
so it cannot overlap a compiler-laid-out import buffer. Control/status mailboxes remain
ordinary maps because userspace needs a stable, directly mmapable ABI.

The native stack is treated as a hot cache, not as the program's semantic
stack. The current late MIR pass uses a profile-wide per-step ceiling derived
from the compiler-generated downstream call chain: 352 bytes for arena and
320 bytes for fixed maps. Native wrappers which own a Capsule boundary are
recursively flattened into their BPF entry, so application call depth cannot
invalidate that ceiling. The pass keeps the most frequently accessed eligible
spill words under it and relocates only the remainder. These values are
internal invariants. Likewise, the fixed tier always retains the proven
32-region direct-map prefix and uses ARRAY only for the tail; the
representation is not an application tuning surface.

Small innermost loops remain native when LLVM proves an exact or maximum bound
of at most 64 trips, the loop contains no managed call, and estimated verifier
expansion stays below a fixed aggregate allowance. A maximum-only proof gets an
explicit guard which aborts on contradiction; an exact loop keeps its own exit.
Eligible dynamic loops execute a compiler-sized bounded chunk before
suspending. Every loop has target-derived local base and desired chunk sizes;
adding unrelated straight-line IR cannot change them. A marginal-benefit
allocator spends the finite whole-load verifier budget on the hottest optional
chunks and boosts. Branch cost includes LLVM `select`, because BPF has no
conditional move and lowers it to control flow. Everything else uses a
one-backedge continuation, which is the universal correctness fallback rather
than a user-selected batching mode.

For Linux 5.15, the MIR sandwich now stops after LLVM's final machine block
placement. A small replica of the old verifier CFG walk materializes only the
implicit fallthroughs which that verifier would reject as cycle-closing edges.
In the motivating QuickJS build this inserted only a small set of eight-byte
`goto +0` instructions, replacing hundreds of IR guard/anchor blocks. Stock LLVM still performs instruction
selection, register allocation, relocation, BTF and object emission.

The compact integer packet-classifier benchmark uses identical source compiled
natively, directly to stock eBPF, and through this pipeline. The host subtracts
an empty `BPF_PROG_TEST_RUN` and checks for nonzero JIT lengths. Real-library
cases exercise the managed fallback, checked memory accesses, software floating
point, and continuation behavior. Runtime values are always printed for paired
old/new runs but never copied here as durable facts because they are
host-specific.

The kernel verifier's processed-instruction count, static eBPF instruction
count, object bytes, entry/drain counts, output digests, and semantic results
are deterministic release metrics and are compared exactly. The
processed/static ratio describes verifier path amplification and therefore how
close a larger source is to the verifier work limit. Generated matrix reports,
not a documentation snapshot, are the authority for all current values.

Direct stock-eBPF numbers do not exist for these libraries: their ordinary LLVM output is
precisely what does not satisfy the BPF ISA/verifier and motivates the
transform.

The Doom benchmark case runs Freedoom Phase 1 by default (fetched, pinned,
free content). Engine initialization is a separate entry and every phase —
start-up and each frame — completes without a userspace continuation drain on
both targets. `CAPSULE_PENDING` is a regression failure for this workload.
Two upstream PureDOOM behaviors read memory the engine never wrote, and the
private build-tree copy makes both deterministic. `I_InitGraphics` replaces
the zeroed `V_Init` framebuffer with a separate uninitialized 64 KiB
`doom_malloc` block; a fresh native allocator usually hides the undefined
edge pixels with zero pages, while TLSF exposes old free-list words that
follow arena address randomization, so the patch zeroes the replacement
block. The vanilla single-patch column drawer also samples up to masked
source index 127 past a lump's end (sparse Freedoom textures end sooner), so
cached lumps carry a 128-byte zeroed guard, adding no renderer-loop
instructions. The regression leaves pixel export enabled, hashes the
complete PPM tree from fresh processes, and requires the arena and map tiers
to produce the same digest.

Binary32 add/subtract/multiply use direct round-to-nearest-even integer
arithmetic rather than an `f32 -> f64 -> operation -> f32` round trip. The
real-library regression corpus exercises these operations in Rust and float
llama workloads without a library-specific pass or runtime option. A dedicated
bit-exact differential soft-float harness remains future work.

The PureDOOM case and the real-library corpus exercise heap routing,
trampoline dispatch, virtualized loops, and software floating point. Their
timings are host-specific observations, not design constants.
`benchmarks/regression.py` produces the authoritative per-revision report from
fresh processes, records object and JIT sizes, and compares paired runs with a
machine-specific JSON baseline.

## Loader-independent arena layout

libbpf 1.6 places initialized arena data at the start of the mapping, while
libbpf 1.7 right-aligns it when the kernel accepts full-range `ldimm64`
offsets. Sparse globals therefore cannot live at a fixed offset immediately
before or after that image. The generated initializer instead asks
`bpf_arena_alloc_pages` for any free span and records the returned low arena
address. Each function that reaches sparse storage loads that base once and
adds compile-time object offsets; initialized globals continue to use normal
loader relocations. The same object consequently works with both placement
policies, and large zero buffers do not become ELF file data. The 5.15
map-backed tier does not use the arena and is unaffected.

The host lifecycle deliberately keeps configuration, libbpf loading, and
generated initialization as separate operations.
`bpf_capsule_finish_initialization()` runs after the application's ordinary
`bpf_object__load()` or skeleton load. An atomic entry fallback prevents
corruption under stock loaders: one first entry initializes and concurrent
contenders return `-EAGAIN` rather than installing competing sparse bases.

## Region execution model

The intended lowering is:

```text
LLVM IR -> semantic/ABI legalization -> Region IR -> eBPF
```

A region is a maximal verifier-safe unit of work. It may contain one function,
part of a function, or a fused caller/callee path. Execution state carries one
continuation `pc`; physical code may partition that flat namespace into several
global BPF subprograms. Region formation, fusion, loop batching and native-stack
spill placement are automatic decisions made from code size, liveness, call
depth and verifier cost.

This is intentionally not one enormous source-level `switch`. The current
lowering selects a physical step subprogram once, then runs a short local chain
of `pc` comparisons for the regions packed into that group. A giant switch puts
every continuation into one verifier graph, increases repeated state merging,
and gives LLVM one huge function to lay out. Dispatching every original basic
block has the opposite problem: small code pieces but maximum continuation
traffic. Region formation aims between those extremes: native fallthrough,
calls and bounded loops inside a region; dispatch only at verifier-required or
budget-required boundaries. Future balanced or hashed dispatch is worthwhile
only when profiles show the local comparison chain itself is material.

The real BPF stack is the hot spill cache. Values stay there when their saved
access cost justifies scarce stack space and the selected profile-wide ceiling
keeps the compiler-generated call chain within the verifier limit. Cold
values, large objects, values live across suspension and enough low-value
spills to satisfy the limit move to the managed frame. The native boundary
chain is flattened before this late layout; computing a less conservative
ceiling independently for every physical group is a possible future
optimization, not a stack-size option exposed to users.
When a BPF helper receives a native-stack pointer, the pointed-to frame object's
exact byte range must remain native. Today that range is pinned for the whole
physical region because relocation chooses one static layout per region. LLVM's
earlier stack coloring can still reuse already-overlaid slots, but the late pass
does not create new lifetime-based overlays around helper calls. An interval-aware
native/unified layout is a future performance optimization, not a correctness
requirement; it should be attempted only with library benchmark evidence.

### Compositional performance boundary

Inside one monolithic BPF load, exact performance independence is impossible:
the verifier charges the complete reachable graph against one processed-
instruction budget, and facts propagated through one subprogram can change the
cost of validating another. The compiler must still avoid arbitrary module-size
cliffs. Local region, loop and spill choices are functions of the code and its
reachable callers; only optional work competes in an explicit aggregate cost
allocator.

The fixed tier always places the stack bank at the ARRAY-backed right edge of
unified memory and performs one lookup per outer Capsule drive. That verifier
pointer is threaded through the trampoline and physical steps; there is no
per-frame lookup representation. One local verifier-scaling choice remains:
an ordinary physical step clamps an impossible compiler-stack address with a
select, while a step containing at least 2048 IR instructions terminates the
invalid memory-fault path. In the aarch64 5.15 run that motivated this policy,
letting the invalid select state enter QuickJS's large dispatchers hit the
verifier's processed-instruction limit while the terminating form loaded below
it. Applying that extra branch to every small dispatcher measurably slowed
wasm3, which is why
the choice follows physical-function verifier size instead of module or
library identity.

## Performance ceiling and strategy

Universal native equivalence is impossible for arbitrary input programs. eBPF
has no general recursion, unrestricted indirect calls, exceptions, arbitrary
pointer semantics or hardware floating-point instructions, and every loaded
program must fit a verifier-understandable finite control graph. When source
code depends on those features, a managed stack, checked memory and explicit
continuations are semantic costs, not merely missed peephole optimizations.

The useful performance target is therefore conditional: code already
expressible as verifier-safe BPF stays physically native, while only the
unsupported closure is managed.

A custom IR-to-eBPF backend is not the first optimization. LLVM already
supplies the difficult target machinery, and current profiles point to semantic
virtualization and memory traffic as the dominant costs. A specialized emitter
becomes justified only if late MIR cleanup and target hooks cannot remove a
measured, recurring LLVM code-quality loss large enough to offset the extra
backend complexity.

## Embedding managed code in ordinary eBPF

Every sectioned entry and its ordinary callees remain native BPF. The explicit
source boundary is now:

```c
struct classification classification;
struct capsule_result status = capsule_call(&classification, classify_with_lua, ctx, argument);
```

After varargs have been expanded, `bpf-expand-sret` normalizes direct internal
aggregate returns where doing so removes an unnecessary escaped result pointer.
It deliberately preserves external, indirect, and address-taken ABIs: their
managed `sret` pointers already address the caller's live unified frame. The
first partition pass then replaces the variadic source marker with a natural
typed direct call. An aggregate-returning root gets a natural-return adapter at
that boundary, because a pointer into the native eBPF stack cannot cross
suspension.
After normal optimization, a second partition pass discovers the target's
complete reachable closure. Functions cannot be owned by both domains and
calls across the partition without `capsule_call()` are compile-time errors.
This deliberately requires whole-object LLVM bitcode; separately transformed
objects cannot recover a dependency graph after BPF ELF linking.

Capsule roots return any fixed-size value accepted by the managed frame ABI.
The native caller supplies typed output storage to `capsule_call()` and again
to `capsule_continue()` if the computation suspended. The compiler keeps the
value in the root frame and copies it out only on `CAPSULE_OK`;
`CAPSULE_PENDING`, `CAPSULE_YIELD`, and `CAPSULE_EXITED` leave the destination
untouched. `void` roots use the explicit `_void` forms. The four statuses are
`CAPSULE_OK`, `CAPSULE_PENDING`, `CAPSULE_YIELD`, and `CAPSULE_EXITED`.
`CAPSULE_PENDING` means the compiled drive span ended; `CAPSULE_YIELD` is an explicit managed
`capsule_yield()`. Both carry a single-consumer continuation, and
`capsule_reset()` discards it. A native caller may implement a request protocol
and continue the same fiber within one BPF invocation; Capsule does not impose
a scheduler.

Ordinary unsectioned globals belong to exactly one domain. Deliberately shared
mailboxes and maps must have explicit ELF sections; accidental unsectioned
sharing is rejected. Functions are never duplicated just because both domains
reference them: the ambiguity is diagnosed and the source must split the
implementation.

A pointer argument marks a verifier-owned borrowed context. The compiler
threads its exact BTF type through physical step functions instead of spilling
it into arena/map memory, preserving `PTR_TO_CTX` and derived packet
provenance. A borrowed-context call must finish in the current entry; an XDP
wrapper chooses its own pass/drop/abort policy and resets on exhaustion. The
Lua-XDP observer is the end-to-end proof: native XDP launches stock Lua, Lua
reads the live packet, and native BPF emits the result through a ring buffer.
Derived verifier pointers are restricted to one non-suspendable physical
region. The borrowed root can be rematerialized at a later step; packet,
map-value, and other derived capabilities cannot be serialized into the
software frame.

A scalar Capsule address can cross in the other direction. Native code uses
`capsule_memory_pointer()` for ordinary loads, stores, and bulk copies; the
memory pass lowers those accesses through the same arena/map tier as managed
code while provenance analysis keeps genuine verifier pointers native. The
context-interoperability regression copies the same 64 packet bytes into the
same Capsule buffer both directly and via yield/native copy/continue. The
benchmark prints direct and yield-mediated timings for same-host comparison
without treating those host-specific values as durable facts. One coarse yield
is cheap; yielding per byte is still the wrong API.

### What the user may tune

The normal interface has no work-budget knob. Every call gets the largest
compiled drive span (2048 squared step invocations); a program that does not
finish reports `PENDING`.

Stack capacity, loop batch sizes, group counts, inlining and spill thresholds
are compiler decisions. Debug overrides may exist for compiler development but
are not part of the application interface.

Kernel target and feature flags are necessarily build-time inputs, not genuine
runtime launch arguments: they change the instruction set, map types and what
the verifier will load. They can look like constants in a build API and drive
specialization, but one loaded object cannot select unsupported kernel features
at packet-processing time.

### Boundary rules

The native/managed boundary must be explicit and cheap:

- native BPF launches a statically visible managed root only through
  `capsule_call()`, and resumes or cancels pending/yielded work only by passing its
  opaque continuation to `capsule_continue()` or `capsule_reset()`;
- one function belongs to one domain; sharing code across the boundary is
  diagnosed instead of silently cloning code or maps;
- sectioned maps/mailboxes may be shared, while unsectioned storage may not;
- borrowed context and packet pointers remain verifier-native typed
  capabilities, not virtual addresses;
- managed pointers cross into native code only as scalar virtual addresses;
  `capsule_memory_pointer()` accesses them through the selected memory tier,
  never as verifier capabilities;
- all managed memory access must preserve `CAPSULE_ERROR_MEMORY_FAULT` behavior;
  masking an invalid offset back into the heap is not acceptable fault
  behavior.

## Future design: Capsule-to-userspace channels

This is a design note, not a current API. A future Capsule channel should
carry arbitrary-size immutable payloads in unified memory instead of copying
them into fixed-size BPF ring-buffer records. A bounded descriptor queue would
publish a token, logical address, and size. Submitting a payload transfers its
ownership to the channel; userspace reads it through the backend-neutral
Capsule memory API and acknowledges the token before Capsule reuses or frees
the allocation.

A shared BPF ring buffer may optionally act as a pollable doorbell. Its records
would identify channels with pending descriptors, not contain or fragment the
payload. Without notifications, a host could drain channels after ordinary
Capsule invocations or poll them explicitly. Publication and acknowledgement
need release/acquire ordering and generation tokens so concurrent producers
cannot expose partially initialized bytes or reuse storage early.

The queue is necessarily bounded even though individual payload sizes are
limited only by available unified memory. Sending must remain nonblocking and
report a full queue rather than introducing an implicit Capsule yield. The
external channel behavior must be identical for arena and fixed-map memory;
only the host memory accessor used to copy a published payload may differ.

## Future design: managed nonlocal control transfer

This is also a design note, not a current API. `setjmp`/`longjmp` fit Capsule's
explicit software call stack better than they fit native eBPF. A compiler
intrinsic for `setjmp` can split the source function at its continuation and
store the current fiber generation, managed frame pointer, managed stack
pointer, and continuation PC in a Capsule-defined jump buffer. Its initial
return value is zero.

`longjmp` would validate that the buffer still names a live frame in the
current fiber, discard intervening managed frames by restoring the saved frame
and stack pointers, place `value ? value : 1` in the continuation's return
slot, select the saved PC, and end the current physical step. The ordinary
trampoline then resumes immediately after `setjmp`. Native `jmp_buf` layout is
neither used nor exposed.

This mechanism is sufficient for Lua's protected-error control transfer. It
is also reusable infrastructure for C++ exception support, but it is not by
itself C++ unwinding: exception personalities must additionally find handlers
and run cleanups and destructors while popping frames.
