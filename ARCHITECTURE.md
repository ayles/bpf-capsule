# Architecture

BPF Capsule compiles freestanding C (and no_std Rust) into one loadable BPF object
supporting recursion, indirect calls, unbounded loops, floating point (as integers), and
a flat address space — by turning the program into a continuation-passing state machine
driven by a bounded trampoline, and by virtualizing memory onto a bpf_arena
(the 6.9 target profile) or overlapping 2 MiB map regions (the 5.15 profile).
The single compatibility knob is
`BPF_CAPSULE_TARGET_KERNEL` (CMake) / `-bpf-target` (opt/llc); `src/pass/target.cpp` derives the
rest in two layers: version -> features (HasArena 6.9, HasCpuV4 6.6,
HasArenaSignedLoads 7.0, instruction-array jump tables always false today), features -> strategy (UseArena,
LowerSignedDivision, LowerArenaSignedLoads, UseJumpTables, InternalizeEarly). Fixed policy also lives
there: MaxStepGroups=180, MaxInlinedInstructions=100, DynamicAllocaBytes=2048, and the
IsUnmanagedRuntime name list (`__bpf_capsule_nosuspend_*`, `__bpf_dadd/.../dcmp`) that
stackify and `bpf-internalize-runtime` must agree on.

## Stage 0: source -> bitcode (`bpf_capsule_bitcode`, cmake/BpfCapsule.cmake)

Unwrapped clang, `-target bpf -mcpu=v3|v4` (v4 iff target >= 6.6), `-O2 -Xclang
-disable-llvm-passes -flto`: O2 *attributes* are recorded but the plugin pipeline owns all
transforms. Freestanding, no unroll, `-mllvm -bpf-stack-size=512`. The program includes
`src/runtime/guest/bpf_capsule.h` (the guest API; any number of TUs). The runtime itself,
`src/runtime/guest/bpf_capsule.c`, is compiled into every object by
`bpf_capsule_object` automatically (maps, fiber controls, trampoline drivers, the
capsule_call/continue/reset macros). Rust ships `bpfel-unknown-none` rlibs, already
bitcode. All LLVM tools must be one major (22); the package config re-checks consumers.

## Stage 1: llvm-link

Whole-program link of every bitcode file (app + support runtime: softfloat.c,
mathfns.c, int128.c, tlsf.c, freestanding.c). Output: one module with the
runtime symbols later passes look up
by name (`bpf_capsule_fibers`, `__bpf_capsule_trampoline*`, `bpf_heap_array`/`arena`,
`__bpf_capsule_call`, ...). Missing symbols are fatal in the pass that needs them.

## Stage 2: opt, `--passes=bpf-capsule` (order is compiler ABI)

The plugin expands that single public pipeline name to the ordered sequence
below. Individual pass names remain available for focused compiler tests, but
applications do not assemble the pipeline themselves.

1. **bpf-expand-varargs** — input: arbitrary variadic C. Devariadicizes the whole program:
   each variadic function gets a fixed signature plus a pack pointer; call sites pack args
   no wider than 8 bytes into fixed slots; va_start/va_arg/va_copy lowered everywhere (also in fixed-arg helpers
   that walk a va_list). Calls to declared-only variadic externals are rejected
   with a wrapper-oriented diagnostic. Guarantees: no `isVarArg` definitions
   remain; escaping defined-variadic addresses and wider slots receive clean
   unsupported-input diagnostics. Establishes:
   stackify can lay out every frame statically.
2. **bpf-expand-sret** — normalizes defined, non-address-taken sret functions and their
   direct internal calls to natural aggregate returns before O2. This is a code-quality
   transform: it prevents an otherwise-local result pointer from escaping its frame and
   blocking fixed-tier stack specialization. External, indirect, and address-taken ABIs
   remain unchanged; stackify accepts their surviving sret pointer as an ordinary unified
   caller-frame pointer.
3. **bpf-partition** (1st run) — lowers the `__bpf_capsule_call` variadic marker into a
   typed direct call carrying the `bpf.capsule.call` operand bundle (fiber id as SSA input)
   plus the status computation over the fiber control words (exit_word/cursor).
   An aggregate-returning root gets a natural-return adapter at this boundary:
   internal sret pointers already refer to a live unified caller frame, whereas
   a pointer into the native eBPF stack cannot survive a suspension.
   Computes domain reachability: entries = sectioned functions (section != .ksyms) are
   native roots; capsule_call targets and surviving address-taken functions seed the
   Capsule closure. Marks `bpf.native`/`bpf.capsule` metadata on functions and globals;
   a function or unsectioned global in both domains is a hard error. Inserts an external
   `__bpf_capsule_suspend_barrier` call at every Capsule entry so O2 cannot move
   helper calls across a potential suspension.
4. **bpf-lower-atomics** (function) — consumes domain metadata. In Capsule functions only:
   accepts relaxed, naturally-aligned integer/pointer atomic loads/stores of 1/2/4/8
   bytes; *rejects* (emitError) every RMW, cmpxchg, fence, or ordered access. Native code
   keeps genuine BPF atomics untouched. This is the validation half of two-phase lowering:
   accepted load/store markers survive memory rewriting and
   `bpf-finalize-atomic-load-store` removes them only after their final address is known.
   There is deliberately no emulation fallback for rejected atomic operations.
5. **bpf-expand-i128** (1st run) — expands source i128 mul inline (schoolbook i64) and
   div/rem into calls to `__bpf_udiv128/__bpf_urem128` (must be linked from int128.c,
   else fatal). Guarantees: no i128 libcall (`__multi3`, `__udivti3`) can be requested.
6. **bpf-soft-float** — retypes every FP *SSA value* (f32->i32, f64->i64, using
   layout-identical integer shadow types for aggregate values and function ABIs) while
   preserving source aggregate/global/alloca memory types, and replaces every FP
   *operation* with a call to `__bpf_f*`/`__bpf_d*` integer routine. Opaque pointers let
   scalar and aggregate memory accesses use the raw integer representation without
   casts or memcpy shims. fabs/copysign/fma expand inline; other FP
   intrinsics (sqrt, transcendentals) become
   `CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC` + zero. Rebuilds BTF-safe
   signatures for retyped functions. Guarantees: no FP type survives in IR.
7. **bpf-no-inline** — strips non-mandatory alwaysinline, adds noinline everywhere except
   `bpf_heap_*` (must stay inlinable). On the fixed-map tier (InternalizeEarly) also
   internalizes everything except entries/trampolines so O2's DCE is effective.
8. **bpf-lower-sdiv** — when !HasCpuV4: sdiv/srem become calls to generated alwaysinline
   `__bpf_sdiv_iN/__bpf_srem_iN` helpers (branchless sign-fixup over udiv/urem), inlined
   back by the following O2 so constant divisors still fold.
9. **default<O2>** (including stock GlobalOpt; `opt` is invoked with
   `--disable-loop-unrolling`). The only stock optimization run. Suspend
   barriers pin Capsule callees as memory-affecting throughout.
10. **bpf-expand-i128** (2nd run) — catches i128 mul/div re-formed by O2 and expands the
    i64 umul/smul-with-overflow intrinsics (whose backend lowering is an i128 libcall).
    This repetition is required even when the current libraries happen not to
    exercise it: O2 recognizes an ordinary multiply/divide-back overflow idiom
    as `llvm.umul.with.overflow.i64` after the first run.
11. **bpf-internalize-runtime** — internalizes everything that is not load-time ABI
    (sections, `__bpf_capsule_trampoline*`, `bpf_heap_*`, unmanaged runtime) and asserts that
    software lowering left no FP values. The custom pass does not duplicate LLVM's
    reachability analysis.
12. **globaldce** — immediately removes the newly internalized dead set so later
    legalization and domain analysis process only the linked application's reachable
    image.
13. **bpf-expand-mem** (function) — lowers memcpy/memmove/memset intrinsics to i64-chunk +
    byte-tail load/store loops, and also expands *plain calls* to memcpy/memset whose
    pointer args reach sectioned globals (a sectioned-map pointer must not cross a
    suspension as a frame-saved integer). Other call sites keep the shared routine.
14. **bpf-bound-vla** (function) — every dynamic alloca becomes a fixed 2048-byte entry-
    block reservation plus a run-time count check; overflow sets
    `CAPSULE_ERROR_VLA_BOUNDS` and
    returns. Guarantees stackify's static-frame invariant (a survivor is diagnosed there).
15. **fix-irreducible** (stock) — makes source CFGs reducible so LoopInfo/SCEV in stackify
    see every cycle as a loop.
16. **bpf-partition** (2nd run) — no markers remain; recomputes domain metadata on the
    post-O2 call graph and *removes* the suspend barriers (their code-motion job is done).
17. **bpf-stackify** — the core transform; see "Execution model" below. Input contract:
    acyclic-frame invariants established above (no varargs, no VLA, no FP, no
    i128 div, domains marked, barriers gone). Output: managed functions are dissolved into
    <=180 `bpf_step.N` global subprograms plus data tables; original managed functions are
    erased and their address uses replaced by integer entry PCs. Native helpers which own
    a `capsule_call` boundary are first flattened into their BPF entries: Linux 5.15's
    hard call-depth limit leaves no extra frame above the complete trampoline/accessor
    chain. Indirect and recursive native boundary wrappers are diagnosed explicitly.
18. **early-cse,gvn,adce** (cleanup) — stock scalar cleanup of the generated dispatch/frame
    code. Runs before define-undef so its poison fills are still caught.
19. **fix-irreducible** (2nd) — resume dispatch jumps into former loop bodies; this rewires
    that irreducibility (stackify pre-split critical switch edges so ControlFlowHub only
    ever redirects branches).
20. **bpf-define-undef** (function) — replaces llvm.trap/debugtrap with
    `CAPSULE_ERROR_TRAP`, `unreachable` terminators with
    `CAPSULE_ERROR_UNREACHABLE` + return (the backend's __bpf_trap is
    unloadable), and every first-class undef/poison operand with zero (verifier rejects
    uninitialized reads).
21. **bpf-scalarize-agg** (function) — fixed-map tier only: splits aggregate loads/stores
    into element accesses so the width-specific heap accessors can route them. No-op on
    arena (deliberately: scalarizing there blew the Rust example's verifier budget).
22. **bpf-memory** (`src/pass/memory.cpp`) — the unified memory model; see
    "Memory tiers". Both tiers first replace
    function-as-value uses with tokens from the reserved high 2 MiB of the
    32-bit domain and verify stackify left no unowned alloca.
23. **bpf-infer-as** (function) — stock InferAddressSpaces(flat=0); folds the
    addrspacecast chains the memory pass introduced (no-op on the fixed tier).
24. **bpf-lower-arena-sext** (function) — affected arena kernels only: places a
    late compiler barrier after narrow arena loads so CPU-v4 instruction selection
    cannot fold a later signed operation into unsupported `BPF_MEMSX`; it is a no-op
    on the fixed tier and kernels which accept signed arena loads.
25. **bpf-finalize-atomic-load-store** (function) — strips the atomic marker from the
    surviving relaxed loads/stores (backend has no AtomicLoad/Store patterns); anything
    else atomic here is a compiler bug and errors.
26. **bpf-split-shift63** (function) — splits 64-bit shifts by exactly 63 into 32+31
    (arm64 JIT "invalid immr encoding 63" would silently force the interpreter and kill
    kfunc calls). Must run after all optimization or InstCombine refolds it.
27. **bpf-no-jump-tables** — stamps `no-jump-tables` on every function unless
    UseJumpTables() (currently never true): .jumptables insn arrays don't load end-to-end
    on any targeted kernel/libbpf pair.
28. **bpf-sanitize-btf** — rewrites every BTF-visible debug name to `[A-Za-z0-9_]` (one
    bad Rust name rejects the whole .BTF) and drops global debug attachments whose size no
    longer matches the global.

## Stage 3: llc + bpf-unified-spills (src/pass/unified_spills_mir.cpp)

Stock `llc -O2 -mcpu=vN` with the same plugin loaded (the preliminary backend
stack ceiling is the configured unified fiber-stack size so register allocation can
finish and expose the real physical frame);
`-bpf-unified-spill-pipeline` inserts a MachineFunctionPass after MachineBlockPlacement
(post-PEI, pre-emission). Two jobs: (a) materialize fallthroughs inside cyclic machine
SCCs as explicit jumps (5.15's CFG walk misclassifies a layout fallthrough that closes a
cycle); (b) for functions whose final frame exceeds `-bpf-unified-spill-limit`, relocate
the coldest *provably scalar* register-spill words into a transient extent at the low end
of that fiber's existing unified stack range. The limit is derived from the deepest
generated call path: 320 bytes for fixed-map targets (512 minus six 32-byte runtime
frames, including its outlined array-map accessor) and 352 bytes for arena targets
(512 minus five). A physical step carries one empty-asm anchor containing the stack address,
current managed SP and exit word. The memory pass resolves the stack to its arena/map
backing once; MIR saves that verifier pointer once, checks `SP >= spill_extent` once, and
uses base+constant accesses thereafter. Physical groups never nest, so every group and
source function reuses offset zero rather than adding its worst-case spill demand to the
semantic stack layout. A dynamically sized dataflow lattice
(Scalar/Masked/Remat/Arena/Unknown, plus per-register taint and mask budgets) decides
eligibility; masks are re-applied after each fill so 5.15 re-derives bounds;
rematerializable ld_imm64+const words are deleted and recomputed. A native function whose
final frame exceeds 512 bytes is fatal because it has neither an exclusive fiber nor a
semantic stack. Helper-visible stack objects remain native at their exact
`MachineFrameInfo` extent; the current layout pins that extent for the complete physical
region. A future interval-aware layout may reuse those bytes outside the helper-visible
object's live range if real workload profiles justify the additional allocator
complexity. There is no separately allocated spill map or fixed spill-size ceiling.

## Stage 4: object -> skeleton -> host

`bpftool gen skeleton` embeds the finished ELF into a header (GenerateSkeleton.cmake); the
host application compiles it with stock libbpf. `src/runtime/host/bpf_capsule_host.h` is
the complete libbpf-based host API, three lifecycle verbs plus a memory view:
`bpf_capsule_configure()` before load (the pure planning arithmetic over the object's
self-describing `.rodata.bpfconfig` record, then map-size application); libbpf's own
load call; `bpf_capsule_finish_initialization()`, which runs the generated
`bpf_capsule_init` program once; then `bpf_capsule_memory()` builds a
`struct bpf_capsule_memory` view once and tier-independent `bpf_capsule_memory_write/read()`
transfer bulk bytes over it (arena mmap, or `.data.heapN`/`.bss.heapN` maps + mmapped
`bpf_heap_array`, maintaining the 8-byte cross-region shadow); the view's accessors report
the managed image bounds and the host-reserved heap prefix selected at configure time.
Non-libbpf ecosystems (cilium/ebpf, aya) reimplement the
SPEC.md loader contract instead of linking this header. Running programs is plain
libbpf; hosts loop on `CAPSULE_PENDING` themselves when their execution model permits
drains, and branch on the mmaped `capsule_result` for every terminal state.

## Execution model (bpf-stackify + bpf_capsule.c)

- **Domains.** Sectioned entries and their callees stay native BPF. `capsule_call(out,
  fn, ...)` acquires a fiber lease (LIFO stack+issued-set on arena, exact lease-hash scan on
  5.15), then enters the managed domain; the partition/stackify passes turn it into: write
  the root frame at the high end of the fiber's unified stack range, set cursor/return_size, call
  `__bpf_capsule_trampoline(fiber)`, then map control words to
  `CAPSULE_OK`/`CAPSULE_PENDING`/`CAPSULE_EXITED`/`CAPSULE_YIELD`.
- **Managed selection.** Small single-use helpers are inlined (<=100 IR); on CPU-v4
  targets the resulting caller also stays <=256 IR to bound verifier path growth. Bounded scalar
  call islands (<=1024 IR, <=256 B alloca, loops <=64 trips, call depth <=2, <=32 chosen by
  static hotness) and `__bpf_capsule_nosuspend_*` roots stay *unmanaged* global
  subprograms — verified once, called normally. Everything else Capsule-reachable becomes
  a managed function with an integer entry PC.
- **Frames.** Per-fiber downward stack range (256 KiB default, power of two) in the
  same unified address space as program globals and the configured heap; the compiler models
  the bank as `bpf_call_stack`. Layout: `[u32 PC][args at module-wide slot stride][locals]
  [return value at top]`. A callee's result sits immediately below the caller's frame
  base, invariant across tail-call chains. `bpf_frame_size` (.rodata.bpffs) maps entry PC
  -> frame size (slot 0 = 0 = invalid); `bpf_pc_group` (.rodata.bpfpc) maps PC -> physical
  group. Cursor encoding: 0 idle, sp+1 live, StackLimit+1 completed; the guard tail of the
  range (>= largest frame) makes underflow detectable at the next dispatch.
- **Suspension.** Managed calls push a callee frame and return; loop backedges either stay
  native (small proven trip counts, guarded), run as bounded chunks (4..64 trips, budget-
  allocated by hotness/verifier-cost), or suspend every iteration; code-size region cuts
  (~6000 IR budget on v3) and `capsule_yield()` (exit-word tag CAPSULE_YIELD, ActionYield) also suspend.
  Values live across any suspension are demoted to frame slots; verifier-owned pointers
  (helper returns, ctx) may never cross one — validated with liveness + StackLifetime,
  compile error if violated. The borrowed XDP ctx is the one exception: it is re-passed to
  every step through the typed `__bpf_capsule_trampoline_ctx*` driver chain and rematerialized.
- **Steps and trampoline.** Transformed regions are packed by size into <=180
  `bpf_step.N(ctx?, fiber)` external subprograms, each with a balanced PC dispatch tree.
  Generated `__bpf_capsule_trampoline_step` checks stop conditions (idle/completed/
  exit word), validates cursor and PC, indexes `bpf_pc_group`, switches to the step;
  the runtime's two-level bounded drivers (2048x2048 + 1 dispatches) multiply iterations
  while verification cost only adds. Terminations are a store of the encoded exit word
  (noinline `bpf_capsule_set_exit`); the driver notices between steps, unwinding free.
  Physical groups return zero for every transition that immediately re-enters managed
  dispatch; only ActionYield is distinct and returns to the native caller.
- **Indirect calls & tails.** Managed function addresses *are* entry PCs; indirect calls
  dispatch by PC with a frame-size-table validity check (size 0 ->
  `CAPSULE_ERROR_INVALID_DISPATCH`; overflow -> `CAPSULE_ERROR_STACK_OVERFLOW`). Indirect
  tail calls in threaded-interpreter shape reuse the current frame;
  connected tail classes get equalized frame sizes and a contiguous PC range so the check
  is one subtract+compare.

## Memory tiers (bpf-memory)

Both tiers keep data below `0xffe00000`. The final 2 MiB of the 32-bit domain
is reserved for function tokens: managed entry PCs use its lower 1 MiB and
memory lowering assigns other callable tokens from the upper 1 MiB. A cast or
corruption therefore cannot name both valid data and a valid function.

- **Arena (>= 6.9).** Movable (Capsule-owned/unclassified, unsectioned) globals with real
  initializers move to address space 1 (one PROGBITS section); zero-filled globals become
  sparse `bpf_capsule_arena_control.virtual_base + offset` addresses committed at init by
  `bpf_arena_alloc_pages`. Generated `__bpf_capsule_init` runs a 0->1->2 CAS election
  (concurrent entry gets -EAGAIN; failure resets to 0, retryable); every sectioned entry
  gets a call-init prologue as a stock-loader fallback, and `bpf_capsule_init`
  (syscall section) lets the host do it eagerly. Non-stack accesses are addrspacecast to
  AS1 (cached per block inside native loops for the arm64 JIT); pointer equality is
  canonicalized into AS1 and pointer differences are computed on low-32 scalars.
- **Fixed maps (5.15..6.8).** All movable globals are laid out in one 32-bit virtual image
  starting at 4096 (null page unmapped), initialized data first, ordinary zeros next, the
  load-time-sized allocator heap, and the logical `bpf_call_stack` bank last; no ordinary object straddles a 2 MiB region except recorded
  spanning objects. Regions 0..31 are direct maps (`.data.heapN`/`.bss.heapN`) each with
  an 8-byte shadow of the next region so an unaligned word crossing a boundary is one
  map access (store paths maintain both directions); overflow capacity lives in the
  multi-entry mmapable `bpf_heap_array` ARRAY map. Pointers
  are plain integers. An access whose base region is compile-time known becomes
  barrier+mask(+range-select if call-derived)+GEP; others call the generated
  `bpf_heap_load/storeN` accessors. The stack bank is covered by 2 MiB ARRAY values and
  is resized before load to the regions containing the selected fibers; generated
  `bpf_stack_*` accessors preserve the same logical address domain for complex current-frame addresses. The outer Capsule
  drive performs one ARRAY region lookup and threads that ephemeral verifier pointer through
  trampoline and physical-step calls. Per-step promotion reuses it for grouped managed
  frame fields and transient spills. Ordinary steps clamp an impossible compiler-stack
  address with a select; a physical dispatcher with at least 2048 IR instructions instead
  terminates that memory-fault path so Linux 5.15 does not re-explore the large body from
  both select states. `BPF_CAPSULE_FIBER_STACK_BYTES` controls the compile-time power-of-two range size
  (default 256 KiB, maximum 2 MiB).

## Object <-> host ABI (from src/runtime headers)

Control sections: `.bss.bpfctrl` = `bpf_capsule_fibers[N]` (per-fiber
{exit_word, stack_cursor, return_size, generation}); `.rodata.bpfconfig` = the
compiler-populated static layout plus load-time fiber/heap selection;
`.data.bpfctrl` (arena tier) = `bpf_capsule_arena_control` (ready + virtual_base);
`.rodata.bpffs`/`.rodata.bpfpc` = dispatch tables. Maps:
`arena`, or `bpf_heap_array` + heap regions; `__bpf_capsule_stack_region` is a compiler
intrinsic eliminated into the drive's ordinary ARRAY lookup, not another map. Fiber lease maps
(`bpf_capsule_issued_fibers`+`bpf_capsule_free_fibers`, or `bpf_capsule_fiber_leases`).
Continuations are generation-tagged 64-bit lease tokens:
`CAPSULE_PENDING`/`CAPSULE_YIELD` hand one to userspace, which re-drives through
`capsule_continue` or cancels through `capsule_reset`. Consumption atomically
advances the generation, so duplicates and tokens from a previous fiber lease
fail without touching the new owner. `CAPSULE_EXITED` carries a signed code:
0..255 belongs to the guest and negative values to the framework. Return values
are copied out of the root frame only on `CAPSULE_OK`, size-checked against
`return_size`.
