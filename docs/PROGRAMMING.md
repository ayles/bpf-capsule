# Programming contract

BPF Capsule has no source annotations for loop batches, native-stack
allowances, spill counts, or continuation budgets. There are nevertheless a
few semantic boundaries between ordinary library code, its BPF entry wrapper, and the host.
This document makes those boundaries explicit.

## Native and Capsule domains

Guest code includes only `bpf_capsule.h`, in any number of translation
units. The runtime — program memory, continuation state, exit state, maps,
and driver — is `bpf_capsule.c`, compiled into the object by the build
pipeline automatically. Input translation units are ordinary C or
LLVM-compatible `no_std` Rust bitcode.

A defined function with an ELF section is an ordinary verifier-native entry.
Its normal callees remain native too. Managed execution starts only at the
explicit `capsule_call()` boundary; the compiler transforms the statically
visible target and its reachable closure. A boundary placed in an ordinary
native helper is flattened into each calling BPF entry so the old kernel's
fixed call-depth limit is independent of source wrapper depth; unrelated
native helpers remain ordinary subprograms:

```c
struct result {
    struct library_result value;
    struct capsule_result capsule;
};

volatile struct result result SEC(".data.result");

static struct library_result workload(unsigned int argument) {
    return library_function(argument);
}

SEC("syscall")
int run(void) {
    result.capsule = capsule_call(&result.value, workload, 42);
    return 0;
}

SEC("syscall")
int drain(void) {
    result.capsule = capsule_continue(&result.value, result.capsule.continuation);
    return 0;
}
```

The target must be a defined, non-variadic function and its arguments must be
statically type-checkable at the call site. `capsule_call(&value, target, ...)`
accepts any fixed-size return type that the managed frame ABI accepts: scalars,
Capsule virtual addresses, and fixed-size aggregates composed from those
values. The destination must be verifier-writable native storage of exactly
that type. It is written only on `CAPSULE_OK`; `CAPSULE_PENDING`,
`CAPSULE_YIELD`, and `CAPSULE_EXITED` leave it unchanged. A later
`capsule_continue(&value, continuation)` supplies destination storage again,
because a native BPF stack or helper-owned pointer cannot survive between
invocations. Passing storage of a different size fails with
`CAPSULE_ERROR_RETURN_MISMATCH` and reclaims the fiber.

Use `capsule_call_void(target, ...)` and
`capsule_continue_void(continuation)` for a `void` root. Variable-size values
cannot cross the boundary by value. Verifier-owned pointers (`ctx`, packet,
map-value, ring-buffer, dynptr, and helper-owned pointers) may not be returned:
their kernel provenance cannot live in a suspendable managed frame. A borrowed
`ctx` is the one input-only exception described below. A returned Capsule
pointer is a virtual address, not a kernel verifier capability. Native BPF may
access it through `capsule_memory_pointer(type, address)`; the compiler lowers
that dereference through the selected memory tier. It must not be passed to a
helper which expects a ctx, packet, map-value, dynptr, or other kernel pointer
type.

Every call form returns a `struct capsule_result`. Its status is exactly one
of `CAPSULE_OK`, `CAPSULE_PENDING`, `CAPSULE_YIELD`, or `CAPSULE_EXITED`.
Pending and yield carry a valid continuation; a return or a termination has
already recycled the leased fiber. The single signed `capsule_result.code` is
shaped like a shell's `$?`: 0..255 is the guest's own exit status, negative
is the framework's (pool exhaustion, for example, is `CAPSULE_EXITED` with
`CAPSULE_ERROR_POOL_EXHAUSTED`).

The partition is whole-object and checked after optimization. A function may
belong to the native closure or a Capsule closure, but not both, and direct
calls across the boundary are rejected. Put deliberately shared control and
result globals in explicit ELF sections. An unsectioned global used from both
domains is a compile-time error; Capsule-only unsectioned storage enters the
virtual memory image.

Scalar `float` and `double` values are lowered to integer software floating
point. Floating-point vectors and other scalar formats such as `half`,
`bfloat`, and `fp128` are rejected with a compile-time diagnostic. Conversions
between floating point and integers wider than 64 bits are also rejected.

### Configure capacity and load

Choose active fibers and heap capacity after opening the object and before
loading it; load with libbpf itself; then bring up the managed memory:

```c
struct bpf_capsule_config config = {
    .fiber_count = fiber_count,
    .heap_bytes = heap_bytes,
};
if (bpf_capsule_configure(object, config) ||
    bpf_object__load(object) ||
    bpf_capsule_finish_initialization(object))
    return -1;
```

Skeleton hosts load with `bpf_object__load_skeleton()` instead. Repeated
pre-load configuration is safe and the last successful values win.
Configuration after load fails with `EBUSY` because BPF map geometry can no
longer change. The fiber count must be nonzero and no larger than the
compiled ceiling. The heap may be zero for a program that does not use an
allocator. Skipping configuration entirely is also valid: the compiler stores
a complete default layout in the object.

On the arena tier, `bpf_capsule_finish_initialization()` runs the generated
`bpf_capsule_init` program, which allocates the selected sparse storage,
records its kernel-selected virtual base, and installs pointer-valued global
fixups. On the 5.15 tier the integer-offset image is already in the ELF and
the call is a no-op.

Every arena entry retains an atomic fallback prologue so omitting the host call
cannot expose partially initialized memory. One simultaneous first entry wins
initialization and contenders return `-EAGAIN`; later entries take the ready
fast path. Applications call the host API before exposing entry programs and
therefore do not see that contention. They never call the compiler-internal
`__bpf_capsule_init()` function directly.

### Completion and aborts

`CAPSULE_PENDING` means the compiled in-kernel drive span was exhausted; it is
not a tunable batch size. `CAPSULE_YIELD` means managed code deliberately
returned to its native caller through `capsule_yield()`. The application owns
the request/response protocol; Capsule only preserves the software stack and
distinguishes voluntary yield from budget exhaustion. Pass either result's
continuation to exactly one later
`capsule_continue()` or `capsule_reset()` call. A continuation is a
single-consumer handle; copying it and using both copies, including concurrently
from different CPUs, is invalid. Malformed tokens report
`CAPSULE_ERROR_INVALID_CONTINUATION`; an already-consumed token or one from an
earlier lease generation reports `CAPSULE_ERROR_STALE_CONTINUATION`, without
disturbing the current owner of that fiber. Tokens are opaque protocol values,
not security capabilities: deriving or forging future generation values is
outside the API contract (and the privileged loader could mutate the backing
maps directly anyway). There is deliberately no host
helper for driving continuations: hosts run their programs with plain libbpf
and branch on the status their control map publishes. The syscall-model loop
is a few explicit lines:

```c
if (bpf_prog_test_run_opts(run_fd, &options))
    return -1;
while (control->capsule.status == CAPSULE_PENDING) {
    if (drains++ == MAX_DRAINS)
        return -1; // wedged: "pending" forever is indistinguishable
    if (bpf_prog_test_run_opts(drain_fd, &options))
        return -1;
}
switch (control->capsule.status) { /* OK, EXITED, YIELD */ }
```

`CAPSULE_EXITED` carries one signed code in `capsule_result.code`: the
guest's `exit()` status when non-negative, the framework's stop reason when
negative (`bpf_capsule_error_string()` names those). Attached hooks never
loop: they must complete in-span, and a pending result there is a failure to
handle with `capsule_reset()`.

Production hooks such as XDP cannot ask userspace to resume one packet. Such a
root must complete within the compiler's in-kernel drive span. The regression
suite requires zero userspace continuation drains for ordinary library
computation; staging and repeated benchmark operations may use distinct entry
calls.

`capsule_exit(status)` — and freestanding `exit(status)` — is the one way
guest code ends the computation early: the caller observes `CAPSULE_EXITED`
with the POSIX-masked status (0..255) in `capsule_result.code`. It is a nonlocal
stop, not C++ unwinding: destructors and atexit handlers do not run, and the
fiber is reclaimed automatically. A negative `capsule_result.code` is the
framework's channel — stack overflow, invalid managed memory, traps, and
compiler/runtime invariant failures. Guest and language adapters use
non-negative exit statuses even when their implementation reaches the same
internal nonlocal-stop primitive: Lua script errors conventionally exit 1,
Rust panic exits 101, and freestanding `abort()` exits 134. Richer failure
detail belongs in the application's own control struct.
`capsule_reset(continuation)` is the explicit cancellation operation for
pending work; it discards that live stack and returns the slot to the pool. The
freestanding support maps `abort()` and `exit()` to their corresponding Capsule
terminal results.

### Borrowed verifier context

A verifier-owned pointer such as `struct xdp_md *` cannot be stored in Capsule
memory and resumed later without losing its kernel type. Passing it as a
pointer argument to a Capsule root selects the typed driver. The compiler
threads that exact pointer through physical step subprograms, so ctx and packet
accesses retain verifier provenance and bypass virtual-memory lowering.

This first implementation supports one borrowed context argument per object,
and it must finish in the current entry invocation. A borrowed root is
rematerializable at every physical step, but any pointer derived from it—such
as a packet-data or map-value pointer—is valid only inside one non-suspendable
physical region. Load scalar data before a managed call, or reacquire and
recheck the verifier pointer after it. The compiler diagnoses a derived
pointer live across a managed call, `capsule_yield()`, resumable loop boundary,
or physical region cut.

Managed code below the root reads the live context with
`capsule_borrowed_ctx()` and casts it to the entry's context type; the marker
never stores the pointer, so its verifier identity is preserved at every use.
The Lua-XDP packet accessors re-derive `data`/`data_end` from it inside each
bounded region for exactly the lifetime reasons above.

### BPF helpers from managed code

Managed code may call ordinary BPF helpers with scalar arguments and results —
`bpf_ktime_get_ns()`, `bpf_map_lookup_elem()` on explicitly sectioned maps,
`bpf_ringbuf_output()` from native code after copy-out. The rule is the same
one that governs every verifier-owned pointer: a helper-returned pointer (a
map value, a ring-buffer reservation, a dynptr) is valid only inside one
non-suspendable physical region. Re-acquire it after anything that may
suspend; never store it in Capsule memory. Naming a managed function with the
`__bpf_capsule_nosuspend_` prefix asks the compiler to flatten it into a
single non-suspendable region — the diagnostic-checked way to hold such a
pointer across a short critical section, used by the bundled allocator's
lease protocol.

If an XDP Capsule reports pending, the native wrapper must choose its
hook-specific fallback and call `capsule_reset()`; it cannot continue the
packet in a later invocation. It may handle `CAPSULE_YIELD` immediately inside
the same XDP invocation and call `capsule_continue()`. The Lua-XDP example
demonstrates the faster direct borrowed-context path and an always-pass failure
policy. The context-interoperability test measures that path against an
equivalent yield/native-copy/continue protocol.

## Memory visible to userspace

Ordinary unsectioned globals belong to Capsule memory. The compiler relocates
them automatically, including zero storage and pointer-valued initializers.
Program code does not select an arena or map backend. In particular, large
import buffers are ordinary unsectioned globals; the compiler chooses their
representation for the selected kernel target.

Globals with explicit sections remain ordinary BPF global-data maps. Use these
for small, fixed-layout control mailboxes and outputs that the host or a helper
must access. Keep their indexed accesses visibly bounded; the compiler adds
old-verifier-safe bounds where it can, but a mailbox is easiest to verify when
it contains fixed-offset scalars.

For host-sized input, set `reserved_bytes` during configuration, obtain its
address from `bpf_capsule_memory_reserved_start()`, and copy the bytes with
`bpf_capsule_memory_write()`. The managed allocator sees only the heap suffix
after that reservation. The llama, zlib, and wasm3 examples use this route, so
input size is not a compiled array bound. A program may instead publish the
Capsule address and capacity of a compile-time global through a sectioned
control map; Doom uses that form for its fixed WAD buffer. In either case the
host memory view hides the selected backend.

For synchronous `BPF_PROG_TEST_RUN`, write input before invoking the program
and read output after the syscall returns; that boundary orders the transfer.
For attached programs or concurrent host access, `volatile` only prevents a
compiler cache and is not synchronization. Use an application protocol and
appropriate atomics, and do not live-poll a mailbox while BPF mutates it unless
that protocol makes the ownership transition explicit.

Native BPF uses the same flat address space without a userspace round trip.
Given a scalar Capsule address returned by managed code or exchanged through a
sectioned mailbox, `capsule_memory_pointer(type, address)` may be dereferenced
or used as the Capsule side of a bulk copy. On 6.9 it becomes an arena access;
on 5.15 it routes through the generated map-backed accessors. Verifier-owned
source or destination pointers retain their original provenance.

The compiler assigns static program storage first. The configured heap follows
it, then an alignment gap if the physical tier requires one, then the selected
fiber stacks. `capsule_heap_start()` and `capsule_heap_size()` expose exactly
the allocator-owned heap interval to managed code. On arena targets the host
sizes sparse backing to those selected intervals at 4 KiB granularity. On 5.15
the first 32 directly relocatable 2 MiB regions are the fast prefix and all
remaining capacity uses one mmapable ARRAY map. Stacks are deliberately placed
in the tail, preserving the direct prefix for ordinary heap traffic. Host
memory helpers work across both representations and reject the alignment gap
and addresses beyond the configured end.

Do not pass process pointers into managed code. File I/O, clocks, devices,
sockets, and other operating-system services are explicit host/platform
callbacks over staged data, not implicit syscalls from the library.

## Atomics

> [!CAUTION]
> **Unsupported atomics are compile-time errors.** The compiler never silently
> converts an atomic operation into a non-atomic access and never reports
> contention as a run-time atomic failure.

The current Capsule-domain contract is deliberately narrow:

| Operation | Supported |
| --- | --- |
| Naturally aligned integer/pointer atomic load or store, 8/16/32/64 bit, relaxed ordering | Yes |
| Atomic read-modify-write (`fetch_add`, `fetch_or`, exchange, and similar) | No |
| Compare-exchange | No |
| Atomic fence | No |
| Acquire, release, acquire-release, or sequentially-consistent ordering | No |

“Relaxed” means C/C++ `memory_order_relaxed`, Rust `Ordering::Relaxed`, or LLVM
IR `unordered`/`monotonic`. The supported operation stays atomic across CPUs:
after optimization, memory routing emits exactly one naturally sized BPF
load/store for the object. This is the subset used by the bundled SQLite
workload, including its byte flags. Misalignment, an unsupported scalar width,
or any operation in a `No` row stops compilation with a diagnostic naming the
operation, width, function and selected kernel profile.

Native-domain atomics are not virtualized. LLVM emits genuine BPF atomic
instructions for them, and the selected kernel/JIT must implement that
instruction. Native synchronization used by the compiler runtime or allocator
does not extend the Capsule-domain subset above.

## Concurrency and limits

A loaded object owns a pre-load-sized pool of fiber state. The object is
compiled with `BPF_CAPSULE_MAX_FIBERS` as a verifier/control upper bound (512
by default), then the host calls
`bpf_capsule_configure(object, config)` after open and before
load. An unconfigured object defaults to one active fiber and a 4 MiB heap.
`capsule_call()` leases a free slot atomically.
Fibers isolate software stacks, return slots, abort state, call staging, and
transient physical spills in the low end of that same fiber stack, so
independent calls may execute simultaneously and may resume on a different CPU.

The compiled maximum does not allocate all of its fiber stacks. Arena objects
commit only `fiber_count` stacks during initialization; fixed-tier objects
resize the unified ARRAY tail before load, rounded to its 2 MiB value granularity.
Only the 32-byte control records are sized by the compiled maximum (16 KiB for
512); configure resizes the small lease/recycle maps to `fiber_count` before
load. Those maps are preallocated because Linux 5.15 requires it for sleepable
programs. There is no one-fiber compiler or runtime specialization. The
release benchmark runs the same active CPU count with compiled bounds 64 and
512 and prints their paired timing difference for human review; host-specific
timings are not a functional regression gate.

Managed code can call `capsule_fiber_index()` to obtain the already-carried fiber
index without a helper or map lookup. An ordinary array indexed by that value
is the intended fiber-local-storage pattern. For example, the Lua XDP demo
stores one persistent `lua_State*` and compiled-policy reference per fiber;
the VM's allocations still come from the shared heap.

The bundled TLSF allocator is also safe across those calls. A global HASH-map
lease serializes each complete allocator metadata operation. The compiler
proves that the lock holder is a bounded, non-suspendable BPF subprogram;
contention returns before mutation and retries only in managed code. This is a
single global lock by design: heap data is shared and the scheme does not
multiply the heap by CPU or fiber count.

Ordinary mutable globals remain shared and require application-level
synchronization using the supported atomic subset or a native wrapper. Managed
code still cannot create pthreads, use general thread-local storage, or rely on
unsupported complex atomics; those operations are not silently weakened.

Both memory tiers expose a compiler-owned 32-bit program address space, with
the actual backing size selected before load. Data ends below the final 2 MiB,
which is reserved for disjoint managed-function tokens. The native BPF stack is used for hot
verifier-safe values, while escaping or large locals and unavoidable physical
spills move to managed storage automatically. The safe native hot budget is an
internal compiler invariant rather than an application setting.

Unsupported semantics include C++ exceptions, general `setjmp`/`longjmp`,
thread creation and general thread-local storage, and arbitrary operating-
system calls. Floating point is supported by software lowering and is
therefore substantially slower than integer code.

Calls to a variadic function defined in the linked bitcode are lowered to the
Capsule slot ABI. Calls to a declared-only variadic external are rejected:
BPF has no external variadic ABI, so expose a fixed-signature wrapper instead.
The freestanding `setjmp` and `longjmp` symbols exist so dependent code links,
but executing either terminates the computation with
`CAPSULE_ERROR_UNSUPPORTED_LIBC`; they do not implement nonlocal control flow.

The bundled freestanding libc fails unavailable OS services explicitly:
`gettimeofday()` returns `-1`/`ENOSYS`, and its non-output `printf()` and
`fprintf()` stubs return `EOF`/`EBADF`. Applications provide their own output
callback, ring buffer, or control-memory protocol instead of receiving a fake
clock or silently successful I/O.

## Host-side loading

The lifecycle is three separate verbs, each owned by the right party:
configure with Capsule, load with libbpf, initialize with Capsule. The shared
helpers in `bpf_capsule_host.h` cover only what is genuinely Capsule:

- `bpf_capsule_configure()` selects active fibers and heap bytes before load
  (plan + apply against the object's configuration record);
- libbpf's own `bpf_object__load()` / `bpf_object__load_skeleton()` load the
  object — loading is libbpf's job and nothing wraps it;
- `bpf_capsule_finish_initialization()` runs the generated
  `bpf_capsule_init` program once after load, bringing up the managed
  address space on the arena tier (a no-op on the fixed-map tier);
- `bpf_capsule_memory()` assembles the object's memory view once after load;
  every bulk transfer then goes through `bpf_capsule_memory_read()` /
  `bpf_capsule_memory_write()` over that view, exchanging bytes through a Capsule
  address without exposing arena or fixed-region placement, and the view's
  accessors report the managed image bounds
  (`bpf_capsule_memory_start/size`) and the host-reserved heap prefix
  (`bpf_capsule_memory_reserved_start/size`) selected at configure time through
  `bpf_capsule_config.reserved_bytes` — the allocator sees only the heap's
  remaining suffix.

Every fallible host helper returns `-1` and sets `errno`; zero is success.
Configuration uses `EINVAL`/`ENOENT` for a malformed or foreign object,
`EBUSY` after load, `E2BIG` above the compiled fiber ceiling, `ENOMEM` for an
oversized reservation, and `EOVERFLOW` for unrepresentable geometry, while a
libbpf resize error preserves its errno. Initialization preserves libbpf's
error or the initializer's negative errno. Memory-view construction uses
`EINVAL`, `ENOENT`, or `EFAULT`; transfers additionally use `EOVERFLOW` and
may preserve `mmap()` errno. A fixed-tier write that fails after crossing a
region may already have written its earlier regions, so validate addresses and
sizes before treating a transfer as transactional.

That list is the complete host surface, and none of it prints or reads
environment variables. Sectioned control globals come from the generated
skeleton's typed fields (`skeleton->data_fib->fib_state`); a raw-object
loader resolves them with its own BTF walk. Running programs is libbpf's job
(`bpf_prog_test_run_opts`, or an attached link); completion is observed
through the shared control map as shown above. Loaders in other ecosystems
(cilium/ebpf, aya) do not link this header: SPEC.md ("Loader contract")
specifies everything a reimplementation needs, with this header as the
reference.

The target selected at compile time is the oldest deployment kernel, written
as `major.minor`. It must not be newer than the kernel that loads the object.
The compile-time geometry bounds and per-object pre-load choices are:

```text
BPF_CAPSULE_TARGET_KERNEL=5.15  map-backed memory and BPF v3 instructions (default)
BPF_CAPSULE_TARGET_KERNEL=6.6   map-backed memory and BPF v4 instructions
BPF_CAPSULE_TARGET_KERNEL=6.9   arena memory and BPF v4 instructions
BPF_CAPSULE_MAX_FIBERS=512      compiled control/verifier ceiling (1..65535)
BPF_CAPSULE_FIBER_STACK_BYTES=262144  compiled per-fiber stack geometry

bpf_capsule_config.fiber_count     active fibers, selected before load
bpf_capsule_config.heap_bytes      total heap, selected before load
bpf_capsule_config.reserved_bytes  host-owned heap prefix, selected before load
```

The application-level control layout and managed-code semantics are otherwise
the same on both tiers.
