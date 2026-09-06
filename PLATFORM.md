# A virtual platform plan for Capsule programs

Status: design note. The default platform currently supplies allocation,
fiber-local `errno`, termination, and weak OS stubs. The components below are
planned, not part of the public API yet.

## Goal

Provide optional Unix-like services so existing libraries need fewer custom
adapters. This is not a promise of POSIX conformance. Local operations must
neither delegate work to userspace nor explicitly suspend the fiber; external
work belongs to a separately selected proxy.

WASI is a useful guide to the boundaries: filesystem, descriptors and streams,
arguments and environment, clocks, random data, and sockets are independent
capabilities. Capsule should use that decomposition while continuing to expose
the normal C and Picolibc interfaces.

## Components

The existing core platform remains the default. It contains the TLSF
allocator, fiber-local `errno`, `_exit`/`abort`, and fallbacks which return an
honest `ENOSYS`, `ENOTSUP`, or descriptor error. It must not silently pretend
that an unavailable operation succeeded.

Optional components are ordinary bitcode archives:

| Component | Interface and implementation |
| --- | --- |
| `environment` | `argv`, `environ`, current directory, umask, configured process identity, and useful `sysconf`/`pathconf` values. |
| `vfs` | A writable in-memory filesystem and descriptor table: files, directories, links, path lookup, `openat`, read/write, seek, stat, truncate, rename, and directory iteration. |
| `stdio` | File descriptors 0, 1, and 2 backed by bounded input and output streams. Picolibc continues to implement `FILE`, `printf`, and the rest of stdio. |
| `clocks` | A monotonic BPF clock, a realtime clock derived from a host-supplied epoch, and a deterministic clock for tests. |
| `random` | A host-seeded CSPRNG for `getentropy`; explicitly insecure random data is a separate interface and must not masquerade as entropy. |
| `ipc` | In-memory pipes and socket pairs plus non-blocking `poll`/`select`. Blocking waits require the scheduler described below. |
| `signals` | Synchronous handlers, masks, and `raise`. It does not claim asynchronous process-signal semantics. |
| `mman-compat` | Anonymous heap-backed `mmap` for software that uses it as an allocator. No page protection, fixed mappings, or fault semantics. |
| `host-proxy` | Explicit, capability-scoped access to host files, sockets, DNS, or other services by yielding and resuming a fiber. |
| `threads` | A later cooperative pthread subset implemented by a Capsule scheduler over fibers. |

Processes (`fork`, `exec`, and `wait`), preemptive threads, asynchronous Unix
signals, job control, dynamic code loading, general `ioctl`, and real virtual
memory cannot be implemented honestly. Those operations remain unavailable.

## Filesystem shape

The VFS has one process-wide descriptor namespace. Open file descriptions own
offsets and are shared by duplicated descriptors, as on Unix. This logical
model does not require one globally locked table: its storage may be sharded
or owned per fiber, with explicit cross-owner handoff. `errno` remains
fiber-local.

A packet-path operation must never spin or wait for shared state. It must use
lock-free or per-fiber state, or report contention after one bounded attempt.
The bounded primitive may be a sectioned-map atomic on capable JITs or the map
lease used by older profiles; neither permits a lock to cross a yield or
continuation boundary.

An initial filesystem is a packed, immutable image staged by the host in
Capsule memory before the first call. A writable overlay stores new files,
changed blocks, metadata, and deletion markers in the Capsule heap. Reads from
untouched files therefore require neither an initialization copy nor a trip to
userspace. The same mechanism can hold a Python standard library, scripts,
models, or application data.

Before implementing the overlay, choose and test a bounded allocation strategy
on both tiers. The current TLSF wrapper may suspend on contention; per-fiber
ownership with remote handoff is a candidate, not a settled design.

The host can read and write quiescent data directly on either tier. Live
mutations need a shared synchronization protocol: compatible hardware atomics
where supported, or a management BPF entry for guest-only map leases. BPF must
never wait for a lock held by interrupted userspace. Host allocation currently
uses `bpf_capsule_malloc`/`bpf_capsule_free` to execute the guest allocator
through `BPF_PROG_TEST_RUN`; no native host allocator shares its metadata.

stdin is either a fixed buffer or an in-memory pipe. stdout and stderr are
bounded buffers by default, so the host can read them directly. A program may
provide a separate ring-buffer adapter for live output; generic stdio must not
assume that one exists.

## Selection and initialization

Select components by linking their bitcode archives, with CMake targets such
as `BpfCapsule::vfs` for convenience. Archive extraction and whole-program DCE
discard unused functions; no runtime vtable is needed.

The current weak syscall definitions cannot stay in an always-linked module:
they make symbols look resolved before an optional archive can provide the
strong implementation. Move fallbacks into an archive linked last. Link order
must be application objects, selected components, fallback platform, then
Picolibc. Tests must prove that application definitions override components,
components override fallbacks, and unused archive members are absent.

Each component has an explicit guest-side initialization function. The virtual
process state is global to one BPF object, matching ordinary POSIX process
state; callers pass storage, limits, mounted images, stream buffers, clock
origin, and entropy seed explicitly. Compile-time constants are verifier
ceilings only. Actual capacities are chosen at initialization.

## Suspension boundary

Local filesystem, buffered stdio, environment, clocks, and seeded randomness
do not introduce I/O suspension. They remain usable in an XDP packet path
without an obligatory userspace round trip.

An empty blocking pipe, sleep, or host-proxy request may suspend only when a
scheduler/driver was explicitly selected. The fiber publishes a request and a
wake condition, yields, and resumes after another BPF invocation supplies the
result. No lock may be held across that boundary. Non-blocking mode instead
returns `EAGAIN`.

Host-backed access is therefore useful for batch programs and initialization,
not as an implicit dependency of a per-packet program.

## Implementation order

1. Turn the current syscall stubs into a final fallback archive and add linker
   precedence/dead-code tests.
2. Choose and validate the VFS state and allocation strategy on both memory
   tiers.
3. Implement the descriptor layer, packed read-only image, writable overlay,
   VFS operations, and buffered stdio.
4. Add environment, clocks, and host-seeded randomness.
5. Add in-memory IPC, synchronous signals, and the limited mapping adapter.
6. Design the scheduler and host-proxy protocol separately; then add host
   filesystem and networking backends without changing the local fast path.
7. Replace example-specific file importers with the VFS, starting with CPython.

Every component needs native semantic tests, kernel execution tests on the
oldest supported profile, instruction-count tracking, and a test showing that
an object which does not select it is unchanged.
