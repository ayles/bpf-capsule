# Proof programs

Nix fetches every upstream source as a fixed-output derivation. The example
apps are direct entry points to their installed host binaries, so arguments
and BPF privilege are explicit rather than supplied by a wrapper:

```sh
sudo nix run .#fib             # default app; `sudo nix run` is equivalent
sudo nix run .#zlib
sudo nix run .#lua -- "$PWD/examples/lua/lua/script.lua"
sudo nix run .#quickjs -- "$PWD/examples/quickjs/script.js"
```

The complete app list is `nix flake show`; the apps use the fast Linux 6.9
compile profile and pass all arguments through unchanged. The explicit CMake
path below is the reference for downstream integration and for selecting the
Linux 5.15 profile.

Configure once and let CMake fetch the pinned upstream sources:

```sh
nix develop
cmake -S . -B build-demo -DCMAKE_BUILD_TYPE=Release \
  -DBPF_CAPSULE_BUILD_EXAMPLES=ON
cmake --build build-demo -j
tests/run-proof-suite.sh build-demo
```

This writes `build-demo/bpf-capsule-proof.json` with correctness, execution,
load/JIT and object-size metrics. `nix flake check` is the complete functional
current-kernel-arena/5.15-map VM gate. `nix run .#benchmarks` runs the same
workloads with KVM and automatically compares performance with the previous
local run. Run `tests/run-proof-suite.sh` as your normal user: it elevates only
the BPF child processes, which preserves the Nix toolchain `PATH` for Python
and the build tools.
For the conventions shared by every BPF-side driver and host, see
[`PROGRAMMING.md`](PROGRAMMING.md).

`BPF_CAPSULE_TARGET_KERNEL` defaults to Linux 5.15. Set it to the oldest deployment
kernel when newer features are useful; for example, 6.9 selects arena memory.
The program interface does not otherwise change. For a clean kernel, use the
reproducible matrix in [`tests/vm`](../tests/vm/README.md).

Upstream source is fetched at its pinned version during configuration. For an
offline build, provide the corresponding `*_BPF_SOURCE_DIR` cache variable
(`PUREDOOM_SOURCE_DIR` for Doom); no fetch is attempted for a valid supplied
tree. Small scripts and deterministic fixtures are kept with their examples.
Large runtime data is not committed: real llama checkpoints and alternate
Doom WADs are paths supplied to their hosts.

## Headline demos

### Lua packet classifier and audit record

The real XDP-context demonstration reads live packet memory from stock Lua,
classifies TCP, UDP and other IPv4 packets, and sends its address/port audit
line to userspace through a BPF ring buffer. Its observer entry always returns
`XDP_PASS`. By default it attaches to the lowest-metric default-route interface:

```sh
sudo nix run .#lua-xdp -- "$PWD/examples/lua/lua-xdp/packet_observer.lua"
sudo nix run .#lua-xdp -- ./observer.lua
sudo nix run .#lua-xdp -- ./observer.lua eth0
```

Lua `print()` records appear directly on stdout. The unpinned BPF link detaches
on Ctrl-C, normal exit, crash, or SIGKILL, and refuses to replace an existing
XDP attachment. Each Capsule fiber retains an independent Lua VM, compiled
policy, and Lua globals across packet invocations. Lua can inspect the first
2,048 bytes of each packet; `#packet` reports that visible prefix length. Lua
errors are emitted through the same ring buffer and poison only the current
fiber's VM until the loader installs a fresh script revision. Run
`lua-xdp-test` with the filter and observer script paths for deterministic
synthetic TCP, UDP, generic IPv4, truncation, error/reload, prefix-boundary, and
retained-state assertions, or run `lua-xdp-benchmark` with a filter script to
measure the cold and steady paths separately. This is a context-interoperation
demonstration, not a production line-rate observer: its multi-megabyte
per-fiber VM state makes hot and cold-cache costs hardware-dependent, and
observing a busy link can visibly throttle it. Compare the dedicated benchmark
before and after changes on the same host. The complete direct commands are
documented in the [`lua-xdp` README](../examples/lua/lua-xdp/README.md).

The small ordinary Lua example behaves like the interpreter it wraps: the
script and batch stdin go into guest-owned buffers, a temporary stock Lua
5.4.8 VM runs in the kernel, and stdout, error text and the exit code come
back the way `lua SCRIPT < input` would return them. `--native` runs the same
script on the natively built Lua instead, so the two engines can be compared
on any machine; each run reports its real execution time on stderr — the
kernel's own BPF runtime accounting (`run_time_ns`), never syscall wall time.
It has no packet interface or retained state:

```sh
sudo build-demo/examples/lua/lua/lua examples/lua/lua/script.lua
```

```text
Lua checksum	16898	true	0
kernel execution: 2265880 ns
```

The separate live-XDP example retains one Lua VM and compiled policy per active
fiber. Its deterministic test uses `BPF_PROG_TEST_RUN.data_in` to compare TCP,
UDP, generic IPv4, and truncated-packet behavior before the live loader is
attached.

### Doom

Doom is built through exactly the same public pipeline as the library
examples. `tools/fetch-doom-wad.sh` downloads the free
[Freedoom](https://freedoom.github.io/) Phase 1 IWAD (pinned by SHA-256);
any lawfully obtained DOOM IWAD works the same way:

```sh
mkdir frames
sudo build-demo/examples/doom/doom \
  "$(tools/fetch-doom-wad.sh)" dump 5 frames
```

The WAD is game data under its own terms and is deliberately not part of this
source repository. The example's combined source and executable are
GPL-2.0-only; this does not change the core compiler's permissive license. The
installed Doom bundle includes the pinned upstream header and every patch as
corresponding source. Two documented PureDOOM patches
initialize the replacement framebuffer and bound the vanilla texture-column
over-read exposed by sparse Freedoom patches; there are no BPF-specific changes
to the engine.

### Unmodified zlib

The zlib driver links the pinned, unmodified upstream inflate implementation:

```sh
sudo build-demo/examples/zlib/zlib
```

It generates compressible input, drives each BPF inflate to completion with no
userspace continuation drain, compares every output byte with the matched
scalar sources built natively and with the platform's system zlib, repeats the
implementations for timing stability, and reports the three inflate times.
Any byte or checksum divergence is a nonzero exit.

### Standalone consumer template

[`examples/standalone`](../examples/standalone) is not part of this build: it
is a self-contained CMake project that consumes an *installed* BPF Capsule
package through `find_package(BpfCapsule)`, exactly as a downstream repository
would. It compiles a recursive-descent expression evaluator — recursion depth
chosen by the input — prints the evaluated value, and verifies the kernel
result against the natively compiled evaluator (any disagreement is a nonzero
exit). Its README carries the copy-paste build steps.

## Remaining coverage

Where a meaningful native execution exists, the example verifies the kernel
result against it and exits nonzero on divergence. Comparative hosts also
report the kernel's `run_time_ns` next to native thread CPU time. `lua` and `quickjs`
additionally accept `--native` to run the identical script on the natively
built interpreter, so the two engines can be compared on any machine.

| Program | Command arguments | Reported result |
| --- | --- | --- |
| wasm3 + zlib Wasm guest | `wasm3 [bytes]` | inflate sizes + adler, kernel/native times |
| QuickJS | `quickjs examples/quickjs/script.js` | script stdout, kernel time |
| SQLite | `sqlite` | `rows=… checksum=…`, kernel/native times |
| Rust `no_std` + `alloc` | `rust` | MLP checksum, `panic demo: status=exited code=101` |
| llama2 float | `llama2 MODEL [steps]` | `tokens: …`, kernel/native times |
| llama2 Q8 | `llama2q MODEL [steps]` | `tokens: …`, kernel/native times |
| C transform overhead | `overhead_host direct.o transformed.o` | `OVERHEAD-PASS` |
| Rust transform overhead | `rust_overhead_host direct.o transformed.o` | `RUST-OVERHEAD-PASS` |

The llama harnesses intentionally do not download model data. The automatic
proof suite generates tiny structurally valid fp32 and Q8 checkpoints. The
commands also accept matching llama2.c checkpoint formats, but these examples
are not hardened parsers for hostile or arbitrary model files. The host
reserves exactly the supplied image size in unified memory and copies it once;
the reported inference completes with zero continuation drains.
