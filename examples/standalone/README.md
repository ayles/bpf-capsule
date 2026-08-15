# Standalone consumer template

This directory is the template for using BPF Capsule from your own
repository. It is a complete CMake project that depends only on an installed
BPF Capsule package plus libbpf — copy it out, rename the targets, and
replace the workload.

The workload is a recursive-descent evaluator for integer arithmetic
(`2*(3+4)-10%3`). Recursion depth and loop trip counts are chosen by the
input string, which stock eBPF cannot express: the verifier permits no
recursion and no loop without a provable bound. The same evaluator sources
compile unchanged for the kernel (through BPF Capsule) and for the host
(natively), and the host requires bit-for-bit equal results. The default
input is a parenthesis tower 64 levels deep.

- `expr.h` / `expr.c` — the workload: ordinary freestanding C, no BPF
  awareness.
- `expr_ctrl.h` — the shared control ABI: one struct and one stage enum,
  included by both sides so they cannot disagree.
- `expr_bpf.c` — the kernel driver: owns the control map, and defines the `expr_prepare` /
  `expr_run` / `expr_drain` syscall entries. The guest owns the input buffer
  and `expr_prepare` publishes its address and capacity; the typed
  `capsule_call` writes the root's return value into the control map on
  completion.
- `expr_host.c` — the libbpf skeleton loader: runs `expr_prepare`, writes the
  input to the published address with `bpf_capsule_memory_write`, drives the
  program to completion with a capped drain loop, verifies against native,
  and reports kernel `run_time_ns` beside native thread CPU time.

## Build and run

Requires an installed BPF Capsule package, LLVM/Clang 22 on `PATH`, libbpf 1.4 or newer,
and pkg-config.

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=<bpf-capsule install prefix>
cmake --build build
sudo ./build/expr
```

Success prints only the evaluated value on stdout. Informational kernel/native
execution times go to stderr; a disagreement is reported there with a nonzero
exit. Pass your own expression as its sole argument:

```sh
sudo ./build/expr '2*(3+4)-10%3'
```

## The CMake surface

`find_package(BpfCapsule CONFIG REQUIRED)` provides the complete compilation
pipeline. `bpf_capsule_bitcode(out SOURCES ... COMPILE_OPTIONS ...)` compiles
CMake-managed C and C++ sources to LLVM bitcode with the matching Clang it
discovers alongside `llc`. It owns target, memory-model, runtime-include, and
freestanding flags while the project supplies only source-specific includes,
definitions, and options.
Set `BPF_CAPSULE_LIBBPF_TARGET` to the imported CMake target that supplies
`bpf_helpers.h`; this project uses `PkgConfig::LibBpf`, but the target name is
not otherwise prescribed.
`bpf_capsule_rust_bitcode()` provides the corresponding Cargo integration.
`bpf_capsule_object(target OUTPUT ... BITCODE ...)` links the bitcode, runs the
verifier-oriented transform pipeline, and emits the final loadable object.
`bpf_capsule_skeleton(target OUTPUT ... OBJECT ... NAME ...)` runs stock
`bpftool gen skeleton`; the resulting header embeds that object so the host is
a single executable. The one compatibility choice is the `BPF_CAPSULE_TARGET_KERNEL`
cache variable: `5.15` (the default and floor: map-backed memory regions, BPF
v3 instructions), `6.6` (map-backed memory, BPF v4 instructions), or `6.9`
(arena memory, BPF v4 instructions). Applications may also set the documented
ABI geometry bounds
`BPF_CAPSULE_MAX_FIBERS` (1 through 65,535) and
`BPF_CAPSULE_FIBER_STACK_BYTES`; active fiber and
heap capacity remain pre-load host configuration. Pass order, native-stack
budgets, and verifier workarounds are compiler decisions rather than tuning
knobs.

The installed `bpf_capsule_host.h` supplies the corresponding libbpf-side
configuration, post-load initialization, and Capsule memory access — and
nothing else. Loading itself is libbpf's own call, control globals are the
skeleton's typed fields, and programs are run with plain libbpf
(`bpf_prog_test_run_opts`),
and the host loops on `CAPSULE_PENDING` itself, as `expr_host.c` shows: the
continuation loop is deliberately explicit application code, not a wrapper.

Guest code includes only `bpf_capsule.h`; the runtime is compiled into the
object by the pipeline automatically.

## Licensing notes for your own project

Two facts worth knowing before you ship a derivative:

- The BPF program declares `SEC("license") = "GPL"`. The kernel requires a
  GPL-compatible program license before it exposes most kfuncs — including
  `bpf_arena_alloc_pages`, which the 6.9 arena tier uses during
  initialization — so on that tier the declaration is load-bearing, not
  boilerplate. The declaration covers the BPF program you load, not your
  userspace host.
- What you link: the runtime headers are Apache-2.0 WITH LLVM-exception. If
  your program pulls in the installed freestanding libc sources (or uses
  `bpf_capsule_rust_bitcode()`, which always links them), note that
  `tlsf.c` is BSD-3-Clause — binary redistribution must reproduce its
  notice (installed as `share/bpf-capsule/libc/TLSF-LICENSE`) — and Rust
  builds statically link the Rust sysroot. `core` and `alloc` are Apache-2.0
  OR MIT; `compiler_builtins` is MIT AND Apache-2.0 WITH LLVM-exception AND
  (MIT OR Apache-2.0). Its upstream notice is installed as
  `share/licenses/bpf-capsule/compiler-builtins-LICENSE.txt`; see the installed
  `THIRD_PARTY.md` for the complete inventory.
