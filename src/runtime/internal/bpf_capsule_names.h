// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Private names shared by generated objects, compiler passes, and the host
// loader. Keeping a second spelling in a pass or loader makes an ordinary
// rename a run-time failure.
#pragma once

// Runtime globals and maps. Their string form is derived from the identifier
// used in the defining C declaration, so the object and loader cannot drift.
#define __BPF_CAPSULE_STRINGIFY_1(value) #value
#define __BPF_CAPSULE_STRINGIFY(value) __BPF_CAPSULE_STRINGIFY_1(value)
#define BPF_CAPSULE_FIBER_CONTROLS_GLOBAL bpf_capsule_fibers
#define BPF_CAPSULE_CONFIG_GLOBAL bpf_capsule_config
#define BPF_CAPSULE_ARENA_CONTROL_GLOBAL bpf_capsule_arena_control
#define BPF_CAPSULE_ARENA_MAP arena
#define BPF_CAPSULE_HEAP_ARRAY_MAP bpf_heap_array
#define BPF_CAPSULE_FIBER_LEASES_MAP bpf_capsule_fiber_leases
#define BPF_CAPSULE_ISSUED_FIBERS_MAP bpf_capsule_issued_fibers
#define BPF_CAPSULE_FREE_FIBERS_MAP bpf_capsule_free_fibers
#define BPF_CAPSULE_CONTINUATION_CLAIMS_MAP bpf_capsule_continuation_claims
#define BPF_CAPSULE_SYMBOL_FIBER_CONTROLS __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_FIBER_CONTROLS_GLOBAL)
#define BPF_CAPSULE_SYMBOL_CONFIG __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_CONFIG_GLOBAL)
#define BPF_CAPSULE_SYMBOL_ARENA_CONTROL __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_ARENA_CONTROL_GLOBAL)
#define BPF_CAPSULE_MAP_ARENA __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_ARENA_MAP)
#define BPF_CAPSULE_MAP_HEAP_ARRAY __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_HEAP_ARRAY_MAP)
#define BPF_CAPSULE_MAP_FIBER_LEASES __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_FIBER_LEASES_MAP)
#define BPF_CAPSULE_MAP_ISSUED_FIBERS __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_ISSUED_FIBERS_MAP)
#define BPF_CAPSULE_MAP_FREE_FIBERS __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_FREE_FIBERS_MAP)
#define BPF_CAPSULE_MAP_CONTINUATION_CLAIMS __BPF_CAPSULE_STRINGIFY(BPF_CAPSULE_CONTINUATION_CLAIMS_MAP)

// Exact ELF sections in the object/loader ABI.
#define BPF_CAPSULE_SECTION_MAPS ".maps"
#define BPF_CAPSULE_SECTION_CONFIG ".rodata.bpfconfig"
#define BPF_CAPSULE_SECTION_ARENA_CONTROL ".data.bpfctrl"
#define BPF_CAPSULE_SECTION_FIBER_CONTROLS ".bss.bpfctrl"
#define BPF_CAPSULE_SECTION_READY ".data.bpfrdy"
#define BPF_CAPSULE_SECTION_FIXUPS ".rodata.bpffix"
#define BPF_CAPSULE_SECTION_PC_TABLE ".rodata.bpfpc"
#define BPF_CAPSULE_SECTION_DATA_HEAP_PREFIX ".data.heap"
#define BPF_CAPSULE_SECTION_BSS_HEAP_PREFIX ".bss.heap"

// Host-run generated program.
#define BPF_CAPSULE_PROGRAM_INIT "bpf_capsule_init"

// Compiler-generated freplace programs. Other freplace sections in the same
// object belong to the application and are not part of the Capsule lifetime.
#define BPF_CAPSULE_FREPLACE_SECTION_PREFIX "freplace/"
#define BPF_CAPSULE_FREPLACE_TARGET_PREFIX "bpf_dispatch_output_"
#define BPF_CAPSULE_FREPLACE_PROGRAM_PREFIX BPF_CAPSULE_FREPLACE_SECTION_PREFIX BPF_CAPSULE_FREPLACE_TARGET_PREFIX
