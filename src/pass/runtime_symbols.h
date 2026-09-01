// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Pass-facing constants for symbol names shared with the runtime and host.
// Loader-visible spellings come from bpf_capsule_names.h; callable helper
// names below remain centralized here and resolve against runtime/libc
// definitions during the whole-program link.
//
// Metadata kind names (the passes' internal wire format) live in common.h as
// bpf::md; this header is strictly linkage-visible names: functions, globals,
// generated-name prefixes, and ELF sections.
//
// The extraction line these names trace is categorical, not size-based:
// whatever computes a VALUE (arithmetic, library semantics) lives in C
// behind a name here — always_inline where it must fold back into its call
// sites during the post-link O2 — while the passes keep only STRUCTURE:
// types, signatures, control flow, metadata, and the marshalling that
// adapts IR vocabulary (comparison predicates, operand splitting) onto
// these C entry points. A pass that runs after the post-link O2 must emit
// its lowerings as IR: no inliner runs later to fold a C call away.
#pragma once

#include "bpf_capsule_names.h"

#include <llvm/ADT/StringRef.h>

namespace bpf::sym {

// ------------------------------------------------ runtime (bpf_capsule.c)

// A symbol bpf_capsule.c genuinely defines (several guest-header names are
// extern markers the compiler resolves, not definitions); bpf-capsule-ld
// probes it to verify the runtime was linked.
inline constexpr llvm::StringLiteral RuntimeProbe{"__bpf_capsule_fiber_acquire"};

// The bounded two-level continuation drivers. `Trampoline` doubles as the
// prefix of the whole driver family for starts_with checks.
inline constexpr llvm::StringLiteral Trampoline{"__bpf_capsule_trampoline"};
inline constexpr llvm::StringLiteral TrampolineL1{"__bpf_capsule_trampoline_l1"};
inline constexpr llvm::StringLiteral TrampolineStep{"__bpf_capsule_trampoline_step"};
inline constexpr llvm::StringLiteral TrampolineCtx{"__bpf_capsule_trampoline_ctx"};
inline constexpr llvm::StringLiteral TrampolineCtxL1{"__bpf_capsule_trampoline_ctx_l1"};
inline constexpr llvm::StringLiteral TrampolineCtxStep{"__bpf_capsule_trampoline_ctx_step"};

// Compiler markers the compiler-facing headers declare and passes resolve.
inline constexpr llvm::StringLiteral CallMarker{"__bpf_capsule_call"};
inline constexpr llvm::StringLiteral ExitMarker{"__bpf_capsule_exit"};
inline constexpr llvm::StringLiteral Yield{"__bpf_capsule_yield"};
inline constexpr llvm::StringLiteral Setjmp{"__bpf_capsule_setjmp"};
inline constexpr llvm::StringLiteral Longjmp{"__bpf_capsule_longjmp"};
inline constexpr llvm::StringLiteral SuspendBarrier{"__bpf_capsule_suspend_barrier"};
inline constexpr llvm::StringLiteral CopyReturn{"__bpf_capsule_copy_return"};
inline constexpr llvm::StringLiteral CurrentFiberIndex{"__bpf_capsule_current_fiber_index"};
inline constexpr llvm::StringLiteral ActiveFiberCount{"__bpf_capsule_active_fiber_count"};
inline constexpr llvm::StringLiteral OutcomePointer{"__bpf_capsule_outcome_ptr"};
inline constexpr llvm::StringLiteral CurrentCtx{"__bpf_capsule_current_ctx"};
inline constexpr llvm::StringLiteral VaArg{"__bpf_capsule_va_arg"};

// Late memory intrinsics: lowered by bpf-memory after layout is known.
inline constexpr llvm::StringLiteral HeapStart{"__bpf_capsule_heap_start"};
inline constexpr llvm::StringLiteral HeapSize{"__bpf_capsule_heap_size"};
inline constexpr llvm::StringLiteral StackRegion{"__bpf_capsule_stack_region"};

// Runtime call glue with pointer arguments; must fold into its entry program
// because a global subprogram cannot accept the entry's native stack
// pointers. Each keeps its alwaysinline from the runtime source.
inline constexpr llvm::StringLiteral FinishExited{"__bpf_capsule_finish_exited"};
inline constexpr llvm::StringLiteral Continue{"__bpf_capsule_continue"};
inline constexpr llvm::StringLiteral Reset{"__bpf_capsule_reset"};

// Runtime globals the passes locate by name.
inline constexpr llvm::StringLiteral FiberControls{BPF_CAPSULE_SYMBOL_FIBER_CONTROLS};
inline constexpr llvm::StringLiteral Config{BPF_CAPSULE_SYMBOL_CONFIG};
inline constexpr llvm::StringLiteral ArenaControl{BPF_CAPSULE_SYMBOL_ARENA_CONTROL};
inline constexpr llvm::StringLiteral CallStack{"bpf_call_stack"};
inline constexpr llvm::StringLiteral HeapArray{BPF_CAPSULE_MAP_HEAP_ARRAY};
inline constexpr llvm::StringLiteral ArenaMap{BPF_CAPSULE_MAP_ARENA};

// Exact ELF sections which are part of the loader-visible object ABI.
inline constexpr llvm::StringLiteral ConfigSection{BPF_CAPSULE_SECTION_CONFIG};
inline constexpr llvm::StringLiteral ArenaControlSection{BPF_CAPSULE_SECTION_ARENA_CONTROL};
inline constexpr llvm::StringLiteral MapsSection{BPF_CAPSULE_SECTION_MAPS};
inline constexpr llvm::StringLiteral FixupSection{BPF_CAPSULE_SECTION_FIXUPS};
inline constexpr llvm::StringLiteral DataHeapSectionPrefix{BPF_CAPSULE_SECTION_DATA_HEAP_PREFIX};
inline constexpr llvm::StringLiteral BssHeapSectionPrefix{BPF_CAPSULE_SECTION_BSS_HEAP_PREFIX};

// The arena page-commit kfunc (kernel-defined, resolved via .ksyms).
inline constexpr llvm::StringLiteral ArenaAllocPages{"bpf_arena_alloc_pages"};

// ------------------------------------------------ generated by the passes

// The once-only arena initialization: the entry program libbpf runs eagerly,
// and the internal routine bpf-memory synthesizes for it and for the lazy
// first-entry fallback.
inline constexpr llvm::StringLiteral InitProgram{BPF_CAPSULE_PROGRAM_INIT};
inline constexpr llvm::StringLiteral InitRoutine{"__bpf_capsule_init"};

// The generated packed-outcome setter (a native scalar subprogram).
inline constexpr llvm::StringLiteral SetOutcome{"bpf_capsule_set_outcome"};

// Temporary code-generation allocation units and staging functions.
inline constexpr llvm::StringLiteral AllocationUnitPrefix{"bpf.unit."};
inline constexpr llvm::StringLiteral DispatchRouterPrefix{"bpf.dispatch."};
inline constexpr llvm::StringLiteral StagePrefix{"bpf.stage."};

// The old-kernel PC-to-allocation-unit table has its own section so the BPF
// backend cannot alias its name in libbpf skeletons.
inline constexpr llvm::StringLiteral PcUnitTable{"bpf_pc_unit"};
inline constexpr llvm::StringLiteral PcUnitSection{BPF_CAPSULE_SECTION_PC_TABLE};

// The empty inline-asm marker pinning (stack base, SP, outcome word) at one
// dominance point for the post-RA spill mover; stackify emits it with a
// leading "# ", the machine pass matches the bare name.
inline constexpr llvm::StringLiteral StackAnchor{"bpf_capsule_stack_anchor"};

// ------------------------------------------------ name prefixes

// Every runtime/libc-internal symbol. The passes use this only to separate
// runtime code from application code in diagnostics/BTF policy.
inline constexpr llvm::StringLiteral RuntimePrefix{"__bpf_"};

// The runtime's heap accessors: each one is a memory access and must stay
// inlinable (a call at every access clobbers the caller-saved registers and
// spills the caller past its 512-byte frame).
inline constexpr llvm::StringLiteral HeapPrefix{"bpf_heap_"};
inline constexpr llvm::StringLiteral HeapCommitPrefix{"bpf_heap_commit_"};
inline constexpr llvm::StringLiteral StackAccessorPrefix{"bpf_stack_"};

// ------------------------------------------------ arithmetic (runtime/libc)

// Wide multiplication, defined in the runtime (bpf-expand-i128).
inline constexpr llvm::StringLiteral Mul64Wide{"__bpf_mul64_wide"};
inline constexpr llvm::StringLiteral UMul64Overflow{"__bpf_umul64_overflow"};
inline constexpr llvm::StringLiteral SMul64Overflow{"__bpf_smul64_overflow"};

// i128 arithmetic, defined in freestanding int128.c (bpf-expand-i128).
inline constexpr llvm::StringLiteral Mul128{"__bpf_mul128"};
inline constexpr llvm::StringLiteral UDiv128{"__bpf_udiv128"};
inline constexpr llvm::StringLiteral URem128{"__bpf_urem128"};
inline constexpr llvm::StringLiteral SDiv128{"__bpf_sdiv128"};
inline constexpr llvm::StringLiteral SRem128{"__bpf_srem128"};

// ------------------------------------------------ soft-float (softfloat.c)

// bpf-soft-float lowers f32/f64 operations to these libc routines.
inline constexpr llvm::StringLiteral FAdd{"__bpf_fadd"};
inline constexpr llvm::StringLiteral FSub{"__bpf_fsub"};
inline constexpr llvm::StringLiteral FMul{"__bpf_fmul"};
inline constexpr llvm::StringLiteral FDiv{"__bpf_fdiv"};
inline constexpr llvm::StringLiteral FRem{"__bpf_frem"};
inline constexpr llvm::StringLiteral FCmp{"__bpf_fcmp"};
inline constexpr llvm::StringLiteral DAdd{"__bpf_dadd"};
inline constexpr llvm::StringLiteral DSub{"__bpf_dsub"};
inline constexpr llvm::StringLiteral DMul{"__bpf_dmul"};
inline constexpr llvm::StringLiteral DDiv{"__bpf_ddiv"};
inline constexpr llvm::StringLiteral DRem{"__bpf_drem"};
inline constexpr llvm::StringLiteral DCmp{"__bpf_dcmp"};
inline constexpr llvm::StringLiteral FNeg{"__bpf_fneg"};
inline constexpr llvm::StringLiteral DNeg{"__bpf_dneg"};
inline constexpr llvm::StringLiteral F2D{"__bpf_f2d"};
inline constexpr llvm::StringLiteral D2F{"__bpf_d2f"};
inline constexpr llvm::StringLiteral I2F{"__bpf_i2f"};
inline constexpr llvm::StringLiteral U2F{"__bpf_u2f"};
inline constexpr llvm::StringLiteral I2D{"__bpf_i2d"};
inline constexpr llvm::StringLiteral U2D{"__bpf_u2d"};
inline constexpr llvm::StringLiteral F2I{"__bpf_f2i"};
inline constexpr llvm::StringLiteral F2U{"__bpf_f2u"};
inline constexpr llvm::StringLiteral D2I{"__bpf_d2i"};
inline constexpr llvm::StringLiteral D2U{"__bpf_d2u"};

// Value-computing helpers written in C that must keep their always_inline
// through bpf-inline-policy: expanded into their call sites during post-link
// O2 they cost nothing once constants fold, while surviving as real
// subprograms multiplies verifier state at every arithmetic site.
inline bool IsAlwaysInlineArithmeticHelper(llvm::StringRef name) {
    // Division/remainder helpers deliberately stay out of this set: their
    // loops are too verifier-expensive to duplicate into every caller.
    return name == Mul64Wide || name == UMul64Overflow || name == SMul64Overflow || name == Mul128 || name == SDiv128 || name == SRem128 || name == FNeg ||
        name == DNeg;
}

} // namespace bpf::sym
