// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"
#include "runtime_layout.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

llvm::DIType* BtfGetInt(llvm::DIBuilder& builder, size_t sizeInBits, bool isSigned);
llvm::DIType* BtfGetByteArrayPointer(llvm::DIBuilder& builder, uint64_t sizeBytes);

void BtfFunctionAddDebugInfo(llvm::DIBuilder& debugBuilder, llvm::Function& func, llvm::ArrayRef<llvm::Metadata*> paramTypes);

// The metadata kind, operand-bundle, and string-attribute names the passes
// use to talk to each other. Linkage-visible symbol names live in
// runtime_symbols.h as bpf::sym.
namespace bpf::md {

// Domain markers established by bpf-capsule-domains on functions and globals.
inline constexpr llvm::StringLiteral Capsule{"bpf.capsule"};
inline constexpr llvm::StringLiteral Native{"bpf.native"};

// The capsule_call boundary: an operand bundle on the crossing call.
inline constexpr llvm::StringLiteral CallBundle{"bpf.capsule.call"};

// A function proven to run without a Capsule suspension remains an ordinary
// BPF subprogram. NativeScalar is the stricter loader-visible scalar ABI used
// for independently verified global subprograms; NoSuspend also covers their
// internal pointer-bearing callees. Their allocas stay on the native BPF
// stack and are budgeted after register allocation.
inline constexpr llvm::StringLiteral NoSuspend{"bpf.capsule.nosuspend"};
inline constexpr llvm::StringLiteral NativeScalar{"bpf.native.scalar"};
inline constexpr llvm::StringLiteral NativeAlloca{"bpf.native.alloca"};

// Temporary allocation units: marker (with borrowed-context flag), the
// fiber-stack size, and the string param attributes naming the borrowed
// verifier context and the fiber-control argument.
inline constexpr llvm::StringLiteral AllocationUnit{"bpf.capsule.allocation.unit"};
inline constexpr llvm::StringLiteral StackSize{"bpf.capsule.stack.size"};
// Post-RA contract: the largest physical frame this allocation unit may
// retain after spill relocation.  It is derived from the actual machine call
// graph, not from the source-level trampoline shape or target kernel.
inline constexpr llvm::StringLiteral NativeStackBudget{"bpf.capsule.native.stack.budget"};
inline constexpr llvm::StringLiteral Borrowed{"bpf.capsule.borrowed"};
inline constexpr llvm::StringLiteral Control{"bpf.capsule.control"};
inline constexpr llvm::StringLiteral StackBacking{"bpf.capsule.stack.backing"};

// Temporary code-generation boundaries. Stackify emits independently
// allocatable step units; the late machine-module pass joins every Unit into
// its Root after register allocation and before BPF assembly/BTF emission.
// The sole operand names an output root. A root-owned dispatcher call may
// adapt argument signatures (scalar into borrowed-context today); its selected
// register moves remain in place when the terminal CALL is removed.
inline constexpr llvm::StringLiteral FlattenUnit{"bpf.capsule.flatten.unit"};
inline constexpr llvm::StringLiteral FlattenRouter{"bpf.capsule.flatten.router"};
inline constexpr llvm::StringLiteral FlattenRoot{"bpf.capsule.flatten.root"};
inline constexpr llvm::StringLiteral FlattenedUnits{"bpf.capsule.flattened.units"};
inline constexpr llvm::StringLiteral FreplaceRoots{"bpf.capsule.freplace.roots"};

// Stackify -> memory-pass handoff.
inline constexpr llvm::StringLiteral FiberStackSize{"bpf.fiber.stack.size"};
inline constexpr llvm::StringLiteral OutcomeStore{"bpf.capsule.outcome.store"};
inline constexpr llvm::StringLiteral SectionedBounded{"bpf.capsule.sectioned.bounded"};
inline constexpr llvm::StringLiteral Init{"bpf.capsule.init"};

} // namespace bpf::md

// Function classes. Declared in source with __BPF_CAPSULE_FN_CLASS /
// CAPSULE_NOSUSPEND annotations, or attached directly by the pass that
// generates a function; materialized once per module from
// llvm.global.annotations into string attributes keyed by the same text.
// Classification never reads symbol names - the runtime_symbols.h names
// are link-time contracts only.
namespace bpf::cls {
inline constexpr llvm::StringLiteral NoSuspend{"capsule.nosuspend"};
inline constexpr llvm::StringLiteral Trampoline{"capsule.trampoline"};
inline constexpr llvm::StringLiteral EntryGlue{"capsule.entry-glue"};
inline constexpr llvm::StringLiteral HeapAccessor{"capsule.heap-accessor"};
inline constexpr llvm::StringLiteral StackAccessor{"capsule.stack-accessor"};
} // namespace bpf::cls

namespace bpf {

// Transfer "capsule.*" function annotations into function attributes so
// every consumer queries one canonical carrier. Idempotent and O(1) after
// the first call (a module flag records completion).
void MaterializeFunctionClasses(llvm::Module& module);
bool HasFunctionClass(const llvm::Function& function, llvm::StringRef cls);

// An entry program owns an ELF program section. .ksyms marks kernel-symbol
// declarations, not entries.
inline bool IsEntryProgram(const llvm::Function& func) {
    return func.hasSection() && func.getSection() != ".ksyms";
}

// Domain metadata is established by bpf-capsule-domains.  Source entry
// programs and their ordinary callees are native; only the closure behind a
// capsule_call boundary carries the Capsule marker.
inline bool IsCapsuleFunction(const llvm::Function& func) {
    return func.getMetadata(md::Capsule) != nullptr;
}

inline bool IsNativeFunction(const llvm::Function& func) {
    return func.getMetadata(md::Native) != nullptr;
}

inline bool IsCapsuleGlobal(const llvm::GlobalVariable& global) {
    return global.getMetadata(md::Capsule) != nullptr;
}

inline bool IsNativeGlobal(const llvm::GlobalVariable& global) {
    return global.getMetadata(md::Native) != nullptr;
}

// Per-pass transformation statistics: stderr under -bpf-capsule-verbose,
// discarded otherwise. Error context and fatal diagnostics stay on errs()
// unconditionally.
bool verbose();
llvm::raw_ostream& stats();

// True when `control` exactly implements struct bpf_capsule_fiber_control from
// the private object ABI. Callers retain their own diagnostics because they
// discover the type through different runtime objects.
bool IsFiberControlLayout(const llvm::StructType* control);

// Hide a scalar's producer from LLVM without emitting a BPF instruction.
// This preserves an explicit verifier proof that later IR simplification
// would otherwise fold away.
llvm::Value* BuildVerifierOpaqueIdentity(llvm::IRBuilderBase& builder, llvm::Value* value, llvm::StringRef name = {});

// Address of the current Capsule fiber's terminal {status, code} pair (see
// the private object ABI): the fields are adjacent and 8-byte aligned, and the
// lowering publishes both with the single 64-bit store OutcomeValue()
// describes. Before stackification the managed form is an accessor marker;
// Stackify replaces it after regions have reached physical step functions.
// Native code has no implicit current fiber and may not publish through
// this interface.
llvm::Value* OutcomePointer(llvm::IRBuilderBase& builder, llvm::Function& owner);

// Replace `point` and the rest of its block with one encoded Capsule exit and
// a zero/void return. Outgoing PHI edges are removed as part of the rewrite.
// This is the one CFG/ABI implementation shared by source exits, traps, and
// the late raw-unreachable fallback.
void TerminateWithOutcome(llvm::Instruction& point, llvm::Value* word);

// The first trap/debugtrap in each block. Rewriting that call deletes the
// block suffix, so collecting later traps would leave stale instructions.
llvm::SmallVector<llvm::CallInst*, 4> FirstTrapCalls(llvm::Function& function);

// A pointer returned by a numbered BPF helper or pointer-returning kfunc is a
// verifier capability, not an address in Capsule's virtual memory. This test
// deliberately excludes ordinary and indirect Capsule calls: their pointer
// results are virtual addresses and must still pass through arena lowering.
bool IsVerifierCall(const llvm::CallBase& call);
bool IsVerifierPointerSource(const llvm::CallBase& call);

// Find SSA values which still carry native verifier pointer provenance. The
// closure crosses pointer arithmetic and the special ctx -> packet load, but
// not loads from helper-returned map/ring-buffer storage: data read through
// those pointers is an ordinary scalar unless the kernel assigns it a richer
// type through a dedicated operation.
void FindVerifierNativeValues(llvm::Function& func, llvm::SmallPtrSetImpl<llvm::Value*>& native);

// The one 64-bit little-endian store that fills the adjacent {status, code}
// pair: status = CAPSULE_EXITED in the low half, the signed code in the
// high half. Byte-identical to the runtime's two field stores.
inline uint64_t OutcomeValue(int32_t code) {
    return ((uint64_t)(int64_t)code << 32) | (uint64_t)CAPSULE_EXITED;
}

llvm::Value* BuildOutcomeValue(llvm::IRBuilderBase& builder, llvm::Value* code);

} // namespace bpf
