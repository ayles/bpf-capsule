// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

llvm::DIType* BtfGetInt(llvm::DIBuilder& builder, size_t sizeInBits, bool isSigned);

void BtfFunctionAddDebugInfo(llvm::DIBuilder& debugBuilder, llvm::Function& func, llvm::ArrayRef<llvm::Metadata*> paramTypes);

namespace bpf {

// Domain metadata is established by bpf-partition.  Source entry programs and
// their ordinary callees are native; only the closure behind a capsule_call
// boundary carries the Capsule marker.
inline bool IsCapsuleFunction(const llvm::Function& func) {
    return func.getMetadata("bpf.capsule") != nullptr;
}

inline bool IsNativeFunction(const llvm::Function& func) {
    return func.getMetadata("bpf.native") != nullptr;
}

inline bool IsCapsuleGlobal(const llvm::GlobalVariable& global) {
    return global.getMetadata("bpf.capsule") != nullptr;
}

inline bool IsNativeGlobal(const llvm::GlobalVariable& global) {
    return global.getMetadata("bpf.native") != nullptr;
}

// Per-pass transformation statistics: stderr under -bpf-capsule-verbose,
// discarded otherwise. Error context and fatal diagnostics stay on errs()
// unconditionally.
llvm::raw_ostream& stats();

// Address of the current Capsule fiber's exit word (encoded terminal tag +
// signed code; see bpf_capsule_abi.h). Before stackification the managed form
// is an accessor marker; Stackify replaces it after regions have reached
// physical step functions. Native compiler guards use fiber zero.
llvm::Value* ExitWordPointer(llvm::IRBuilderBase& builder, llvm::Function& owner);

// A pointer returned by a numbered BPF helper or pointer-returning kfunc is a
// verifier capability, not an address in Capsule's virtual memory. This test
// deliberately excludes ordinary and indirect Capsule calls: their pointer
// results are virtual addresses and must still pass through the memory tier.
bool IsVerifierCall(const llvm::CallBase& call);
bool IsVerifierPointerSource(const llvm::CallBase& call);

// Find SSA values which still carry native verifier pointer provenance. The
// closure crosses pointer arithmetic and the special ctx -> packet load, but
// not loads from helper-returned map/ring-buffer storage: data read through
// those pointers is an ordinary scalar unless the kernel assigns it a richer
// type through a dedicated operation.
void FindVerifierNativeValues(llvm::Function& func, llvm::SmallPtrSetImpl<llvm::Value*>& native);

} // namespace bpf

#include "bpf_capsule_abi.h"

namespace bpf {
// The encoded exit word for a framework code: ((int64_t)code << 32) | tag.
inline uint64_t ExitWordValue(int32_t code) {
    return ((uint64_t)(int64_t)code << 32) | (uint64_t)CAPSULE_EXITED;
}
} // namespace bpf
