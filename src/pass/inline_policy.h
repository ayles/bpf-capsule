// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>

namespace bpf {

// Distinguishes the temporary pre-O2 inlining veto below from a source-level
// noinline contract. Stackify may reconsider only this compiler-owned veto
// after optimization has made a function compact and single-use.
inline constexpr llvm::StringLiteral InlinePolicyVetoAttr = "bpf.capsule.inline-policy-veto";

// The source-IR ceiling below which a loop-free helper counts as compact.
// Both the pre-O2 inlining veto and Stackify's size-neutral single-use pass
// use it consistently; bpf-capsule-ld sets it from --inline-limit.
unsigned CompactInlineIrLimit();

} // namespace bpf

bool RegisterInlinePolicyPass(llvm::StringRef name, llvm::FunctionPassManager& manager);
