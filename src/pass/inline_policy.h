// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>

namespace bpf {

// Distinguishes the temporary pre-O2 inlining veto below from a source-level
// noinline contract. Stackify may reconsider only this compiler-owned veto
// after optimization has made a function compact and single-use.
inline constexpr llvm::StringLiteral InlinePolicyVetoAttr = "bpf.capsule.inline-policy-veto";

// One managed call/return executes roughly 85--90 generated instructions.
// Both the pre-O2 inlining veto and Stackify's size-neutral single-use pass
// use this nearby source-IR ceiling to define a compact helper consistently.
inline constexpr unsigned CompactInlineIrLimit = 100;

} // namespace bpf

bool RegisterInlinePolicyPass(llvm::StringRef name, llvm::FunctionPassManager& manager);
