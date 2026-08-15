// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/IR/PassManager.h>

// Whole-program devariadicization: BPF has no variadic ABI, so call sites
// pack variadic arguments into 8-byte slots and callees walk the pack.
struct ExpandVarargsPass : llvm::PassInfoMixin<ExpandVarargsPass> {
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam);
};
