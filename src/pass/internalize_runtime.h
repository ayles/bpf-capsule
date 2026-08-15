// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/IR/PassManager.h>

// Internalize the linked runtime after generic optimization; GlobalDCE follows.
struct InternalizeRuntimePass : llvm::PassInfoMixin<InternalizeRuntimePass> {
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam);
};
