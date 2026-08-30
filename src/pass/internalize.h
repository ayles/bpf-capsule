// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

bool RegisterInternalizePass(llvm::StringRef name, llvm::ModulePassManager& manager);

// Closes the linked freestanding image: everything that is not load-time ABI
// becomes internal, so the GlobalDCE stage that follows can drop it.
struct InternalizePass : llvm::PassInfoMixin<InternalizePass> {
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& am);
};
