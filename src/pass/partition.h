// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

// Finds explicit native -> Capsule boundaries, assigns every reachable
// definition to exactly one domain, and rejects accidental sharing.
class CapsulePartitionPass : public llvm::PassInfoMixin<CapsulePartitionPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& am);
};
