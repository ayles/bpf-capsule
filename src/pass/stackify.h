// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

// Moves the call stack of "managed" functions into an explicit software stack
// so the kernel-visible BPF call graph never exceeds MAX_CALL_FRAMES.
class Stackify : public llvm::PassInfoMixin<Stackify> {
public:
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& am);
};
