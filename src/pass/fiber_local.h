// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

bool RegisterFiberLocalPass(llvm::StringRef name, llvm::ModulePassManager& manager);

// Gives every thread-local variable one instance per fiber. The BPF target
// has no thread-local storage: bpf-capsule-cc marks C `_Thread_local` and
// `__thread` definitions with an annotation, other frontends emit genuine
// thread_local globals, and this pass gathers both into one block indexed by
// the current fiber.
struct FiberLocalPass : llvm::PassInfoMixin<FiberLocalPass> {
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& am);
};
