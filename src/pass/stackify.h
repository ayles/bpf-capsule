// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

enum class StackifyMode {
    Arena,
    Fixed,
    FixedV3,
    Direct,
};

// Moves the call stack of "managed" functions into an explicit software stack
// so the kernel-visible BPF call graph never exceeds MAX_CALL_FRAMES.
class Stackify : public llvm::PassInfoMixin<Stackify> {
public:
    explicit Stackify(StackifyMode mode = StackifyMode::Arena)
        : FixedMemory_(mode == StackifyMode::Fixed || mode == StackifyMode::FixedV3)
        , DirectDispatch_(mode == StackifyMode::Direct)
        , BoundedDispatch_(mode == StackifyMode::FixedV3) {
    }

    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& am);

private:
    bool FixedMemory_;
    bool DirectDispatch_;
    bool BoundedDispatch_;
};

bool RegisterStackifyPass(llvm::StringRef name, llvm::ModulePassManager& manager);
