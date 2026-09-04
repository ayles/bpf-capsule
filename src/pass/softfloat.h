// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>

#include <string>
#include <vector>

namespace llvm {
class Module;
} // namespace llvm

bool RegisterSoftFloatPass(llvm::StringRef name, llvm::ModulePassManager& manager);

// libm routines that bpf-soft-float will call when it lowers intrinsics.
// Archive linking needs these implicit dependencies as well as the module's
// explicit undefined symbols.
std::vector<std::string> RequiredSoftFloatLibcalls(const llvm::Module& module);

// Remove floating point from the module: every float value becomes an
// integer holding its bit pattern, and every float operation becomes a call
// to an integer routine. BPF has no floating-point registers and its backend
// refuses to emit libcalls, so this has to happen here rather than in codegen.
struct SoftFloatPass : llvm::PassInfoMixin<SoftFloatPass> {
    llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& mam);
};
