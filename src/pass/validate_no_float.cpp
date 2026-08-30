// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-validate-no-float: pipeline invariant tripwire. bpf-soft-float owns the
// complete scalar f32/f64 lowering contract and runs before O2, and O2 cannot
// conjure floating point into float-free code — so after O2 no FP type may
// exist anywhere. A survivor is a compiler bug; naming it here turns a deep
// instruction-selection crash into a source-located error.
#include "validate_no_float.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

bool UsesFloatingPoint(Function& func) {
    auto isFp = [](Type* type) { return type->isFPOrFPVectorTy(); };
    if (isFp(func.getReturnType())) {
        return true;
    }
    for (auto&& arg : func.args()) {
        if (isFp(arg.getType())) {
            return true;
        }
    }
    for (auto&& inst : instructions(func)) {
        if (isFp(inst.getType())) {
            return true;
        }
        for (auto&& op : inst.operands()) {
            if (isFp(op->getType())) {
                return true;
            }
        }
    }
    return false;
}

struct ValidateNoFloatPass : public PassInfoMixin<ValidateNoFloatPass> {
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        if (UsesFloatingPoint(func)) {
            func.getContext().emitError(Twine("bpf-validate-no-float: floating point survived software lowering in ") + func.getName());
        }
        return PreservedAnalyses::all();
    }
};

} // namespace

bool RegisterValidateNoFloatPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-validate-no-float") {
        return false;
    }
    manager.addPass(ValidateNoFloatPass());
    return true;
}
