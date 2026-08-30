// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "split_shift63.h"

#include "common.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// ---------------------------------------------------------------------------
// bpf-split-shift63: the arm64 JIT cannot encode a 64-bit right shift by 63
// ("invalid immr encoding 63"). When the JIT bails the program falls back to
// the interpreter, and interpreted programs are not allowed to call kfuncs, so
// a single instruction takes the whole load down. Split it into two shifts.
// Must run after all optimization, or InstCombine folds it straight back.
// ---------------------------------------------------------------------------

class SplitShift63Pass : public PassInfoMixin<SplitShift63Pass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        SmallVector<BinaryOperator*> work;
        for (auto&& inst : instructions(func)) {
            auto* op = dyn_cast<BinaryOperator>(&inst);
            if (!op || (op->getOpcode() != Instruction::AShr && op->getOpcode() != Instruction::LShr)) {
                continue;
            }
            auto* amount = dyn_cast<ConstantInt>(op->getOperand(1));
            if (amount && amount->getZExtValue() == 63 && op->getType()->isIntegerTy(64)) {
                work.push_back(op);
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        for (auto* op : work) {
            IRBuilder<> b(op);
            Type* type = op->getType();
            Value* first = b.CreateBinOp(op->getOpcode(), op->getOperand(0), ConstantInt::get(type, 32));
            Value* second = b.CreateBinOp(op->getOpcode(), first, ConstantInt::get(type, 31));
            if (auto* inst = dyn_cast<Instruction>(second)) {
                inst->setDebugLoc(op->getDebugLoc());
            }
            if (auto* inst = dyn_cast<Instruction>(first)) {
                inst->setDebugLoc(op->getDebugLoc());
            }
            op->replaceAllUsesWith(second);
            op->eraseFromParent();
        }
        bpf::stats() << "bpf-split-shift63: " << work.size() << " shifts split in " << func.getName() << "\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterSplitShift63Pass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-split-shift63") {
        return false;
    }
    manager.addPass(SplitShift63Pass());
    return true;
}
