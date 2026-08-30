// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "lower_sdiv.h"

#include "common.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

using namespace llvm;

namespace {

// CPU v4 added native signed div/mod. On v3, express them with unsigned
// operations before O2. |x| is `(x ^ sign) - sign`; quotient sign is a^b,
// while remainder sign is a. Keeping this as IR avoids a runtime ABI helper
// and lets the ordinary optimizer fold constant divisors normally.
class LowerSDivPass : public PassInfoMixin<LowerSDivPass> {
public:
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        SmallVector<BinaryOperator*> work;
        for (Function& function : module) {
            for (Instruction& instruction : instructions(function)) {
                auto* operation = dyn_cast<BinaryOperator>(&instruction);
                if (operation && (operation->getOpcode() == Instruction::SDiv || operation->getOpcode() == Instruction::SRem)) {
                    work.push_back(operation);
                }
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        for (BinaryOperator* operation : work) {
            auto* sourceType = dyn_cast<IntegerType>(operation->getType());
            if (!sourceType || sourceType->getBitWidth() > 64) {
                module.getContext().emitError(operation, "bpf-lower-sdiv: expected a scalar integer no wider than 64 bits");
                continue;
            }
            unsigned bits = sourceType->getBitWidth() <= 32 ? 32 : 64;
            auto* type = IntegerType::get(module.getContext(), bits);
            IRBuilder<> builder(operation);
            builder.SetCurrentDebugLocation(operation->getDebugLoc());
            Value* lhs = builder.CreateSExtOrTrunc(operation->getOperand(0), type);
            Value* rhs = builder.CreateSExtOrTrunc(operation->getOperand(1), type);
            Value* lhsSign = builder.CreateAShr(lhs, ConstantInt::get(type, bits - 1));
            Value* rhsSign = builder.CreateAShr(rhs, ConstantInt::get(type, bits - 1));
            Value* lhsMagnitude = builder.CreateSub(builder.CreateXor(lhs, lhsSign), lhsSign);
            Value* rhsMagnitude = builder.CreateSub(builder.CreateXor(rhs, rhsSign), rhsSign);
            Value* magnitude =
                operation->getOpcode() == Instruction::SDiv ? builder.CreateUDiv(lhsMagnitude, rhsMagnitude) : builder.CreateURem(lhsMagnitude, rhsMagnitude);
            Value* sign = operation->getOpcode() == Instruction::SDiv ? builder.CreateXor(lhsSign, rhsSign) : lhsSign;
            Value* result = builder.CreateSub(builder.CreateXor(magnitude, sign), sign);
            operation->replaceAllUsesWith(builder.CreateTruncOrBitCast(result, sourceType));
            operation->eraseFromParent();
        }
        bpf::stats() << "bpf-lower-sdiv: " << work.size() << " signed division or remainder operations lowered\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterLowerSDivPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-lower-sdiv") {
        return false;
    }
    manager.addPass(LowerSDivPass());
    return true;
}
