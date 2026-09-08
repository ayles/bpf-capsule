// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "expand_i128.h"

#include "common.h"
#include "runtime_symbols.h"

#include <llvm/ADT/StringSet.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>

using namespace llvm;

namespace {

StringRef arithmeticLibcall(const Instruction& instruction) {
    if (instruction.getType()->isIntegerTy(128)) {
        switch (instruction.getOpcode()) {
            case Instruction::Mul:
                return bpf::sym::Mul128;
            case Instruction::UDiv:
                return bpf::sym::UDiv128;
            case Instruction::URem:
                return bpf::sym::URem128;
            case Instruction::SDiv:
                return bpf::sym::SDiv128;
            case Instruction::SRem:
                return bpf::sym::SRem128;
            default:
                break;
        }
    }
    if (const auto* intrinsic = dyn_cast<IntrinsicInst>(&instruction)) {
        switch (intrinsic->getIntrinsicID()) {
            case Intrinsic::umul_with_overflow:
                if (intrinsic->getArgOperand(0)->getType()->isIntegerTy(64)) {
                    return bpf::sym::Mul128;
                }
                break;
            case Intrinsic::smul_with_overflow:
                if (intrinsic->getArgOperand(0)->getType()->isIntegerTy(64)) {
                    return bpf::sym::SMul64Overflow;
                }
                break;
            default:
                break;
        }
    }
    return {};
}

// BPF legalizes wide add/shift/compare in registers, but mul/div/rem need
// compiler-rt. Keep its ordinary i128 signatures: managed calls already pass
// arbitrary-width arguments and results through the fiber frame. There is no
// native two-register return ABI or Capsule-specific arithmetic wrapper.
struct ExpandI128Pass : public PassInfoMixin<ExpandI128Pass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        SmallVector<Instruction*> work;
        for (Function& function : module) {
            for (Instruction& instruction : instructions(function)) {
                if (!arithmeticLibcall(instruction).empty()) {
                    work.push_back(&instruction);
                }
            }
        }
        for (Instruction* instruction : work) {
            IRBuilder<> b(instruction);
            StringRef name = arithmeticLibcall(*instruction);
            auto* i128 = b.getInt128Ty();
            Value* a = instruction->getOperand(0);
            Value* d = instruction->getOperand(1);
            Value* result;
            if (isa<BinaryOperator>(instruction)) {
                auto helper = module.getOrInsertFunction(name, i128, i128, i128);
                result = b.CreateCall(helper, {a, d});
            } else {
                Value* product;
                Value* overflow;
                if (cast<IntrinsicInst>(instruction)->getIntrinsicID() == Intrinsic::umul_with_overflow) {
                    auto helper = module.getOrInsertFunction(name, i128, i128, i128);
                    Value* wide = b.CreateCall(helper, {b.CreateZExt(a, i128), b.CreateZExt(d, i128)});
                    product = b.CreateTrunc(wide, b.getInt64Ty());
                    overflow = b.CreateICmpNE(b.CreateLShr(wide, 64), ConstantInt::get(i128, 0));
                } else {
                    IRBuilder<> entry(&*instruction->getFunction()->getEntryBlock().getFirstInsertionPt());
                    Value* slot = entry.CreateAlloca(b.getInt32Ty(), nullptr, "multiply.overflow");
                    auto helper = module.getOrInsertFunction(name, b.getInt64Ty(), b.getInt64Ty(), b.getInt64Ty(), b.getPtrTy());
                    product = b.CreateCall(helper, {a, d, slot});
                    overflow = b.CreateICmpNE(b.CreateLoad(b.getInt32Ty(), slot), b.getInt32(0));
                }
                result = b.CreateInsertValue(PoisonValue::get(instruction->getType()), product, 0);
                result = b.CreateInsertValue(result, overflow, 1);
            }
            instruction->replaceAllUsesWith(result);
            instruction->eraseFromParent();
        }
        if (!work.empty()) {
            bpf::stats() << "bpf-expand-i128: " << work.size() << " arithmetic operations expanded\n";
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

} // namespace

std::vector<std::string> RequiredIntegerLibcalls(const Module& module) {
    std::vector<std::string> result;
    StringSet<> seen;
    for (const Function& function : module) {
        for (const Instruction& instruction : instructions(function)) {
            StringRef name = arithmeticLibcall(instruction);
            if (name.empty()) {
                continue;
            }
            const GlobalValue* implementation = module.getNamedValue(name);
            if ((!implementation || implementation->isDeclarationForLinker()) && seen.insert(name).second) {
                result.push_back(name.str());
            }
        }
    }
    return result;
}

bool RegisterExpandI128Pass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-expand-i128") {
        return false;
    }
    manager.addPass(ExpandI128Pass());
    return true;
}
