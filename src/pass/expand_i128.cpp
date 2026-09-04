// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "expand_i128.h"

#include "common.h"
#include "target.h"
#include "runtime_symbols.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// The BPF backend legalizes i128 by splitting for every operation except
// mul, div and rem, which become libcalls (__multi3, __udivti3) the kernel
// cannot host. All of that arithmetic lives as C in the compiler runtime's
// int128.c (__bpf_mul128, __bpf_udiv128/__bpf_sdiv128 and friends, plus the
// 64-bit overflow-multiply helpers the backend would otherwise expand through
// the same libcall); this pass only decomposes each operation into i64 words
// and rewrites it as a call. The helpers are marked always_inline, so the
// post-link -O2 folds each one into its call site and a constant divisor
// still collapses the same way an inline IR expansion would.
struct ExpandI128Pass : public PassInfoMixin<ExpandI128Pass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        auto* i64 = IntegerType::getInt64Ty(module.getContext());
        auto* i128 = IntegerType::getInt128Ty(module.getContext());
        SmallVector<BinaryOperator*> work;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* bin = dyn_cast<BinaryOperator>(&inst);
                if (!bin || bin->getType() != i128) {
                    continue;
                }
                switch (bin->getOpcode()) {
                    case Instruction::Mul:
                    case Instruction::UDiv:
                    case Instruction::URem:
                    case Instruction::SDiv:
                    case Instruction::SRem:
                        work.push_back(bin);
                        break;
                    default:
                        break;
                }
            }
        }
        for (auto* bin : work) {
            IRBuilder<> b(bin);
            StringRef name;
            switch (bin->getOpcode()) {
                case Instruction::Mul:
                    name = bpf::sym::Mul128;
                    break;
                case Instruction::UDiv:
                    name = bpf::sym::UDiv128;
                    break;
                case Instruction::URem:
                    name = bpf::sym::URem128;
                    break;
                case Instruction::SDiv:
                    name = bpf::sym::SDiv128;
                    break;
                default:
                    name = bpf::sym::SRem128;
                    break;
            }
            Value* a = bin->getOperand(0);
            Value* d = bin->getOperand(1);
            Value* args[] = {
                b.CreateTrunc(a, i64),
                b.CreateTrunc(b.CreateLShr(a, 64), i64),
                b.CreateTrunc(d, i64),
                b.CreateTrunc(b.CreateLShr(d, 64), i64),
            };
            auto [lo, hi] = EmitHelperCall(module, b, name, args, bin);
            Value* outLo = b.CreateZExt(lo, i128);
            Value* outHi = b.CreateZExt(hi, i128);
            outHi = b.CreateShl(outHi, 64);
            Value* out = b.CreateOr(outLo, outHi);
            bin->replaceAllUsesWith(out);
            bin->eraseFromParent();
        }

        // The i64 overflow-multiply intrinsics expand to the same libcall
        // (the backend forms the 128-bit product to test the top half).
        SmallVector<CallInst*> overflowCalls;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* call = dyn_cast<CallInst>(&inst);
                if (call && (call->getIntrinsicID() == Intrinsic::umul_with_overflow || call->getIntrinsicID() == Intrinsic::smul_with_overflow) &&
                    call->getArgOperand(0)->getType() == i64) {
                    overflowCalls.push_back(call);
                }
            }
        }
        for (auto* call : overflowCalls) {
            IRBuilder<> b(call);
            StringRef name = call->getIntrinsicID() == Intrinsic::umul_with_overflow ? bpf::sym::UMul64Overflow : bpf::sym::SMul64Overflow;
            Value* args[] = {call->getArgOperand(0), call->getArgOperand(1)};
            auto [lo, hi] = EmitHelperCall(module, b, name, args, call);
            Value* pair = PoisonValue::get(call->getType());
            pair = b.CreateInsertValue(pair, lo, 0);
            pair = b.CreateInsertValue(pair, b.CreateICmpNE(hi, ConstantInt::get(i64, 0)), 1);
            call->replaceAllUsesWith(pair);
            call->eraseFromParent();
        }
        if (!work.empty() || !overflowCalls.empty()) {
            bpf::stats() << "bpf-expand-i128: " << work.size() << " i128 operations, " << overflowCalls.size() << " overflow operations expanded\n";
        }
        return work.empty() && overflowCalls.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }

    // Call an int128.c helper returning {i64, i64}, accepting either LLVM's
    // sret form or a natural aggregate return, and split the pair.
    std::pair<Value*, Value*> EmitHelperCall(Module& module, IRBuilder<>& b, StringRef name, ArrayRef<Value*> args, Instruction* site) {
        Function* helper = module.getFunction(name);
        if (!helper || helper->isDeclaration()) {
            report_fatal_error(Twine("bpf-expand-i128: ") + name +
                " needed but the source defining it (bpf_capsule.c for 64-bit overflow multiply, "
                "compiler-runtime int128.c for i128 arithmetic) is not linked in");
        }
        Value* pair = nullptr;
        if (helper->arg_size() > args.size() && helper->getArg(0)->hasStructRetAttr()) {
            Type* pairType = helper->getParamStructRetType(0);
            IRBuilder<> entry(&*site->getFunction()->getEntryBlock().getFirstInsertionPt());
            AllocaInst* result = entry.CreateAlloca(pairType, nullptr, "i128.result");
            if (auto alignment = helper->getParamAlign(0)) {
                result->setAlignment(*alignment);
            }
            SmallVector<Value*> helperArgs{result};
            helperArgs.append(args.begin(), args.end());
            CallInst* call = b.CreateCall(helper->getFunctionType(), helper, helperArgs);
            call->setCallingConv(helper->getCallingConv());
            call->setAttributes(helper->getAttributes());
            pair = b.CreateLoad(pairType, result);
        } else {
            pair = b.CreateCall(helper, args);
        }
        return {b.CreateExtractValue(pair, 0), b.CreateExtractValue(pair, 1)};
    }
};

} // namespace

bool RegisterExpandI128Pass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-expand-i128") {
        return false;
    }
    manager.addPass(ExpandI128Pass());
    return true;
}
