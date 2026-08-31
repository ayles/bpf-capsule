// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "expand_mem.h"

#include "common.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include <vector>

using namespace llvm;

namespace {

// ---------------------------------------------------------------------------
// bpf-expand-mem: lower memcpy/memmove/memset intrinsics to plain load/store
// loops (i64 chunks + byte tail) so memory lowering sees ordinary accesses and
// stackification can classify or virtualize the loops. Runs before both.
// ---------------------------------------------------------------------------

// Emits one copy loop over [begin, end) with the given element type, in
// ascending or descending address order. Insertion continues after the loop.
void EmitCopyRange(IRBuilder<>& b, Type* elemType, Value* dst, Value* src, Value* begin, Value* end, uint64_t step, bool isVolatile, bool descending) {
    LLVMContext& ctx = b.getContext();
    Function* func = b.GetInsertBlock()->getParent();
    auto* i64 = Type::getInt64Ty(ctx);

    BasicBlock* pre = b.GetInsertBlock();
    BasicBlock* after = pre->splitBasicBlock(b.GetInsertPoint(), "copy.after");
    pre->getTerminator()->eraseFromParent();

    BasicBlock* cond = BasicBlock::Create(ctx, "copy.cond", func, after);
    BasicBlock* body = BasicBlock::Create(ctx, "copy.body", func, after);

    b.SetInsertPoint(pre);
    b.CreateBr(cond);

    b.SetInsertPoint(cond);
    auto* i = b.CreatePHI(i64, 2, "copy.i");
    Value* cmp = descending ? b.CreateICmpUGT(i, begin) : b.CreateICmpULT(i, end);
    b.CreateCondBr(cmp, body, after);

    b.SetInsertPoint(body);
    Value* off = descending ? b.CreateSub(i, ConstantInt::get(i64, step)) : static_cast<Value*>(i);
    auto* ld = b.CreateAlignedLoad(elemType, b.CreatePtrAdd(src, off), MaybeAlign(1), isVolatile);
    b.CreateAlignedStore(ld, b.CreatePtrAdd(dst, off), MaybeAlign(1), isVolatile);
    Value* next = descending ? off : b.CreateAdd(i, ConstantInt::get(i64, step));
    b.CreateBr(cond);
    i->addIncoming(descending ? end : begin, pre);
    i->addIncoming(next, body);

    b.SetInsertPoint(after, after->begin());
}

void EmitCopy(IRBuilder<>& b, Value* dst, Value* src, Value* len, bool isVolatile, bool backward) {
    LLVMContext& ctx = b.getContext();
    auto* i64 = Type::getInt64Ty(ctx);
    auto* i8 = Type::getInt8Ty(ctx);

    auto* wordsEnd = b.CreateMul(b.CreateUDiv(len, ConstantInt::get(i64, 8)), ConstantInt::get(i64, 8));
    auto* zero = ConstantInt::get(i64, 0);

    if (backward) {
        // Highest addresses first: byte tail [wordsEnd, len) desc, then words desc.
        EmitCopyRange(b, i8, dst, src, wordsEnd, len, 1, isVolatile, /*descending=*/true);
        EmitCopyRange(b, i64, dst, src, zero, wordsEnd, 8, isVolatile, /*descending=*/true);
    } else {
        EmitCopyRange(b, i64, dst, src, zero, wordsEnd, 8, isVolatile, /*descending=*/false);
        EmitCopyRange(b, i8, dst, src, wordsEnd, len, 1, isVolatile, /*descending=*/false);
    }
}

// The memset twin of EmitCopyRange: one store loop over [begin, end).
void EmitSetRange(IRBuilder<>& b, Value* dst, Value* value, Value* begin, Value* end, uint64_t step, bool isVolatile) {
    LLVMContext& ctx = b.getContext();
    Function* func = b.GetInsertBlock()->getParent();
    auto* i64 = Type::getInt64Ty(ctx);

    BasicBlock* pre = b.GetInsertBlock();
    BasicBlock* after = pre->splitBasicBlock(b.GetInsertPoint(), "set.after");
    pre->getTerminator()->eraseFromParent();

    BasicBlock* cond = BasicBlock::Create(ctx, "set.cond", func, after);
    BasicBlock* body = BasicBlock::Create(ctx, "set.body", func, after);

    b.SetInsertPoint(pre);
    b.CreateBr(cond);

    b.SetInsertPoint(cond);
    auto* i = b.CreatePHI(i64, 2, "set.i");
    b.CreateCondBr(b.CreateICmpULT(i, end), body, after);

    b.SetInsertPoint(body);
    b.CreateAlignedStore(value, b.CreatePtrAdd(dst, i), MaybeAlign(1), isVolatile);
    auto* next = b.CreateAdd(i, ConstantInt::get(i64, step));
    b.CreateBr(cond);
    i->addIncoming(begin, pre);
    i->addIncoming(next, body);

    b.SetInsertPoint(after, after->begin());
}

void EmitSet(IRBuilder<>& b, Value* dst, Value* value, Value* length, bool isVolatile) {
    auto* i64 = Type::getInt64Ty(b.getContext());
    auto* byte = b.CreateZExtOrTrunc(value, Type::getInt8Ty(b.getContext()));
    auto* word = b.CreateMul(b.CreateZExt(byte, i64), ConstantInt::get(i64, 0x0101010101010101ull));
    auto* wordsEnd = b.CreateMul(b.CreateUDiv(length, ConstantInt::get(i64, 8)), ConstantInt::get(i64, 8));
    EmitSetRange(b, dst, word, ConstantInt::get(i64, 0), wordsEnd, 8, isVolatile);
    EmitSetRange(b, dst, byte, wordsEnd, length, 1, isVolatile);
}

class ExpandMemPass : public PassInfoMixin<ExpandMemPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        std::vector<Instruction*> candidates;
        for (auto&& inst : instructions(func)) {
            if (isa<MemCpyInst>(&inst) || isa<MemMoveInst>(&inst) || isa<MemSetInst>(&inst)) {
                candidates.push_back(&inst);
                continue;
            }

            // Freestanding runtimes commonly provide real memcpy/memmove/memset
            // definitions, so Clang deliberately leaves ordinary calls
            // instead of intrinsics.  A pointer into a sectioned BPF map must
            // not cross a managed suspension: ptrtoint emits no instruction
            // and therefore does not erase the verifier's pointer type, while
            // storing it in the software frame would leak a kernel pointer.
            // Expand only the call sites that actually touch verifier-native
            // storage.  Other sites keep the shared out-of-line routine and
            // its code-size benefit.
            auto* call = dyn_cast<CallInst>(&inst);
            Function* callee = call ? call->getCalledFunction() : nullptr;
            if (!callee || (callee->getName() != "memcpy" && callee->getName() != "memmove" && callee->getName() != "memset")) {
                continue;
            }
            unsigned pointerArgs = callee->getName() == "memset" ? 1 : 2;
            if (call->arg_size() < 3) {
                continue;
            }
            bool nativeMemory = false;
            for (unsigned i = 0; i < pointerArgs; i++) {
                Value* base = getUnderlyingObject(call->getArgOperand(i));
                auto* global = dyn_cast<GlobalVariable>(base);
                nativeMemory |= global && global->hasSection();
            }
            if (nativeMemory) {
                candidates.push_back(call);
            }
        }
        if (candidates.empty()) {
            return PreservedAnalyses::all();
        }

        LLVMContext& ctx = func.getContext();
        auto* i64 = Type::getInt64Ty(ctx);
        unsigned outlined = 0;

        // An intrinsic site expands inline only when it must (verifier-native
        // memory, volatile) or when it is cheap (small constant length whose
        // exact-trip loops stackify keeps native).  Everything else calls the
        // shared out-of-line driver, which walks the length through bounded
        // nosuspend chunk kernels the verifier checks exactly once — inline
        // loops at every site were 72% of SQLite's object and pushed it past
        // the one-million-instruction verifier budget.
        constexpr uint64_t InlineExpansionLimit = 256;
        auto outlineDriver = [&](Instruction* inst) -> Function* {
            auto* mi = dyn_cast<MemIntrinsic>(inst);
            if (!mi || mi->isVolatile()) {
                return nullptr;
            }
            if (auto* len = dyn_cast<ConstantInt>(mi->getLength()); len && len->getZExtValue() <= InlineExpansionLimit) {
                return nullptr;
            }
            unsigned pointerArgs = isa<MemTransferInst>(mi) ? 2u : 1u;
            for (unsigned i = 0; i < pointerArgs; i++) {
                Value* operand = mi->getArgOperand(i);
                if (operand->getType()->getPointerAddressSpace() != 0) {
                    return nullptr;
                }
                auto* global = dyn_cast<GlobalVariable>(getUnderlyingObject(operand));
                if (global && global->hasSection()) {
                    return nullptr;
                }
            }
            const char* name = isa<MemSetInst>(mi) ? "memset" : isa<MemMoveInst>(mi) ? "memmove" : "memcpy";
            Function* driver = func.getParent()->getFunction(name);
            return driver && !driver->isDeclaration() ? driver : nullptr;
        };

        for (auto* inst : candidates) {
            IRBuilder<> b(inst);
            if (Function* driver = outlineDriver(inst)) {
                auto* mi = cast<MemIntrinsic>(inst);
                Value* length = b.CreateZExtOrTrunc(mi->getLength(), i64);
                CallInst* replacement = nullptr;
                if (auto* transfer = dyn_cast<MemTransferInst>(mi)) {
                    replacement = b.CreateCall(driver, {transfer->getRawDest(), transfer->getRawSource(), length});
                } else {
                    auto* set = cast<MemSetInst>(mi);
                    Value* value = b.CreateZExt(set->getValue(), Type::getInt32Ty(ctx));
                    replacement = b.CreateCall(driver, {set->getRawDest(), value, length});
                }
                replacement->setDebugLoc(inst->getDebugLoc());
                inst->eraseFromParent();
                ++outlined;
                continue;
            }
            if (auto* mt = dyn_cast<MemTransferInst>(inst)) {
                Value* len = b.CreateZExtOrTrunc(mt->getLength(), i64);
                if (isa<MemMoveInst>(mt)) {
                    auto* dstInt = b.CreatePtrToInt(mt->getRawDest(), i64);
                    auto* srcInt = b.CreatePtrToInt(mt->getRawSource(), i64);
                    auto* isBackward = b.CreateICmpUGT(dstInt, srcInt);
                    Instruction* thenTerm = nullptr;
                    Instruction* elseTerm = nullptr;
                    SplitBlockAndInsertIfThenElse(isBackward, inst->getIterator(), &thenTerm, &elseTerm);
                    IRBuilder<> bt(thenTerm);
                    EmitCopy(bt, mt->getRawDest(), mt->getRawSource(), len, mt->isVolatile(), /*backward=*/true);
                    IRBuilder<> be(elseTerm);
                    EmitCopy(be, mt->getRawDest(), mt->getRawSource(), len, mt->isVolatile(), /*backward=*/false);
                } else {
                    EmitCopy(b, mt->getRawDest(), mt->getRawSource(), len, mt->isVolatile(), /*backward=*/false);
                }
            } else if (auto* ms = dyn_cast<MemSetInst>(inst)) {
                Value* len = b.CreateZExtOrTrunc(ms->getLength(), i64);
                EmitSet(b, ms->getRawDest(), ms->getValue(), len, ms->isVolatile());
            } else if (auto* call = dyn_cast<CallInst>(inst)) {
                Function* callee = call->getCalledFunction();
                Value* dst = call->getArgOperand(0);
                if (!call->getType()->isVoidTy()) {
                    call->replaceAllUsesWith(dst);
                }
                if (callee->getName() == "memcpy") {
                    Value* len = b.CreateZExtOrTrunc(call->getArgOperand(2), i64);
                    EmitCopy(b, dst, call->getArgOperand(1), len,
                        /*isVolatile=*/false, /*backward=*/false);
                } else if (callee->getName() == "memmove") {
                    Value* src = call->getArgOperand(1);
                    Value* len = b.CreateZExtOrTrunc(call->getArgOperand(2), i64);
                    Value* dstAddress = b.CreatePtrToInt(dst, i64);
                    Value* srcAddress = b.CreatePtrToInt(src, i64);
                    auto* isBackward = b.CreateICmpUGT(dstAddress, srcAddress);
                    Instruction* thenTerm = nullptr;
                    Instruction* elseTerm = nullptr;
                    SplitBlockAndInsertIfThenElse(isBackward, inst->getIterator(), &thenTerm, &elseTerm);
                    IRBuilder<> backward(thenTerm);
                    EmitCopy(backward, dst, src, len, /*isVolatile=*/false, /*backward=*/true);
                    IRBuilder<> forward(elseTerm);
                    EmitCopy(forward, dst, src, len, /*isVolatile=*/false, /*backward=*/false);
                } else {
                    Value* len = b.CreateZExtOrTrunc(call->getArgOperand(2), i64);
                    EmitSet(b, dst, call->getArgOperand(1), len, /*isVolatile=*/false);
                }
            }
            inst->eraseFromParent();
        }

        bpf::stats() << "bpf-expand-mem: " << candidates.size() - outlined << " sites expanded, " << outlined << " sites outlined\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterExpandMemPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-expand-mem") {
        return false;
    }
    manager.addPass(ExpandMemPass());
    return true;
}
