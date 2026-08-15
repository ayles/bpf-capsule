// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "common.h"
#include "memory.h"
#include "partition.h"

#include "stackify.h"
#include "softfloat.h"
#include "internalize_runtime.h"
#include "bpf_capsule_abi.h"
#include "target.h"
#include "varargs.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/ADT/MapVector.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/ReplaceConstant.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Plugins/PassPlugin.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/Scalar/InferAddressSpaces.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <unordered_map>

using namespace llvm;

namespace {

// This order is the compiler pipeline ABI. Keep it beside the pass
// implementations rather than exposing a replaceable CMake string: the two
// partition passes bracket generic optimization, and the second i128 pass
// catches operations O2 can introduce.
constexpr StringLiteral CapsulePipeline = "bpf-expand-varargs,bpf-expand-sret,bpf-partition,"
                                          "function(bpf-lower-atomics),bpf-expand-i128,bpf-soft-float,"
                                          "bpf-no-inline,bpf-lower-sdiv,default<O2>,bpf-expand-i128,"
                                          "bpf-internalize-runtime,globaldce,function(bpf-expand-mem),function(bpf-bound-vla),"
                                          "function(fix-irreducible),bpf-partition,bpf-stackify,"
                                          "function(early-cse,gvn,adce),function(fix-irreducible),"
                                          "function(bpf-define-undef),function(bpf-scalarize-agg),bpf-memory,"
                                          "function(bpf-infer-as),function(bpf-lower-arena-sext),"
                                          "function(bpf-finalize-atomic-load-store),function(bpf-split-shift63),"
                                          "bpf-no-jump-tables,bpf-sanitize-btf";

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

class ExpandMemPass : public PassInfoMixin<ExpandMemPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        std::vector<Instruction*> candidates;
        for (auto&& inst : instructions(func)) {
            if (isa<MemCpyInst>(&inst) || isa<MemMoveInst>(&inst) || isa<MemSetInst>(&inst)) {
                candidates.push_back(&inst);
                continue;
            }

            // Freestanding runtimes commonly provide real memcpy/memset
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
            if (!callee || (callee->getName() != "memcpy" && callee->getName() != "memset")) {
                continue;
            }
            unsigned pointerArgs = callee->getName() == "memcpy" ? 2 : 1;
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
        auto* i8 = Type::getInt8Ty(ctx);

        for (auto* inst : candidates) {
            IRBuilder<> b(inst);
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
                Value* byte = b.CreateZExtOrTrunc(ms->getValue(), i8);
                Value* word = b.CreateMul(b.CreateZExt(byte, i64), ConstantInt::get(i64, 0x0101010101010101ull));
                auto* wordsEnd = b.CreateMul(b.CreateUDiv(len, ConstantInt::get(i64, 8)), ConstantInt::get(i64, 8));

                EmitSetRange(b, ms->getRawDest(), word, ConstantInt::get(i64, 0), wordsEnd, 8, ms->isVolatile());
                EmitSetRange(b, ms->getRawDest(), byte, wordsEnd, len, 1, ms->isVolatile());
            } else if (auto* call = dyn_cast<CallInst>(inst)) {
                Function* callee = call->getCalledFunction();
                Value* dst = call->getArgOperand(0);
                if (!call->getType()->isVoidTy()) {
                    call->replaceAllUsesWith(dst);
                }
                if (callee->getName() == "memcpy") {
                    Value* len = b.CreateZExtOrTrunc(call->getArgOperand(2), i64);
                    EmitCopy(
                        b, dst, call->getArgOperand(1), len,
                        /*isVolatile=*/false, /*backward=*/false
                    );
                } else {
                    Value* len = b.CreateZExtOrTrunc(call->getArgOperand(2), i64);
                    Value* byte = b.CreateZExtOrTrunc(call->getArgOperand(1), i8);
                    Value* word = b.CreateMul(b.CreateZExt(byte, i64), ConstantInt::get(i64, 0x0101010101010101ull));
                    auto* wordsEnd = b.CreateMul(b.CreateUDiv(len, ConstantInt::get(i64, 8)), ConstantInt::get(i64, 8));
                    EmitSetRange(b, dst, word, ConstantInt::get(i64, 0), wordsEnd, 8, /*isVolatile=*/false);
                    EmitSetRange(
                        b, dst, byte, wordsEnd, len, 1,
                        /*isVolatile=*/false
                    );
                }
            }
            inst->eraseFromParent();
        }

        return PreservedAnalyses::none();
    }

private:
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
};

// ---------------------------------------------------------------------------
// bpf-no-inline: the architecture wants many small functions — one 512-byte
// frame each, bounded spills — so inlining is opt-in via alwaysinline only.
// ---------------------------------------------------------------------------

class NoInlinePass : public PassInfoMixin<NoInlinePass> {
public:
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        for (auto&& func : module) {
            if (func.isDeclaration()) {
                continue;
            }
            // Capsule links a freestanding program image. Calls named like C
            // library routines resolve to definitions in that image; they are
            // not host libcalls. Rust bitcode does not carry Clang's
            // -ffreestanding attribute, so without this module-wide contract
            // LLVM can rewrite the linked calloc definition back into an
            // unresolved @calloc declaration during -O2. Mark every caller
            // consistently instead of disabling GlobalOpt or other generic
            // optimizers for the whole pipeline.
            func.addFnAttr("no-builtins");
            // The heap accessors must stay inlinable: each one is a memory
            // access, and a call at every access clobbers the caller-saved
            // registers and spills the caller past its 512-byte frame.
            if (func.getName().starts_with("bpf_heap_")) {
                continue;
            }
            // Pointer-argument call glue must fold into its entry: a global
            // subprogram cannot accept the entry's native stack pointers, so
            // these two keep their alwaysinline from the runtime source.
            if (func.getName() == "__bpf_capsule_finish_exited" || func.getName() == "__bpf_capsule_continue" || func.getName() == "__bpf_capsule_reset") {
                continue;
            }
            // Decide this before internalizing: internal linkage is itself
            // discardable-if-unused, so doing it the other way round answers
            // yes for every function and leaves alwaysinline on all of them —
            // which folds whole subsystems into the entry programs, loops
            // included, exactly where they cannot be stackified away.
            if (func.hasFnAttribute(Attribute::AlwaysInline)) {
                // A C99 `inline` definition has no out-of-line copy, so it has
                // to be inlined. Everything else keeps its own frame: the
                // hand-written alwaysinline annotations in legacy ports often
                // exist only to flatten the call graph, which bpf-stackify now
                // does without costing native stack space.
                if (func.hasAvailableExternallyLinkage() || func.isDiscardableIfUnused()) {
                    continue;
                }
                func.removeFnAttr(Attribute::AlwaysInline);
            }
            func.addFnAttr(Attribute::NoInline);
            // Everything that is not an entry point or part of the runtime can
            // be made internal, so the -O2 run that follows deletes whatever a
            // stripped feature left unreachable; C linkage would keep it all.
            // Fixed-map targets internalize early because every surviving
            // function consumes scarce verifier call-graph and software-frame
            // capacity. Arena targets defer this until after optimization.
            if (bpf::InternalizeEarly() && !func.hasSection() && func.getName() != "__bpf_capsule_trampoline") {
                func.setLinkage(GlobalValue::InternalLinkage);
            }
        }
        return PreservedAnalyses::none();
    }
};

// ---------------------------------------------------------------------------
// bpf-lower-sdiv: cpu v4 added signed division; older kernels only have
// unsigned. Rewrite sdiv/srem as unsigned operations with an explicit sign
// fixup so the whole thing builds at -mcpu=v3.
// ---------------------------------------------------------------------------

class LowerSDivPass : public PassInfoMixin<LowerSDivPass> {
public:
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        if (!bpf::LowerSignedDivision()) {
            return PreservedAnalyses::all();
        }
        SmallVector<BinaryOperator*> work;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* op = dyn_cast<BinaryOperator>(&inst);
                if (op && (op->getOpcode() == Instruction::SDiv || op->getOpcode() == Instruction::SRem)) {
                    work.push_back(op);
                }
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        for (auto* op : work) {
            IRBuilder<> b(op);
            bool isRem = op->getOpcode() == Instruction::SRem;
            auto* call = b.CreateCall(GetOrCreateHelper(module, op->getType(), isRem), {op->getOperand(0), op->getOperand(1)});
            // A call in a function with debug info must carry a location, and
            // the division it replaces may not have had one.
            DebugLoc loc = op->getDebugLoc();
            if (!loc) {
                if (auto* sp = op->getFunction()->getSubprogram()) {
                    loc = DILocation::get(module.getContext(), 0, 0, sp);
                }
            }
            call->setDebugLoc(loc);
            op->replaceAllUsesWith(call);
            op->eraseFromParent();
        }
        return PreservedAnalyses::none();
    }

private:
    // Emitted once and called, rather than expanded at every division site:
    // inline expansion multiplies the verifier's state count at each caller,
    // while a call is verified once and returns an opaque scalar.
    Function* GetOrCreateHelper(Module& module, Type* type, bool isRem) {
        std::string name = (isRem ? "__bpf_srem_i" : "__bpf_sdiv_i") + std::to_string(type->getIntegerBitWidth());
        if (auto* existing = module.getFunction(name)) {
            return existing;
        }

        LLVMContext& ctx = module.getContext();
        // Deliberately inlined away by the -O2 run that follows: constant
        // divisors fold to shifts once the optimizer sees the expansion.
        // Leaving the helpers as real
        // subprograms both costs verifier budget and pushes the kernel's
        // jit_subprogs() over the edge, which disables kfunc calls.
        auto* func = Function::Create(FunctionType::get(type, {type, type}, false), Function::InternalLinkage, name, module);
        func->setCallingConv(CallingConv::C);
        func->addFnAttr(Attribute::AlwaysInline);

        auto* block = BasicBlock::Create(ctx, "", func);
        IRBuilder<> b(block);
        Value* lhs = func->getArg(0);
        Value* rhs = func->getArg(1);

        // |x| branchlessly: (x ^ s) - s, where s is the sign mask.
        auto* shift = ConstantInt::get(type, type->getIntegerBitWidth() - 1);
        Value* lhsSign = b.CreateAShr(lhs, shift);
        Value* rhsSign = b.CreateAShr(rhs, shift);
        Value* lhsAbs = b.CreateSub(b.CreateXor(lhs, lhsSign), lhsSign);
        Value* rhsAbs = b.CreateSub(b.CreateXor(rhs, rhsSign), rhsSign);

        // A quotient's sign is lhs^rhs; a remainder takes the sign of lhs.
        Value* result = isRem ? b.CreateURem(lhsAbs, rhsAbs) : b.CreateUDiv(lhsAbs, rhsAbs);
        Value* sign = isRem ? lhsSign : b.CreateXor(lhsSign, rhsSign);
        b.CreateRet(b.CreateSub(b.CreateXor(result, sign), sign));

        if (!module.debug_compile_units().empty()) {
            DIBuilder debugBuilder(module, false, *module.debug_compile_units_begin());
            auto* intType = BtfGetInt(debugBuilder, type->getIntegerBitWidth(), true);
            BtfFunctionAddDebugInfo(debugBuilder, *func, {intType, intType, intType});
            debugBuilder.finalize();
        }
        return func;
    }
};

// ---------------------------------------------------------------------------
// bpf-lower-arena-sext: CPU v4 can fold a narrow load used by any signed
// operation (not only an explicit IR sext) into BPF_MEMSX. Kernels before 7.0
// reject that load mode specifically for arena pointers. Put a zero-cost,
// side-effecting compiler barrier after each narrow arena load: selection then
// emits BPF_MEM followed by any required register sign extension. This is
// intentionally late, after address-space inference, so only actual
// PTR_TO_ARENA loads are affected and no later IR optimizer can fold them back.
// ---------------------------------------------------------------------------

class LowerArenaSignedLoadsPass : public PassInfoMixin<LowerArenaSignedLoadsPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        if (!bpf::LowerArenaSignedLoads()) {
            return PreservedAnalyses::all();
        }

        SmallVector<LoadInst*> work;
        for (auto&& inst : instructions(func)) {
            auto* load = dyn_cast<LoadInst>(&inst);
            if (!load || load->getPointerAddressSpace() != 1 || !load->getType()->isIntegerTy()) {
                continue;
            }
            unsigned sourceBits = load->getType()->getIntegerBitWidth();
            if (sourceBits == 8 || sourceBits == 16 || sourceBits == 32) {
                work.push_back(load);
            }
        }

        for (LoadInst* load : work) {
            SmallVector<Use*> existingUses;
            for (Use& use : load->uses()) {
                existingUses.push_back(&use);
            }
            IRBuilder<> b(load->getNextNode());
            b.SetCurrentDebugLocation(load->getDebugLoc());
            Type* type = load->getType();
            auto* barrier = InlineAsm::get(FunctionType::get(type, {type}, false), "", "=r,0", /*hasSideEffects=*/true);
            Value* visible = b.CreateCall(barrier, {load}, "bpf.arena.load.visible");
            for (Use* use : existingUses) {
                use->set(visible);
            }
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

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
        return PreservedAnalyses::none();
    }
};

// ---------------------------------------------------------------------------
// bpf-define-undef: the verifier rejects any read of an uninitialized
// register, but LLVM happily materializes undef/poison — fix-irreducible in
// particular fills its guard PHIs with poison on paths where the value is not
// used. Poison permits any value, so replacing it with zero is a refinement.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// bpf-bound-vla: a variable-length array needs a frame whose size is known
// only at run time, and the software frame here is laid out once for every
// call depth at once. Each VLA therefore becomes a fixed reservation, made in
// the entry block so it is an ordinary static alloca by the time the call
// stack is built. Real code bounds these anyway (wasm3 rejects more than 1000
// arguments a few lines before declaring its array), but a request larger
// than the reservation would silently overrun adjacent frame slots, so each
// site also gets a run-time check. An oversized request publishes
// CAPSULE_ERROR_VLA_BOUNDS and returns before the reservation can be touched.
// ---------------------------------------------------------------------------
class BoundVlaPass : public PassInfoMixin<BoundVlaPass> {
public:
    static constexpr int32_t AbortCode = CAPSULE_ERROR_VLA_BOUNDS;

    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        SmallVector<AllocaInst*> dynamic;
        for (auto&& inst : instructions(func)) {
            if (auto* a = dyn_cast<AllocaInst>(&inst)) {
                if (!isa<ConstantInt>(a->getArraySize())) {
                    dynamic.push_back(a);
                }
            }
        }
        if (dynamic.empty()) {
            return PreservedAnalyses::all();
        }
        Module& module = *func.getParent();
        const DataLayout& dl = module.getDataLayout();
        IRBuilder<> b(&*func.getEntryBlock().getFirstInsertionPt());
        auto* i8 = Type::getInt8Ty(func.getContext());
        for (auto* a : dynamic) {
            TypeSize allocSize = dl.getTypeAllocSize(a->getAllocatedType());
            if (allocSize.isScalable()) {
                func.getContext().emitError(a, Twine("bpf-bound-vla: scalable alloca in ") + func.getName());
                return PreservedAnalyses::all();
            }
            uint64_t elementBytes = allocSize.getFixedValue();
            if (!elementBytes || elementBytes > bpf::DynamicAllocaBytes()) {
                func.getContext().emitError(a, Twine("bpf-bound-vla: element in ") + func.getName() + " exceeds the per-frame VLA reserve");
                return PreservedAnalyses::all();
            }

            auto* fixed = b.CreateAlloca(ArrayType::get(i8, bpf::DynamicAllocaBytes()), nullptr, a->getName() + ".vla");
            fixed->setAlignment(Align(16));

            // Compare the element count to capacity instead of multiplying by
            // element size: this is both cheaper and cannot wrap.
            BasicBlock* check = a->getParent();
            BasicBlock* body = check->splitBasicBlock(a, a->getName() + ".vla.ok");
            check->getTerminator()->eraseFromParent();
            BasicBlock* abort = BasicBlock::Create(func.getContext(), a->getName() + ".vla.abort", &func, body);

            IRBuilder<> cb(check);
            Value* count = cb.CreateZExtOrTrunc(a->getArraySize(), cb.getInt64Ty());
            Value* over = cb.CreateICmpUGT(count, cb.getInt64(bpf::DynamicAllocaBytes() / elementBytes));
            cb.CreateCondBr(over, abort, body);

            cb.SetInsertPoint(abort);
            cb.CreateStore(cb.getInt64(bpf::ExitWordValue(AbortCode)), bpf::ExitWordPointer(cb, func));
            if (func.getReturnType()->isVoidTy()) {
                cb.CreateRetVoid();
            } else {
                cb.CreateRet(Constant::getNullValue(func.getReturnType()));
            }

            a->replaceAllUsesWith(fixed);
            a->eraseFromParent();
        }
        return PreservedAnalyses::none();
    }
};

class DefineUndefPass : public PassInfoMixin<DefineUndefPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        bool changed = false;

        // `unreachable` is a promise the compiler made to itself, and the
        // backend turns it into a call to __bpf_trap, which the kernel
        // refuses to load ("unexpected __bpf_trap()"). The promise does not
        // always hold once whole paths have been rewritten, so each one
        // becomes an abort with its own code and an ordinary return: if the
        // program really does get there, it stops and says so.
        // llvm.trap lowers to the same refused __bpf_trap call (Rust emits it
        // for cold aborts); it conveys nothing an abort code does not.
        SmallVector<CallInst*> trapCalls;
        for (auto&& inst : instructions(func)) {
            auto* call = dyn_cast<CallInst>(&inst);
            if (call && (call->getIntrinsicID() == Intrinsic::trap || call->getIntrinsicID() == Intrinsic::debugtrap)) {
                trapCalls.push_back(call);
            }
        }
        for (auto* call : trapCalls) {
            IRBuilder<> b(call);
            b.CreateStore(ConstantInt::get(Type::getInt64Ty(func.getContext()), bpf::ExitWordValue(CAPSULE_ERROR_TRAP)), bpf::ExitWordPointer(b, func));
            call->eraseFromParent();
            changed = true;
        }

        SmallVector<UnreachableInst*> traps;
        for (auto&& block : func) {
            if (auto* un = dyn_cast<UnreachableInst>(block.getTerminator())) {
                traps.push_back(un);
            }
        }
        for (auto* un : traps) {
            IRBuilder<> b(un);
            b.CreateStore(ConstantInt::get(Type::getInt64Ty(func.getContext()), bpf::ExitWordValue(CAPSULE_ERROR_UNREACHABLE)), bpf::ExitWordPointer(b, func));
            if (func.getReturnType()->isVoidTy()) {
                b.CreateRetVoid();
            } else {
                b.CreateRet(Constant::getNullValue(func.getReturnType()));
            }
            un->eraseFromParent();
            changed = true;
        }

        for (auto&& inst : instructions(func)) {
            for (auto&& op : inst.operands()) {
                Value* value = op.get();
                if (!isa<UndefValue>(value) && !isa<PoisonValue>(value)) {
                    continue;
                }
                Type* type = value->getType();
                // Aggregate arguments and returns are scalarized later.  If
                // they remain poison here, scalarization turns one harmless
                // unspecified value into several accessor calls with
                // uninitialized argument registers, which the verifier quite
                // correctly rejects.  Zero is a valid refinement for every
                // first-class undef/poison value, including aggregates and
                // floating-point values.
                if (!type->isFirstClassType()) {
                    continue;
                }
                op.set(Constant::getNullValue(type));
                changed = true;
            }
        }
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

// The heap-region tier routes memory through width-specific accessors
// (bpf_heap_load32/64...), so a load or store of a first-class AGGREGATE —
// the shape stackify emits when a by-value struct argument or return moves
// through a frame slot — slips past the router and reaches the verifier as
// a raw access to an integer address. Scalarize them: element loads plus
// insertvalue, extractvalue plus element stores. The arena tier tolerates
// aggregate accesses, so this is a no-op there in effect, but it runs on
// every tier for one less shape to reason about.
struct ScalarizeAggPass : public PassInfoMixin<ScalarizeAggPass> {
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        // Only the heap-region tier routes memory through width-specific
        // accessors that an aggregate access slips past. The arena tier does
        // its own bounds check in hardware and takes aggregate loads fine, so
        // scalarizing there only inflates the instruction count (it pushed the
        // Rust MLP past the 1M verification budget). No-op on arena.
        if (bpf::UseArena()) {
            return PreservedAnalyses::all();
        }
        SmallVector<Instruction*> work;
        for (auto&& inst : instructions(func)) {
            if (auto* load = dyn_cast<LoadInst>(&inst); load && load->getType()->isAggregateType()) {
                work.push_back(load);
            } else if (auto* store = dyn_cast<StoreInst>(&inst); store && store->getValueOperand()->getType()->isAggregateType()) {
                work.push_back(store);
            }
        }
        for (unsigned i = 0; i < work.size(); i++) { // grows for nesting
            Instruction* inst = work[i];
            IRBuilder<> b(inst);
            if (auto* load = dyn_cast<LoadInst>(inst)) {
                Type* type = load->getType();
                Value* agg = PoisonValue::get(type);
                unsigned n = type->isStructTy() ? type->getStructNumElements() : type->getArrayNumElements();
                for (unsigned e = 0; e < n; e++) {
                    Value* ptr = b.CreateConstInBoundsGEP2_32(type, load->getPointerOperand(), 0, e);
                    Type* et = type->isStructTy() ? type->getStructElementType(e) : type->getArrayElementType();
                    auto* part = b.CreateLoad(et, ptr);
                    if (et->isAggregateType()) {
                        work.push_back(part);
                    }
                    agg = b.CreateInsertValue(agg, part, e);
                }
                load->replaceAllUsesWith(agg);
                load->eraseFromParent();
            } else {
                auto* store = cast<StoreInst>(inst);
                Value* val = store->getValueOperand();
                Type* type = val->getType();
                unsigned n = type->isStructTy() ? type->getStructNumElements() : type->getArrayNumElements();
                for (unsigned e = 0; e < n; e++) {
                    Value* ptr = b.CreateConstInBoundsGEP2_32(type, store->getPointerOperand(), 0, e);
                    auto* part = b.CreateStore(b.CreateExtractValue(val, e), ptr);
                    if (part->getValueOperand()->getType()->isAggregateType()) {
                        work.push_back(part);
                    }
                }
                store->eraseFromParent();
            }
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

// Kernel BTF accepts only C identifiers, but Rust debug info names types
// like `<core::fmt::Error as core::fmt::Debug>::{vtable_type}` and functions
// like `grow_amortized<alloc::alloc::Global>`. One invalid name makes the
// kernel reject the WHOLE .BTF, libbpf then loads without func_info, every
// subprogram silently becomes static, and the verifier walks the trampoline
// dispatch until "8193 jumps is too complex". Sanitize every BTF-visible
// debug-info name to [A-Za-z0-9_].
// Wide switches — the trampoline's physical-group dispatch is one in every
// program — must not become .jumptables indirect jumps on kernels without a
// working insn-array flow (see HasInsnArrayJumpTables). The attribute travels
// in the bitcode, so every llc invocation lowers switches as compare trees
// without needing backend flags. Runs after stackify: the trampoline and step
// functions must already exist to be stamped.
struct NoJumpTablesPass : public PassInfoMixin<NoJumpTablesPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        if (bpf::UseJumpTables()) {
            return PreservedAnalyses::all();
        }
        for (auto&& func : module) {
            func.addFnAttr("no-jump-tables", "true");
        }
        return PreservedAnalyses::all();
    }
};

struct SanitizeBtfNamesPass : public PassInfoMixin<SanitizeBtfNamesPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        bool changed = false;
        DebugInfoFinder finder;
        finder.processModule(module);
        auto fix = [&](DINode* node, MDString* raw) {
            if (!raw) {
                return;
            }
            StringRef name = raw->getString();
            if (name.empty() || llvm::all_of(name, [](char c) { return isalnum((unsigned char)c) || c == '_'; })) {
                return;
            }
            std::string clean = name.str();
            for (auto&& c : clean) {
                if (!isalnum((unsigned char)c) && c != '_') {
                    c = '_';
                }
            }
            MDString* neat = MDString::get(module.getContext(), clean);
            for (unsigned i = 0; i < node->getNumOperands(); i++) {
                if (node->getOperand(i).get() == raw) {
                    node->replaceOperandWith(i, neat);
                    changed = true;
                }
            }
        };
        for (DIType* type : finder.types()) {
            if (auto* comp = dyn_cast<DICompositeType>(type)) {
                fix(comp, comp->getRawName());
            } else if (auto* derived = dyn_cast<DIDerivedType>(type)) {
                fix(derived, derived->getRawName());
            }
        }
        for (DISubprogram* sp : finder.subprograms()) {
            fix(sp, sp->getRawName());
        }
        for (auto&& func : module) {
            if (DISubprogram* sp = func.getSubprogram()) {
                fix(sp, sp->getRawName());
            }
        }
        for (DIGlobalVariableExpression* gve : finder.global_variables()) {
            if (auto* gv = gve->getVariable()) {
                fix(gv, gv->getRawName());
            }
        }
        // Upstream optimizers (rustc's own release pipeline) split globals
        // into fragments while both halves keep the ORIGINAL variable's
        // debug info. The BTF emitter ignores fragment expressions, so the
        // datasec entry claims the full type's size for a half-sized global
        // and the kernel rejects the whole .BTF ("Invalid size"). A debug
        // attachment that no longer matches its global is worse than none.
        const DataLayout& dl = module.getDataLayout();
        for (auto&& g : module.globals()) {
            SmallVector<DIGlobalVariableExpression*> attachments;
            g.getDebugInfo(attachments);
            if (attachments.empty() || !g.getValueType()->isSized()) {
                continue;
            }
            bool bad = false;
            uint64_t bytes = dl.getTypeAllocSize(g.getValueType());
            for (auto* gve : attachments) {
                if (gve->getExpression() && gve->getExpression()->getNumElements()) {
                    bad = true;
                }
                DIType* type = gve->getVariable() ? gve->getVariable()->getType() : nullptr;
                if (type && type->getSizeInBits() && type->getSizeInBits() != bytes * 8) {
                    bad = true;
                }
            }
            if (bad) {
                g.eraseMetadata(module.getContext().getMDKindID("dbg"));
                changed = true;
            }
        }
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

// The BPF backend legalizes i128 by splitting for every operation except
// mul, div and rem, which become libcalls (__multi3, __udivti3) the kernel
// cannot host. Multiplication expands inline to 32-bit-half schoolbook — all
// i64 arithmetic. Division and remainder decompose into i64 pairs and call
// the freestanding __bpf_udiv128/__bpf_urem128 (pure 64-bit shift-subtract);
// signed forms wrap them in sign fixups built from splittable i128 ops.
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
            Value* result = nullptr;
            if (bin->getOpcode() == Instruction::Mul) {
                result = EmitMul(b, i64, i128, bin->getOperand(0), bin->getOperand(1));
            } else {
                result = EmitDivRem(module, b, i64, i128, bin);
            }
            bin->replaceAllUsesWith(result);
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
            Value* a = call->getArgOperand(0);
            Value* v = call->getArgOperand(1);
            auto [lo, hi] = EmitMul64Wide(b, i64, a, v);
            Value* overflow = nullptr;
            if (call->getIntrinsicID() == Intrinsic::umul_with_overflow) {
                overflow = b.CreateICmpNE(hi, ConstantInt::get(i64, 0));
            } else {
                // Signed high half: adjust the unsigned one, then the product
                // fits iff it equals the sign-extension of the low half.
                Value* zero = ConstantInt::get(i64, 0);
                Value* shi = b.CreateSub(hi, b.CreateAdd(b.CreateSelect(b.CreateICmpSLT(a, zero), v, zero), b.CreateSelect(b.CreateICmpSLT(v, zero), a, zero)));
                overflow = b.CreateICmpNE(shi, b.CreateAShr(lo, 63));
            }
            Value* pair = PoisonValue::get(call->getType());
            pair = b.CreateInsertValue(pair, lo, 0);
            pair = b.CreateInsertValue(pair, overflow, 1);
            call->replaceAllUsesWith(pair);
            call->eraseFromParent();
        }
        return work.empty() && overflowCalls.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }

    // 64x64 -> 128 as two i64 words, in i64 arithmetic only.
    std::pair<Value*, Value*> EmitMul64Wide(IRBuilder<>& b, Type* i64, Value* a0, Value* b0) {
        Value* mask = ConstantInt::get(i64, 0xffffffffull);
        Value* x0 = b.CreateAnd(a0, mask);
        Value* x1 = b.CreateLShr(a0, 32);
        Value* y0 = b.CreateAnd(b0, mask);
        Value* y1 = b.CreateLShr(b0, 32);
        Value* p00 = b.CreateMul(x0, y0);
        Value* p01 = b.CreateMul(x0, y1);
        Value* p10 = b.CreateMul(x1, y0);
        Value* p11 = b.CreateMul(x1, y1);
        Value* lo1 = b.CreateAdd(p00, b.CreateShl(b.CreateAnd(p01, mask), 32));
        Value* c1 = b.CreateZExt(b.CreateICmpULT(lo1, p00), i64);
        Value* lo2 = b.CreateAdd(lo1, b.CreateShl(b.CreateAnd(p10, mask), 32));
        Value* c2 = b.CreateZExt(b.CreateICmpULT(lo2, lo1), i64);
        Value* hi = b.CreateAdd(b.CreateAdd(p11, b.CreateAdd(b.CreateLShr(p01, 32), b.CreateLShr(p10, 32))), b.CreateAdd(c1, c2));
        return {lo2, hi};
    }

    Value* EmitMul(IRBuilder<>& b, Type* i64, Type* i128, Value* a, Value* v) {
        Value* a0 = b.CreateTrunc(a, i64);
        Value* a1 = b.CreateTrunc(b.CreateLShr(a, 64), i64);
        Value* b0 = b.CreateTrunc(v, i64);
        Value* b1 = b.CreateTrunc(b.CreateLShr(v, 64), i64);
        auto [lo, hi] = EmitMul64Wide(b, i64, a0, b0);
        hi = b.CreateAdd(hi, b.CreateAdd(b.CreateMul(a0, b1), b.CreateMul(a1, b0)));
        return b.CreateOr(b.CreateZExt(lo, i128), b.CreateShl(b.CreateZExt(hi, i128), 64));
    }

    Value* EmitDivRem(Module& module, IRBuilder<>& b, Type* i64, Type* i128, BinaryOperator* bin) {
        bool isRem = bin->getOpcode() == Instruction::URem || bin->getOpcode() == Instruction::SRem;
        bool isSigned = bin->getOpcode() == Instruction::SDiv || bin->getOpcode() == Instruction::SRem;
        Function* helper = module.getFunction(isRem ? "__bpf_urem128" : "__bpf_udiv128");
        if (!helper) {
            report_fatal_error(
                "bpf-expand-i128: i128 division present but "
                "freestanding int128.c is not linked in"
            );
        }
        Value* zero = ConstantInt::get(i128, 0);
        Value* a = bin->getOperand(0);
        Value* d = bin->getOperand(1);
        Value* negA = nullptr;
        Value* negD = nullptr;
        if (isSigned) {
            negA = b.CreateICmpSLT(a, zero);
            negD = b.CreateICmpSLT(d, zero);
            a = b.CreateSelect(negA, b.CreateSub(zero, a), a);
            d = b.CreateSelect(negD, b.CreateSub(zero, d), d);
        }
        Value* args[] = {
            b.CreateTrunc(a, i64),
            b.CreateTrunc(b.CreateLShr(a, 64), i64),
            b.CreateTrunc(d, i64),
            b.CreateTrunc(b.CreateLShr(d, 64), i64),
        };
        Value* pair = nullptr;
        if (helper->arg_size() && helper->getArg(0)->hasStructRetAttr()) {
            Type* pairType = helper->getParamStructRetType(0);
            IRBuilder<> entry(&*bin->getFunction()->getEntryBlock().getFirstInsertionPt());
            AllocaInst* result = entry.CreateAlloca(pairType, nullptr, "i128.result");
            if (auto alignment = helper->getParamAlign(0)) {
                result->setAlignment(*alignment);
            }
            SmallVector<Value*> helperArgs{result};
            helperArgs.append(std::begin(args), std::end(args));
            CallInst* call = b.CreateCall(helper->getFunctionType(), helper, helperArgs);
            call->setCallingConv(helper->getCallingConv());
            call->setAttributes(helper->getAttributes());
            pair = b.CreateLoad(pairType, result);
        } else {
            pair = b.CreateCall(helper, args);
        }
        Value* lo = b.CreateExtractValue(pair, 0);
        Value* hi = b.CreateExtractValue(pair, 1);
        Value* out = b.CreateOr(b.CreateZExt(lo, i128), b.CreateShl(b.CreateZExt(hi, i128), 64));
        if (isSigned) {
            // Quotient flips when signs differ; remainder takes the dividend's.
            Value* flip = isRem ? negA : b.CreateXor(negA, negD);
            out = b.CreateSelect(flip, b.CreateSub(zero, out), out);
        }
        return out;
    }
};

// Atomics are a semantic boundary, not a verifier workaround. Native wrappers
// keep genuine BPF atomics. Relaxed scalar loads/stores remain atomic too: the
// memory pass retains them through -O2 and eventually emits one naturally
// sized BPF memory instruction. Capsule operations that need an ISA RMW or a
// memory-ordering fence are rejected until they have an exact lowering. There
// is no bounded-retry lock, silent non-atomic fallback, or run-time atomic
// failure: none would implement the source language contract.
struct LowerAtomicsPass : public PassInfoMixin<LowerAtomicsPass> {
    static bool IsPreservedLoadStore(Instruction& inst) {
        Type* type = nullptr;
        AtomicOrdering ordering = AtomicOrdering::NotAtomic;
        Align alignment(1);
        if (auto* load = dyn_cast<LoadInst>(&inst); load && load->isAtomic()) {
            type = load->getType();
            ordering = load->getOrdering();
            alignment = load->getAlign();
        } else if (auto* store = dyn_cast<StoreInst>(&inst); store && store->isAtomic()) {
            type = store->getValueOperand()->getType();
            ordering = store->getOrdering();
            alignment = store->getAlign();
        } else {
            return false;
        }

        if (ordering != AtomicOrdering::Unordered && ordering != AtomicOrdering::Monotonic) {
            return false;
        }
        if (!type->isIntegerTy() && !type->isPointerTy()) {
            return false;
        }
        uint64_t bytes = inst.getModule()->getDataLayout().getTypeStoreSize(type).getFixedValue();
        return (bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8) && alignment.value() >= bytes;
    }

    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        if (!bpf::IsCapsuleFunction(func)) {
            return PreservedAnalyses::all();
        }
        SmallVector<Instruction*> work;
        for (Instruction& inst : instructions(func)) {
            bool atomic = isa<AtomicRMWInst>(inst) || isa<AtomicCmpXchgInst>(inst) || isa<FenceInst>(inst) ||
                (isa<LoadInst>(inst) && cast<LoadInst>(inst).isAtomic()) || (isa<StoreInst>(inst) && cast<StoreInst>(inst).isAtomic());
            if (atomic && !IsPreservedLoadStore(inst)) {
                work.push_back(&inst);
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        Instruction* unsupported = work.front();
        Type* valueType = nullptr;
        std::string operation;
        if (auto* rmw = dyn_cast<AtomicRMWInst>(unsupported)) {
            valueType = rmw->getValOperand()->getType();
            operation = AtomicRMWInst::getOperationName(rmw->getOperation());
        } else if (auto* cas = dyn_cast<AtomicCmpXchgInst>(unsupported)) {
            valueType = cas->getCompareOperand()->getType();
            operation = "compare-exchange";
        } else if (auto* load = dyn_cast<LoadInst>(unsupported)) {
            valueType = load->getType();
            operation = "load";
        } else if (auto* store = dyn_cast<StoreInst>(unsupported)) {
            valueType = store->getValueOperand()->getType();
            operation = "store";
        } else {
            operation = "fence";
        }
        uint64_t bits = valueType ? func.getParent()->getDataLayout().getTypeStoreSizeInBits(valueType).getFixedValue() : 0;
        unsigned version = bpf::Version();
        func.getContext().emitError(
            unsupported,
            Twine("bpf-lower-atomics: Capsule atomic ") + operation + (bits ? Twine(" i") + Twine(bits) : Twine()) + " in " + func.getName() +
                " cannot be preserved for the Linux " + Twine(version / 1000) + "." + Twine(version % 1000) + " target"
        );
        return PreservedAnalyses::all();
    }
};

// LLVM's BPF backend has no selection pattern for AtomicLoad/AtomicStore,
// even for relaxed naturally aligned accesses whose machine representation is
// exactly one ordinary load/store. Keep the atomic marker through all generic
// optimization and virtual-memory routing, then remove it here at the last IR
// stage. No optimizing IR pass runs afterwards.
struct FinalizeAtomicLoadStorePass : public PassInfoMixin<FinalizeAtomicLoadStorePass> {
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        SmallVector<Instruction*> work;
        for (Instruction& inst : instructions(func)) {
            if ((isa<LoadInst>(inst) && cast<LoadInst>(inst).isAtomic()) || (isa<StoreInst>(inst) && cast<StoreInst>(inst).isAtomic())) {
                if (!LowerAtomicsPass::IsPreservedLoadStore(inst)) {
                    func.getContext().emitError(
                        &inst,
                        "bpf-finalize-atomic-load-store: unsupported atomic "
                        "survived validation"
                    );
                    return PreservedAnalyses::all();
                }
                work.push_back(&inst);
            }
        }
        for (Instruction* inst : work) {
            IRBuilder<> b(inst);
            if (auto* load = dyn_cast<LoadInst>(inst)) {
                auto* replacement = b.CreateLoad(load->getType(), load->getPointerOperand());
                replacement->setAlignment(load->getAlign());
                replacement->setVolatile(load->isVolatile());
                replacement->copyMetadata(*load);
                replacement->setDebugLoc(load->getDebugLoc());
                load->replaceAllUsesWith(replacement);
            } else {
                auto* store = cast<StoreInst>(inst);
                auto* replacement = b.CreateStore(store->getValueOperand(), store->getPointerOperand());
                replacement->setAlignment(store->getAlign());
                replacement->setVolatile(store->isVolatile());
                replacement->copyMetadata(*store);
                replacement->setDebugLoc(store->getDebugLoc());
            }
            inst->eraseFromParent();
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

// Internal sret pointers are semantically valid unified-memory pointers, but
// keeping the ABI indirection makes every aggregate result an escaped logical
// pointer. On the fixed tier that prevents current-frame stack specialization
// and substantially expands both emitted code and verifier path exploration.
// Normalize definitions and calls to natural aggregate values before O2. This
// is a code-quality transform; Stackify still accepts sret IR as a fallback.
struct ExpandSretPass : public PassInfoMixin<ExpandSretPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        SmallVector<Function*> worklist;
        for (auto&& func : module) {
            // Rewriting an address-taken function would also change the ABI
            // expected by an indirect caller which cannot be proven to name
            // only definitions in this module.  Capsule roots are
            // intentionally address-taken by the call marker and are adapted
            // at that boundary instead.  Direct internal calls provide the
            // code-quality win without changing any external ABI.
            if (!func.isDeclaration() && !func.hasAddressTaken() && func.arg_size() > 0 && func.getArg(0)->hasStructRetAttr()) {
                worklist.push_back(&func);
            }
        }
        DenseMap<Function*, Type*> rewritten;
        for (auto* func : worklist) {
            RewriteFunction(module, *func, rewritten);
        }
        // Opaque pointers let the rewritten definition replace the old
        // callee operand while the CallInst retains its original function
        // type and hidden result argument. Rewrite precisely those direct
        // sites; declarations and indirect calls keep their ABI.
        SmallVector<std::pair<CallInst*, Type*>> sites;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* call = dyn_cast<CallInst>(&inst);
                if (!call) {
                    continue;
                }
                auto* callee = dyn_cast<Function>(call->getCalledOperand()->stripPointerCasts());
                auto it = callee ? rewritten.find(callee) : rewritten.end();
                if (it == rewritten.end()) {
                    continue;
                }
                if (!call->getFunctionType()->getReturnType()->isVoidTy() || call->arg_size() != callee->arg_size() + 1) {
                    report_fatal_error(Twine("bpf-expand-sret: malformed direct call to ") + callee->getName());
                }
                sites.push_back({call, it->second});
            }
        }
        for (auto&& [call, retType] : sites) {
            RewriteCallSite(*call, retType);
        }
        return worklist.empty() && sites.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }

    void RewriteFunction(Module& module, Function& func, DenseMap<Function*, Type*>& rewritten) {
        Type* retType = func.getParamStructRetType(0);
        SmallVector<Type*> params;
        for (unsigned i = 1; i < func.arg_size(); i++) {
            params.push_back(func.getArg(i)->getType());
        }
        auto* newType = FunctionType::get(retType, params, func.isVarArg());
        Function* newFunc = Function::Create(newType, func.getLinkage(), func.getAddressSpace(), "", &module);
        newFunc->takeName(&func);
        newFunc->copyAttributesFrom(&func);
        newFunc->setCallingConv(func.getCallingConv());
        newFunc->setSubprogram(func.getSubprogram());
        SmallVector<AttributeSet> parameterAttributes;
        for (unsigned i = 1; i < func.arg_size(); ++i) {
            parameterAttributes.push_back(func.getAttributes().getParamAttrs(i));
        }
        newFunc->setAttributes(AttributeList::get(module.getContext(), func.getAttributes().getFnAttrs(), AttributeSet(), parameterAttributes));
        newFunc->splice(newFunc->begin(), &func);

        IRBuilder<> builder(&newFunc->getEntryBlock(), newFunc->getEntryBlock().getFirstNonPHIIt());
        auto* slot = builder.CreateAlloca(retType);
        if (auto alignment = func.getParamAlign(0)) {
            slot->setAlignment(*alignment);
        }
        func.getArg(0)->replaceAllUsesWith(slot);
        for (unsigned i = 1; i < func.arg_size(); i++) {
            func.getArg(i)->replaceAllUsesWith(newFunc->getArg(i - 1));
            newFunc->getArg(i - 1)->takeName(func.getArg(i));
        }
        for (auto&& block : *newFunc) {
            auto* ret = dyn_cast<ReturnInst>(block.getTerminator());
            if (!ret) {
                continue;
            }
            IRBuilder<> rb(ret);
            rb.CreateRet(rb.CreateLoad(retType, slot));
            ret->eraseFromParent();
        }
        // Opaque pointers make the old and new function interchangeable as
        // values; direct calls still carry their own sret attribute and are
        // rewritten with the indirect ones.
        func.replaceAllUsesWith(newFunc);
        func.eraseFromParent();
        rewritten[newFunc] = retType;
    }

    void RewriteCallSite(CallInst& call, Type* retType) {
        Value* out = call.getArgOperand(0);
        SmallVector<Value*> args;
        SmallVector<Type*> params;
        SmallVector<AttributeSet> parameterAttributes;
        for (unsigned i = 1; i < call.arg_size(); i++) {
            args.push_back(call.getArgOperand(i));
            params.push_back(call.getArgOperand(i)->getType());
            parameterAttributes.push_back(call.getAttributes().getParamAttrs(i));
        }
        IRBuilder<> builder(&call);
        auto* newType = FunctionType::get(retType, params, call.getFunctionType()->isVarArg());
        SmallVector<OperandBundleDef> bundles;
        call.getOperandBundlesAsDefs(bundles);
        auto* newCall = builder.CreateCall(newType, call.getCalledOperand(), args, bundles);
        // A convention mismatch between call site and callee is UB that the
        // optimizer folds to poison — the grow path of Rust's Vec vanished
        // this way (fastcc callee, default-cc call).
        newCall->setCallingConv(call.getCallingConv());
        newCall->setAttributes(AttributeList::get(call.getContext(), call.getAttributes().getFnAttrs(), AttributeSet(), parameterAttributes));
        newCall->copyMetadata(call);
        newCall->setDebugLoc(call.getDebugLoc());
        StoreInst* store = builder.CreateStore(newCall, out);
        if (auto alignment = call.getParamAlign(0)) {
            store->setAlignment(*alignment);
        }
        call.eraseFromParent();
    }
};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {
        .APIVersion = LLVM_PLUGIN_API_VERSION,
        .PluginName = "BPF Capsule",
        .PluginVersion = "1.0",
        .RegisterPassBuilderCallbacks = [](PassBuilder& PB) {
            PB.registerPipelineParsingCallback([&PB](StringRef Name, ModulePassManager& PM, ArrayRef<PassBuilder::PipelineElement>) {
                if (Name == "bpf-capsule") {
                    if (Error error = PB.parsePassPipeline(PM, CapsulePipeline)) {
                        report_fatal_error(Twine("cannot construct BPF Capsule pipeline: ") + toString(std::move(error)));
                    }
                    return true;
                }
                if (RegisterMemoryPass(Name, PM)) {
                    return true;
                }
                if (Name == "bpf-partition") {
                    PM.addPass(CapsulePartitionPass());
                    return true;
                }
                if (Name == "bpf-stackify") {
                    PM.addPass(Stackify());
                    return true;
                }
                if (Name == "bpf-no-inline") {
                    PM.addPass(NoInlinePass());
                    return true;
                }
                if (Name == "bpf-lower-sdiv") {
                    PM.addPass(LowerSDivPass());
                    return true;
                }
                if (Name == "bpf-expand-varargs") {
                    PM.addPass(ExpandVarargsPass());
                    return true;
                }
                if (Name == "bpf-expand-sret") {
                    PM.addPass(ExpandSretPass());
                    return true;
                }
                if (Name == "bpf-expand-i128") {
                    PM.addPass(ExpandI128Pass());
                    return true;
                }
                if (Name == "bpf-no-jump-tables") {
                    PM.addPass(NoJumpTablesPass());
                    return true;
                }
                if (Name == "bpf-sanitize-btf") {
                    PM.addPass(SanitizeBtfNamesPass());
                    return true;
                }
                if (Name == "bpf-soft-float") {
                    PM.addPass(SoftFloatPass());
                    return true;
                }
                if (Name == "bpf-internalize-runtime") {
                    PM.addPass(InternalizeRuntimePass());
                    return true;
                }
                return false;
            });
            PB.registerPipelineParsingCallback([](StringRef Name, FunctionPassManager& PM, ArrayRef<PassBuilder::PipelineElement>) {
                if (Name == "bpf-expand-mem") {
                    PM.addPass(ExpandMemPass());
                    return true;
                }
                if (Name == "bpf-split-shift63") {
                    PM.addPass(SplitShift63Pass());
                    return true;
                }
                if (Name == "bpf-bound-vla") {
                    PM.addPass(BoundVlaPass());
                    return true;
                }
                if (Name == "bpf-define-undef") {
                    PM.addPass(DefineUndefPass());
                    return true;
                }
                if (Name == "bpf-infer-as") {
                    PM.addPass(InferAddressSpacesPass(0));
                    return true;
                }
                if (Name == "bpf-lower-arena-sext") {
                    PM.addPass(LowerArenaSignedLoadsPass());
                    return true;
                }
                if (Name == "bpf-lower-atomics") {
                    PM.addPass(LowerAtomicsPass());
                    return true;
                }
                if (Name == "bpf-finalize-atomic-load-store") {
                    PM.addPass(FinalizeAtomicLoadStorePass());
                    return true;
                }
                if (Name == "bpf-scalarize-agg") {
                    PM.addPass(ScalarizeAggPass());
                    return true;
                }
                return false;
            });
        },
    };
}
