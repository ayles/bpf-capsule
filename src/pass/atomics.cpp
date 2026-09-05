// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "atomics.h"

#include "common.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

using namespace llvm;

namespace {

constexpr StringLiteral AtomicFenceName = "__bpf_capsule_atomic_fence";
constexpr StringLiteral AtomicFenceSection = ".data.bpfatomic";

unsigned AtomicWidth(const DataLayout& layout, Type* type) {
    TypeSize size = layout.getTypeStoreSizeInBits(type);
    return size.isScalable() ? 0 : size.getFixedValue();
}

bool IsIntegerWidth(Type* type, unsigned bits) {
    return type->isIntegerTy(bits) || (type->isPointerTy() && bits == 64);
}

Value* ToIntegerBits(IRBuilder<>& builder, Value* value, IntegerType* type) {
    if (value->getType()->isPointerTy()) {
        return builder.CreatePtrToInt(value, type);
    }
    if (value->getType() == type) {
        return value;
    }
    return builder.CreateBitCast(value, type);
}

Value* FromIntegerBits(IRBuilder<>& builder, Value* value, Type* type) {
    if (type->isPointerTy()) {
        return builder.CreateIntToPtr(value, type);
    }
    if (value->getType() == type) {
        return value;
    }
    return builder.CreateBitCast(value, type);
}

Value* AtomicOperation(IRBuilder<>& builder, AtomicRMWInst::BinOp operation, Value* oldValue, Value* operand) {
    switch (operation) {
        case AtomicRMWInst::Add:
            return builder.CreateAdd(oldValue, operand);
        case AtomicRMWInst::Sub:
            return builder.CreateSub(oldValue, operand);
        case AtomicRMWInst::And:
            return builder.CreateAnd(oldValue, operand);
        case AtomicRMWInst::Nand:
            return builder.CreateNot(builder.CreateAnd(oldValue, operand));
        case AtomicRMWInst::Or:
            return builder.CreateOr(oldValue, operand);
        case AtomicRMWInst::Xor:
            return builder.CreateXor(oldValue, operand);
        case AtomicRMWInst::Xchg:
            return operand;
        default:
            return nullptr;
    }
}

bool IsSectionedPointer(Value* pointer) {
    auto* global = dyn_cast<GlobalVariable>(getUnderlyingObject(pointer));
    return global && global->hasSection();
}

struct NarrowWord {
    Value* Pointer;
    Value* Shift;
    Value* Mask;
};

NarrowWord NarrowWordFor(IRBuilder<>& builder, Value* pointer, unsigned bits) {
    const DataLayout& layout = builder.GetInsertBlock()->getModule()->getDataLayout();
    auto* pointerType = cast<PointerType>(pointer->getType());
    IntegerType* addressType = layout.getIntPtrType(builder.getContext(), pointerType->getAddressSpace());
    Value* address = builder.CreatePtrToInt(pointer, addressType);
    Value* byte = builder.CreateAnd(address, ConstantInt::get(addressType, 3));
    Value* aligned = builder.CreateAnd(address, ConstantInt::get(addressType, -4, true));
    Value* wordPointer = builder.CreateIntToPtr(aligned, pointerType);
    Value* shift = builder.CreateMul(builder.CreateTrunc(byte, builder.getInt32Ty()), builder.getInt32(8));
    uint32_t lowMask = bits == 32 ? UINT32_MAX : (uint32_t(1) << bits) - 1;
    Value* mask = builder.CreateShl(builder.getInt32(lowMask), shift);
    return {wordPointer, shift, mask};
}

Value* ExtractNarrow(IRBuilder<>& builder, Value* word, Value* shift, IntegerType* type) {
    return builder.CreateTrunc(builder.CreateLShr(word, shift), type);
}

Value* ReplaceNarrow(IRBuilder<>& builder, Value* word, Value* shift, Value* mask, Value* value) {
    Value* inserted = builder.CreateShl(builder.CreateZExt(value, builder.getInt32Ty()), shift);
    Value* preserved = builder.CreateAnd(word, builder.CreateNot(mask));
    Value* replacement = builder.CreateAnd(inserted, mask);
    return builder.CreateOr(preserved, replacement);
}

AtomicCmpXchgInst* CreateCas(IRBuilder<>& builder, Value* pointer, Value* expected, Value* desired, Align alignment) {
    return builder.CreateAtomicCmpXchg(pointer, expected, desired, alignment, AtomicOrdering::SequentiallyConsistent, AtomicOrdering::SequentiallyConsistent);
}

// BPF has native 32/64-bit atomics, but no sub-word RMWs. Capsule-managed
// memory is a naturally aligned flat arena, so a byte or half-word operation
// can update its containing word with compare-exchange while preserving the
// neighbouring fields. The retry loop is source-visible IR: unlike a loop
// hidden inside a JIT expansion, each attempt remains one faultable arena CAS.
Value* LowerNarrowRmw(AtomicRMWInst& rmw) {
    auto* type = cast<IntegerType>(rmw.getValOperand()->getType());
    unsigned bits = type->getBitWidth();
    Function* function = rmw.getFunction();
    LLVMContext& context = function->getContext();
    BasicBlock* before = rmw.getParent();
    BasicBlock* done = before->splitBasicBlock(rmw.getIterator(), "atomic.done");
    before->getTerminator()->eraseFromParent();
    BasicBlock* retry = BasicBlock::Create(context, "atomic.retry", function, done);

    IRBuilder<> entry(before);
    entry.SetCurrentDebugLocation(rmw.getDebugLoc());
    NarrowWord target = NarrowWordFor(entry, rmw.getPointerOperand(), bits);
    auto* initial = entry.CreateLoad(entry.getInt32Ty(), target.Pointer);
    initial->setAtomic(AtomicOrdering::Monotonic);
    initial->setAlignment(Align(4));
    entry.CreateBr(retry);

    IRBuilder<> loop(retry);
    loop.SetCurrentDebugLocation(rmw.getDebugLoc());
    PHINode* current = loop.CreatePHI(loop.getInt32Ty(), 2, "atomic.current");
    current->addIncoming(initial, before);
    Value* oldValue = ExtractNarrow(loop, current, target.Shift, type);
    Value* newValue = AtomicOperation(loop, rmw.getOperation(), oldValue, rmw.getValOperand());
    if (!newValue) {
        report_fatal_error(Twine("bpf-lower-managed-atomics: unsupported atomic ") + AtomicRMWInst::getOperationName(rmw.getOperation()));
    }
    Value* desired = ReplaceNarrow(loop, current, target.Shift, target.Mask, newValue);
    AtomicCmpXchgInst* cas = CreateCas(loop, target.Pointer, current, desired, Align(4));
    Value* observed = loop.CreateExtractValue(cas, 0);
    Value* success = loop.CreateExtractValue(cas, 1);
    current->addIncoming(observed, retry);
    loop.CreateCondBr(success, done, retry);

    rmw.replaceAllUsesWith(oldValue);
    rmw.eraseFromParent();
    return oldValue;
}

Value* LowerWideRmw(AtomicRMWInst& rmw) {
    Function* function = rmw.getFunction();
    LLVMContext& context = function->getContext();
    BasicBlock* before = rmw.getParent();
    BasicBlock* done = before->splitBasicBlock(rmw.getIterator(), "atomic.done");
    before->getTerminator()->eraseFromParent();
    BasicBlock* retry = BasicBlock::Create(context, "atomic.retry", function, done);

    IRBuilder<> entry(before);
    entry.SetCurrentDebugLocation(rmw.getDebugLoc());
    auto* initial = entry.CreateLoad(rmw.getValOperand()->getType(), rmw.getPointerOperand());
    initial->setAtomic(AtomicOrdering::Monotonic);
    initial->setAlignment(rmw.getAlign());
    entry.CreateBr(retry);

    IRBuilder<> loop(retry);
    loop.SetCurrentDebugLocation(rmw.getDebugLoc());
    PHINode* current = loop.CreatePHI(rmw.getValOperand()->getType(), 2, "atomic.current");
    current->addIncoming(initial, before);
    Value* desired = AtomicOperation(loop, rmw.getOperation(), current, rmw.getValOperand());
    if (!desired) {
        report_fatal_error(Twine("bpf-lower-managed-atomics: unsupported atomic ") + AtomicRMWInst::getOperationName(rmw.getOperation()));
    }
    AtomicCmpXchgInst* cas = CreateCas(loop, rmw.getPointerOperand(), current, desired, rmw.getAlign());
    Value* observed = loop.CreateExtractValue(cas, 0);
    Value* success = loop.CreateExtractValue(cas, 1);
    current->addIncoming(observed, retry);
    loop.CreateCondBr(success, done, retry);

    rmw.replaceAllUsesWith(current);
    rmw.eraseFromParent();
    return current;
}

Value* LowerNarrowCmpXchg(AtomicCmpXchgInst& original) {
    auto* type = cast<IntegerType>(original.getCompareOperand()->getType());
    unsigned bits = type->getBitWidth();
    Function* function = original.getFunction();
    LLVMContext& context = function->getContext();
    BasicBlock* before = original.getParent();
    BasicBlock* done = before->splitBasicBlock(original.getIterator(), "atomic.done");
    before->getTerminator()->eraseFromParent();
    BasicBlock* retry = BasicBlock::Create(context, "atomic.retry", function, done);
    BasicBlock* attempt = BasicBlock::Create(context, "atomic.attempt", function, done);

    IRBuilder<> entry(before);
    entry.SetCurrentDebugLocation(original.getDebugLoc());
    NarrowWord target = NarrowWordFor(entry, original.getPointerOperand(), bits);
    auto* initial = entry.CreateLoad(entry.getInt32Ty(), target.Pointer);
    initial->setAtomic(AtomicOrdering::Monotonic);
    initial->setAlignment(Align(4));
    entry.CreateBr(retry);

    IRBuilder<> loop(retry);
    loop.SetCurrentDebugLocation(original.getDebugLoc());
    PHINode* current = loop.CreatePHI(loop.getInt32Ty(), 2, "atomic.current");
    current->addIncoming(initial, before);
    Value* observedValue = ExtractNarrow(loop, current, target.Shift, type);
    Value* matches = loop.CreateICmpEQ(observedValue, original.getCompareOperand());
    loop.CreateCondBr(matches, attempt, done);

    IRBuilder<> exchange(attempt);
    exchange.SetCurrentDebugLocation(original.getDebugLoc());
    Value* desired = ReplaceNarrow(exchange, current, target.Shift, target.Mask, original.getNewValOperand());
    AtomicCmpXchgInst* cas = CreateCas(exchange, target.Pointer, current, desired, Align(4));
    Value* observedWord = exchange.CreateExtractValue(cas, 0);
    Value* success = exchange.CreateExtractValue(cas, 1);
    current->addIncoming(observedWord, attempt);
    exchange.CreateCondBr(success, done, retry);

    IRBuilder<> tail(&*done->begin());
    PHINode* exchanged = tail.CreatePHI(tail.getInt1Ty(), 2, "atomic.exchanged");
    exchanged->addIncoming(tail.getFalse(), retry);
    exchanged->addIncoming(tail.getTrue(), attempt);
    Value* result = PoisonValue::get(original.getType());
    result = tail.CreateInsertValue(result, observedValue, 0);
    result = tail.CreateInsertValue(result, exchanged, 1);
    original.replaceAllUsesWith(result);
    original.eraseFromParent();
    return result;
}

struct LowerManagedAtomicsPass : public PassInfoMixin<LowerManagedAtomicsPass> {
    explicit LowerManagedAtomicsPass(bool lowerWideBitwise = true)
        : LowerWideBitwise_(lowerWideBitwise) {
    }

    bool LowerWideBitwise_ = true;

    PreservedAnalyses run(Function& function, FunctionAnalysisManager&) {
        if (!bpf::IsCapsuleFunction(function)) {
            return PreservedAnalyses::all();
        }
        SmallVector<Instruction*> work;
        for (Instruction& inst : instructions(function)) {
            if (isa<AtomicRMWInst, AtomicCmpXchgInst, FenceInst>(&inst) || (isa<LoadInst>(&inst) && cast<LoadInst>(inst).isAtomic()) ||
                (isa<StoreInst>(&inst) && cast<StoreInst>(inst).isAtomic())) {
                work.push_back(&inst);
            }
        }

        bool changed = false;
        for (Instruction* inst : work) {
            const DataLayout& layout = function.getParent()->getDataLayout();
            if (auto* rmw = dyn_cast<AtomicRMWInst>(inst)) {
                unsigned bits = AtomicWidth(layout, rmw->getValOperand()->getType());
                if ((bits == 8 || bits == 16) && !IsSectionedPointer(rmw->getPointerOperand())) {
                    if (rmw->getAlign().value() * 8 < bits) {
                        report_fatal_error("bpf-lower-managed-atomics: sub-word atomic is not naturally aligned");
                    }
                    LowerNarrowRmw(*rmw);
                    changed = true;
                } else if ((rmw->getOperation() == AtomicRMWInst::Nand ||
                               (LowerWideBitwise_ &&
                                   (rmw->getOperation() == AtomicRMWInst::And || rmw->getOperation() == AtomicRMWInst::Or ||
                                       rmw->getOperation() == AtomicRMWInst::Xor))) &&
                    !IsSectionedPointer(rmw->getPointerOperand())) {
                    LowerWideRmw(*rmw);
                    changed = true;
                } else if (rmw->getOperation() == AtomicRMWInst::Sub && (bits == 32 || bits == 64)) {
                    IRBuilder<> builder(rmw);
                    builder.SetCurrentDebugLocation(rmw->getDebugLoc());
                    rmw->setOperation(AtomicRMWInst::Add);
                    rmw->setOperand(1, builder.CreateNeg(rmw->getValOperand()));
                    changed = true;
                }
                continue;
            }
            if (auto* cas = dyn_cast<AtomicCmpXchgInst>(inst)) {
                unsigned bits = AtomicWidth(layout, cas->getCompareOperand()->getType());
                if ((bits == 8 || bits == 16) && !IsSectionedPointer(cas->getPointerOperand())) {
                    if (cas->getAlign().value() * 8 < bits) {
                        report_fatal_error("bpf-lower-managed-atomics: sub-word compare-exchange is not naturally aligned");
                    }
                    LowerNarrowCmpXchg(*cas);
                    changed = true;
                }
                continue;
            }
            if (auto* load = dyn_cast<LoadInst>(inst); load && load->isAtomic() && isStrongerThanMonotonic(load->getOrdering())) {
                unsigned bits = AtomicWidth(layout, load->getType());
                if ((bits != 8 && bits != 16 && bits != 32 && bits != 64) || (bits < 32 && IsSectionedPointer(load->getPointerOperand()))) {
                    continue;
                }
                if (load->getAlign().value() * 8 < bits) {
                    report_fatal_error("bpf-lower-managed-atomics: atomic load is not naturally aligned");
                }
                IRBuilder<> builder(load);
                builder.SetCurrentDebugLocation(load->getDebugLoc());
                IntegerType* integerType = builder.getIntNTy(bits);
                Value* result;
                if (bits < 32) {
                    NarrowWord target = NarrowWordFor(builder, load->getPointerOperand(), bits);
                    Value* word =
                        builder.CreateAtomicRMW(AtomicRMWInst::Add, target.Pointer, builder.getInt32(0), Align(4), AtomicOrdering::SequentiallyConsistent);
                    result = ExtractNarrow(builder, word, target.Shift, integerType);
                } else {
                    result = builder.CreateAtomicRMW(AtomicRMWInst::Add, load->getPointerOperand(), ConstantInt::get(integerType, 0), load->getAlign(),
                        AtomicOrdering::SequentiallyConsistent);
                }
                load->replaceAllUsesWith(FromIntegerBits(builder, result, load->getType()));
                load->eraseFromParent();
                changed = true;
                continue;
            }
            if (auto* store = dyn_cast<StoreInst>(inst); store && store->isAtomic() && isStrongerThanMonotonic(store->getOrdering())) {
                unsigned bits = AtomicWidth(layout, store->getValueOperand()->getType());
                if ((bits != 8 && bits != 16 && bits != 32 && bits != 64) || (bits < 32 && IsSectionedPointer(store->getPointerOperand()))) {
                    continue;
                }
                if (store->getAlign().value() * 8 < bits) {
                    report_fatal_error("bpf-lower-managed-atomics: atomic store is not naturally aligned");
                }
                IRBuilder<> builder(store);
                builder.SetCurrentDebugLocation(store->getDebugLoc());
                IntegerType* integerType = builder.getIntNTy(bits);
                Value* value = ToIntegerBits(builder, store->getValueOperand(), integerType);
                if (bits < 32) {
                    auto* replacement = builder.CreateAtomicRMW(
                        AtomicRMWInst::Xchg, store->getPointerOperand(), value, store->getAlign(), AtomicOrdering::SequentiallyConsistent);
                    LowerNarrowRmw(*replacement);
                } else {
                    builder.CreateAtomicRMW(AtomicRMWInst::Xchg, store->getPointerOperand(), value, store->getAlign(), AtomicOrdering::SequentiallyConsistent);
                }
                store->eraseFromParent();
                changed = true;
                continue;
            }
            if (auto* fence = dyn_cast<FenceInst>(inst)) {
                // atomic_signal_fence is a compiler barrier only. Clang emits
                // it with single-thread sync scope, which the BPF backend
                // retains as a machine barrier without emitting an
                // instruction. A system-scope C thread fence still needs a
                // real, globally ordered operation.
                if (fence->getSyncScopeID() == SyncScope::SingleThread) {
                    continue;
                }
                Module* module = function.getParent();
                GlobalVariable* word = module->getGlobalVariable(AtomicFenceName, true);
                if (!word) {
                    word = new GlobalVariable(*module, Type::getInt32Ty(module->getContext()), false, GlobalValue::InternalLinkage,
                        ConstantInt::get(Type::getInt32Ty(module->getContext()), 0), AtomicFenceName);
                    word->setAlignment(Align(4));
                    word->setSection(AtomicFenceSection);
                }
                IRBuilder<> builder(fence);
                builder.SetCurrentDebugLocation(fence->getDebugLoc());
                builder.CreateAtomicRMW(AtomicRMWInst::Xchg, word, builder.getInt32(0), Align(4), AtomicOrdering::SequentiallyConsistent);
                fence->eraseFromParent();
                changed = true;
            }
        }
        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

// Atomics are a semantic boundary, not a verifier workaround. Native wrappers
// keep genuine BPF atomics. Relaxed scalar loads/stores remain atomic too: the
// memory pass retains them through -O2 and eventually emits one naturally
// sized BPF memory instruction. Capsule operations that need an ISA RMW or a
// memory-ordering fence are rejected until they have an exact lowering. There
// is no bounded-retry lock, silent non-atomic fallback, or run-time atomic
// failure: none would implement the source language contract.
//
// A rejection here is a statement about this core, not about BPF: targets
// that grow the missing instructions can relax specific rows behind a
// pipeline/feature choice in bpf-capsule-ld without touching this policy.
struct ValidateAtomicsPass : public PassInfoMixin<ValidateAtomicsPass> {
    explicit ValidateAtomicsPass(bool managedRmw = false)
        : ManagedRmw_(managedRmw) {
    }

    bool ManagedRmw_ = false;

    static Value* PointerOperand(Instruction& inst) {
        if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
            return rmw->getPointerOperand();
        }
        if (auto* cas = dyn_cast<AtomicCmpXchgInst>(&inst)) {
            return cas->getPointerOperand();
        }
        if (auto* load = dyn_cast<LoadInst>(&inst)) {
            return load->getPointerOperand();
        }
        if (auto* store = dyn_cast<StoreInst>(&inst)) {
            return store->getPointerOperand();
        }
        return nullptr;
    }

    static bool IsCompilerFence(Instruction& inst) {
        auto* fence = dyn_cast<FenceInst>(&inst);
        return fence && fence->getSyncScopeID() == SyncScope::SingleThread;
    }

    // An explicitly sectioned global is still native kernel map storage when
    // reached from managed code. The BPF v3 ISA can therefore execute its
    // 32/64-bit integer RMWs directly; rejecting them merely because the
    // surrounding function is stackified loses both semantics and useful
    // runtime synchronization. Managed-memory RMWs are accepted separately
    // only when the linker enables their lowering and address routing.
    static bool IsNativeRmw(Instruction& inst) {
        Value* pointer = PointerOperand(inst);
        auto* global = pointer ? dyn_cast<GlobalVariable>(getUnderlyingObject(pointer)) : nullptr;
        if (!global || !global->hasSection()) {
            return false;
        }
        Type* type = nullptr;
        Align alignment(1);
        if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
            switch (rmw->getOperation()) {
                case AtomicRMWInst::Add:
                case AtomicRMWInst::And:
                case AtomicRMWInst::Or:
                case AtomicRMWInst::Xor:
                case AtomicRMWInst::Xchg:
                    type = rmw->getValOperand()->getType();
                    break;
                default:
                    return false;
            }
            alignment = rmw->getAlign();
        } else if (auto* cas = dyn_cast<AtomicCmpXchgInst>(&inst)) {
            type = cas->getCompareOperand()->getType();
            alignment = cas->getAlign();
        }
        if (!type) {
            return false;
        }
        unsigned bits = AtomicWidth(inst.getModule()->getDataLayout(), type);
        return IsIntegerWidth(type, bits) && (bits == 32 || bits == 64) && alignment.value() * 8 >= bits;
    }

    static bool IsManagedRmw(Instruction& inst) {
        Type* type = nullptr;
        Align alignment(1);
        if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
            switch (rmw->getOperation()) {
                case AtomicRMWInst::Add:
                case AtomicRMWInst::And:
                case AtomicRMWInst::Or:
                case AtomicRMWInst::Xor:
                case AtomicRMWInst::Xchg:
                    type = rmw->getValOperand()->getType();
                    break;
                default:
                    return false;
            }
            alignment = rmw->getAlign();
        } else if (auto* cas = dyn_cast<AtomicCmpXchgInst>(&inst)) {
            type = cas->getCompareOperand()->getType();
            alignment = cas->getAlign();
        }
        if (!type) {
            return false;
        }
        unsigned bits = AtomicWidth(inst.getModule()->getDataLayout(), type);
        return IsIntegerWidth(type, bits) && (bits == 32 || bits == 64) && alignment.value() * 8 >= bits;
    }

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
        if (!type->isIntegerTy() && !type->isPointerTy() && !type->isFloatingPointTy()) {
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
            if (atomic && !IsCompilerFence(inst) && !IsPreservedLoadStore(inst) && !IsNativeRmw(inst) && !(ManagedRmw_ && IsManagedRmw(inst))) {
                work.push_back(&inst);
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        for (Instruction* unsupported : work) {
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
            if ((bits == 8 || bits == 16) && IsSectionedPointer(PointerOperand(*unsupported))) {
                func.getContext().emitError(unsupported,
                    Twine("bpf-validate-atomics: sectioned i") + Twine(bits) + " atomic " + operation + " in " + func.getName() +
                        " cannot be widened without modifying adjacent map data");
                continue;
            }
            func.getContext().emitError(unsupported,
                Twine("bpf-validate-atomics: Capsule atomic ") + operation + (bits ? Twine(" i") + Twine(bits) : Twine()) + " in " + func.getName() +
                    " has no exact lowering for this target");
        }
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
                if (!ValidateAtomicsPass::IsPreservedLoadStore(inst)) {
                    func.getContext().emitError(&inst,
                        "bpf-finalize-atomic-load-store: unsupported atomic "
                        "survived validation");
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
        if (!work.empty()) {
            bpf::stats() << "bpf-finalize-atomic-load-store: " << work.size() << " accesses finalized\n";
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterAtomicsPasses(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name == "bpf-lower-managed-atomics") {
        manager.addPass(LowerManagedAtomicsPass());
        return true;
    }
    if (name == "bpf-lower-managed-atomics-fixed") {
        manager.addPass(LowerManagedAtomicsPass(false));
        return true;
    }
    if (name == "bpf-validate-atomics") {
        manager.addPass(ValidateAtomicsPass());
        return true;
    }
    if (name == "bpf-validate-managed-atomics") {
        manager.addPass(ValidateAtomicsPass(true));
        return true;
    }
    if (name == "bpf-finalize-atomic-load-store") {
        manager.addPass(FinalizeAtomicLoadStorePass());
        return true;
    }
    return false;
}
