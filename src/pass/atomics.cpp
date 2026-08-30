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

using namespace llvm;

namespace {

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
    static Value* PointerOperand(Instruction& inst) {
        if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
            return rmw->getPointerOperand();
        }
        if (auto* cas = dyn_cast<AtomicCmpXchgInst>(&inst)) {
            return cas->getPointerOperand();
        }
        return nullptr;
    }

    // An explicitly sectioned global is still native kernel map storage when
    // reached from managed code. The BPF v4 ISA can therefore execute its
    // 32/64-bit integer RMWs directly; rejecting them merely because the
    // surrounding function is stackified loses both semantics and useful
    // runtime synchronization. RMWs into capsule memory are rejected until a
    // target can be told to accept them.
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
        if (!type || !type->isIntegerTy()) {
            return false;
        }
        unsigned bits = type->getIntegerBitWidth();
        return (bits == 32 || bits == 64) && alignment.value() * 8 >= bits;
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
            if (atomic && !IsPreservedLoadStore(inst) && !IsNativeRmw(inst)) {
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
    if (name == "bpf-validate-atomics") {
        manager.addPass(ValidateAtomicsPass());
        return true;
    }
    if (name == "bpf-finalize-atomic-load-store") {
        manager.addPass(FinalizeAtomicLoadStorePass());
        return true;
    }
    return false;
}
