// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "lower_arena_sext.h"

#include "common.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// ---------------------------------------------------------------------------
// bpf-lower-arena-sext: CPU v4 can fold a narrow load used by any signed
// operation (not only an explicit IR sext) into BPF_MEMSX, a load mode some
// target verifiers reject from arena pointers. Put a zero-cost,
// side-effecting compiler barrier after each narrow arena load: selection
// then emits BPF_MEM followed by any required register sign extension.
// bpf-capsule-ld includes this pass in the pipeline only for targets that
// need it — the pass itself is unconditional. It is intentionally late,
// after address-space inference, so only actual PTR_TO_ARENA loads are
// affected and no later IR optimizer can fold them back.
// ---------------------------------------------------------------------------

class LowerArenaSignedLoadsPass : public PassInfoMixin<LowerArenaSignedLoadsPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
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
        if (!work.empty()) {
            bpf::stats() << "bpf-lower-arena-sext: " << work.size() << " narrow arena loads fenced\n";
        }
        return work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterLowerArenaSignedLoadsPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-lower-arena-sext") {
        return false;
    }
    manager.addPass(LowerArenaSignedLoadsPass());
    return true;
}
