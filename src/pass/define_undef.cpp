// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "define_undef.h"

#include "common.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// ---------------------------------------------------------------------------
// bpf-define-undef: the verifier rejects any read of an uninitialized
// register, but LLVM happily materializes undef/poison — fix-irreducible in
// particular fills its guard PHIs with poison on paths where the value is not
// used. Poison permits any value, so replacing it with zero is a refinement.
// ---------------------------------------------------------------------------

class DefineUndefPass : public PassInfoMixin<DefineUndefPass> {
public:
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        unsigned changes = 0;

        // Native entries and scalar islands have no implicit current Capsule
        // fiber. Stackify deliberately keeps terminating managed helpers out
        // of islands; diagnose any remaining native source trap instead of
        // silently attributing it to fiber zero.
        if (!bpf::IsCapsuleFunction(func) && !func.getMetadata(bpf::md::AllocationUnit)) {
            for (Instruction& instruction : instructions(func)) {
                auto* call = dyn_cast<CallInst>(&instruction);
                bool trap = call && (call->getIntrinsicID() == Intrinsic::trap || call->getIntrinsicID() == Intrinsic::debugtrap);
                if (trap || isa<UnreachableInst>(instruction)) {
                    func.getContext().emitError(
                        &instruction, Twine("bpf-define-undef: native function ") + func.getName() + " has no Capsule fiber for a trap");
                    return PreservedAnalyses::all();
                }
            }
        }

        // `unreachable` is a promise the compiler made to itself, and the
        // backend turns it into a call to __bpf_trap, which the kernel
        // refuses to load ("unexpected __bpf_trap()"). The promise does not
        // always hold once whole paths have been rewritten, so each one
        // becomes an abort with its own code and an ordinary return: if the
        // program really does get there, it stops and says so.
        // llvm.trap lowers to the same refused __bpf_trap call (Rust emits it
        // for cold aborts); it conveys nothing an abort code does not.
        for (CallInst* trap : bpf::FirstTrapCalls(func)) {
            bpf::TerminateWithOutcome(*trap, ConstantInt::get(Type::getInt64Ty(func.getContext()), bpf::OutcomeValue(CAPSULE_ERROR_TRAP)));
            ++changes;
        }

        SmallVector<UnreachableInst*> traps;
        for (auto&& block : func) {
            if (auto* un = dyn_cast<UnreachableInst>(block.getTerminator())) {
                traps.push_back(un);
            }
        }
        for (auto* un : traps) {
            bpf::TerminateWithOutcome(*un, ConstantInt::get(Type::getInt64Ty(func.getContext()), bpf::OutcomeValue(CAPSULE_ERROR_UNREACHABLE)));
            ++changes;
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
                ++changes;
            }
        }
        if (changes) {
            bpf::stats() << "bpf-define-undef: " << changes << " traps or undefined values made explicit\n";
        }
        return changes ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // namespace

bool RegisterDefineUndefPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-define-undef") {
        return false;
    }
    manager.addPass(DefineUndefPass());
    return true;
}
