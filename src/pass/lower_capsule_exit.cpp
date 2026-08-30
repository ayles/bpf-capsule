// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-lower-capsule-exit: managed code cannot "exit" a kernel program.
// Termination means publish the encoded outcome word and return to the
// trampoline, so the drive loop stops. A source language may still require
// its panic/throw routine to have a `noreturn` type, so after replacing each
// __bpf_capsule_exit marker or managed llvm.trap/debugtrap with store+ret,
// the direct noreturn wrapper chain above it (abort() -> panic() -> ...) is reopened: every
// `call wrapper; unreachable` becomes `call; ret`, transitively, but only
// through source-noreturn wrappers — an ordinary function with a conditional
// abort path still returns normally on its other paths. Traps must be lowered
// here, before O2: otherwise FunctionAttrs can infer a Capsule root as
// `noreturn` and delete the native boundary's result handling. Unrelated LLVM
// `unreachable` promises retain their late raw-unreachable handling.
//
// Runs after bpf-capsule-domains: the marker is only legal in Capsule code,
// and the domain labels are how that is checked.
#include "lower_capsule_exit.h"

#include "common.h"
#include "runtime_symbols.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>

using namespace llvm;

namespace {

struct LowerCapsuleExitPass : public PassInfoMixin<LowerCapsuleExitPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        Function* marker = module.getFunction(bpf::sym::ExitMarker);
        if (marker &&
            (!marker->isDeclaration() || marker->isVarArg() || marker->arg_size() != 1 || !marker->getReturnType()->isVoidTy() ||
                !marker->getArg(0)->getType()->isIntegerTy(32))) {
            module.getContext().emitError(Twine("bpf-lower-capsule-exit: malformed ") + bpf::sym::ExitMarker + " marker");
            return PreservedAnalyses::all();
        }

        SmallPtrSet<Function*, 32> capsule;
        SmallVector<Function*> capsuleFunctions; // module order, for stable iteration
        for (Function& function : module) {
            if (bpf::IsCapsuleFunction(function)) {
                capsule.insert(&function);
                capsuleFunctions.push_back(&function);
            }
        }

        SmallVector<CallInst*> calls;
        if (marker) {
            for (User* user : marker->users()) {
                auto* call = dyn_cast<CallInst>(user);
                if (!call || call->getCalledOperand()->stripPointerCasts() != marker || !capsule.contains(call->getFunction())) {
                    module.getContext().emitError(Twine("bpf-lower-capsule-exit: ") + bpf::sym::ExitMarker + " must be called directly from managed code");
                    return PreservedAnalyses::all();
                }
                calls.push_back(call);
            }
        }

        SmallPtrSet<Function*, 16> terminating;
        for (CallInst* call : calls) {
            Function* owner = call->getFunction();
            bool ownerIsNoReturn = owner->hasFnAttribute(Attribute::NoReturn);
            IRBuilder<> builder(call);
            bpf::TerminateWithOutcome(*call, bpf::BuildOutcomeValue(builder, call->getArgOperand(0)));
            if (ownerIsNoReturn) {
                terminating.insert(owner);
            }
        }
        if (marker) {
            marker->eraseFromParent();
        }

        // Lower the first trap in each managed block. Anything after it is
        // semantically dead and TerminateWithOutcome removes the suffix, so
        // collecting later traps in the same block would leave stale pointers.
        SmallVector<CallInst*> trapCalls;
        for (Function* function : capsuleFunctions) {
            auto traps = bpf::FirstTrapCalls(*function);
            trapCalls.append(traps.begin(), traps.end());
        }
        for (CallInst* call : trapCalls) {
            Function* owner = call->getFunction();
            bool ownerIsNoReturn = owner->hasFnAttribute(Attribute::NoReturn);
            bpf::TerminateWithOutcome(*call, ConstantInt::get(Type::getInt64Ty(module.getContext()), bpf::OutcomeValue(CAPSULE_ERROR_TRAP)));
            if (ownerIsNoReturn) {
                terminating.insert(owner);
            }
        }

        bool progress;
        do {
            progress = false;
            for (Function* function : capsuleFunctions) {
                bool functionIsNoReturn = function->hasFnAttribute(Attribute::NoReturn);
                bool rewroteCall = false;
                for (BasicBlock& block : *function) {
                    auto* unreachable = dyn_cast<UnreachableInst>(block.getTerminator());
                    Instruction* previous = unreachable ? unreachable->getPrevNode() : nullptr;
                    while (auto* intrinsic = dyn_cast_or_null<IntrinsicInst>(previous)) {
                        if (!intrinsic->isLifetimeStartOrEnd() && !isa<DbgInfoIntrinsic>(intrinsic)) {
                            break;
                        }
                        previous = previous->getPrevNode();
                    }
                    auto* call = dyn_cast_or_null<CallBase>(previous);
                    Function* callee = call ? call->getCalledFunction() : nullptr;
                    if (!callee || !terminating.contains(callee)) {
                        continue;
                    }
                    call->removeFnAttr(Attribute::NoReturn);
                    IRBuilder<> builder(unreachable);
                    if (function->getReturnType()->isVoidTy()) {
                        builder.CreateRetVoid();
                    } else {
                        builder.CreateRet(Constant::getNullValue(function->getReturnType()));
                    }
                    function->removeFnAttr(Attribute::NoReturn);
                    unreachable->eraseFromParent();
                    rewroteCall = true;
                    progress = true;
                }
                // Only a source-level noreturn function can extend the wrapper
                // chain. An ordinary function may have several conditional
                // calls to a terminating wrapper and still return on another
                // path; all those call sites need reopening, but its callers
                // must not be treated as non-returning.
                if (rewroteCall && functionIsNoReturn) {
                    terminating.insert(function);
                }
            }
        } while (progress);

        if (calls.empty() && trapCalls.empty()) {
            return PreservedAnalyses::all();
        }
        bpf::stats() << "bpf-lower-capsule-exit: " << calls.size() << " capsule_exit sites, " << trapCalls.size() << " trap sites\n";
        if (verifyModule(module, &errs())) {
            module.getContext().emitError("bpf-lower-capsule-exit produced an invalid module");
        }
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterLowerCapsuleExitPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-lower-capsule-exit") {
        return false;
    }
    manager.addPass(LowerCapsuleExitPass());
    return true;
}
