// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-capsule-domains: assign every defined function and global to exactly
// one execution domain and reject accidental sharing.
//
// Native code (entry programs and their ordinary callees) runs on the real
// BPF stack and is verified directly; Capsule code (the closure behind a
// capsule_call boundary) is stackified onto the software stack. The same
// body cannot be both, so a function reachable from both domains — and an
// unsectioned global used by both — is a compile error rather than a silent
// clone or a silently forked variable. The verdict is published as
// bpf.native / bpf.capsule metadata, which every later pass consumes.
//
// Runs twice: once right after the boundary is lowered, and again after
// default<O2>, because inlining and DCE reshape reachability and the labels
// must describe the graph stackify actually sees.
#include "capsule_domains.h"

#include "common.h"
#include "runtime_symbols.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/ErrorHandling.h>

using namespace llvm;

namespace {

bool IsCompilerDriver(const Function& func) {
    return bpf::HasFunctionClass(func, bpf::cls::Trampoline);
}

bool IsBoundaryCall(const CallBase& call) {
    return call.getOperandBundle(bpf::md::CallBundle).has_value();
}

void AddIndirectTargets(Module& module, CallBase& call, SmallVectorImpl<Function*>& work) {
    FunctionType* wanted = call.getFunctionType();
    for (Function& candidate : module) {
        if (candidate.isDeclaration() || bpf::IsEntryProgram(candidate) || IsCompilerDriver(candidate) || candidate.getFunctionType() != wanted) {
            continue;
        }
        // A direct-only function cannot be the value in this indirect call.
        if (!candidate.hasAddressTaken(nullptr, /*IgnoreCallbackUses=*/false,
                /*IgnoreAssumeLikeCalls=*/true,
                /*IgnoreLLVMUsed=*/true)) {
            continue;
        }
        work.push_back(&candidate);
    }
}

void AddReferencedFunctions(Value* value, SmallVectorImpl<Function*>& work, SmallPtrSetImpl<Value*>& seen) {
    if (!seen.insert(value).second) {
        return;
    }
    if (auto* function = dyn_cast<Function>(value->stripPointerCasts())) {
        if (!function->isDeclaration()) {
            work.push_back(function);
        }
        return;
    }
    // Function pointers commonly cross a library API as ordinary callback
    // arguments (job queues, dispatch tables), rather than appearing as the
    // callee of an indirect call in the same function. Follow functions
    // nested in constant tables/casts too so the Capsule closure owns the code
    // whose address it exports.
    if (auto* constant = dyn_cast<Constant>(value)) {
        for (Value* operand : constant->operands()) {
            AddReferencedFunctions(operand, work, seen);
        }
    }
}

bool Reach(Module& module, ArrayRef<Function*> roots, bool native, SmallPtrSetImpl<Function*>& reached) {
    SmallVector<Function*> work(roots.begin(), roots.end());
    while (!work.empty()) {
        Function* func = work.pop_back_val();
        if (!func || func->isDeclaration() || !reached.insert(func).second) {
            continue;
        }
        for (Instruction& inst : instructions(*func)) {
            auto* call = dyn_cast<CallBase>(&inst);
            if (call && IsBoundaryCall(*call)) {
                if (!native) {
                    func->getContext().emitError(call,
                        Twine("bpf-capsule-domains: capsule_call inside Capsule "
                              "function ") +
                            func->getName());
                    return false;
                }
                // The target and arguments are the other side of this explicit
                // domain edge; do not accidentally pull their function
                // constants back into the native closure.
                continue;
            }
            SmallPtrSet<Value*, 8> seenValues;
            for (Value* operand : inst.operands()) {
                AddReferencedFunctions(operand, work, seenValues);
            }
            if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                continue;
            }
            if (Function* callee = call->getCalledFunction()) {
                if (!callee->isDeclaration()) {
                    work.push_back(callee);
                }
            } else if (!isa<Constant>(call->getCalledOperand())) {
                // A numbered BPF helper is represented as a call through a
                // constant inttoptr. It is not an indirect C call and cannot
                // target any address-taken function in this module.
                AddIndirectTargets(module, *call, work);
            }
        }
    }
    return true;
}

void FindGlobalOwners(
    GlobalVariable& global, const SmallPtrSetImpl<Function*>& native, const SmallPtrSetImpl<Function*>& capsule, bool& usedNative, bool& usedCapsule) {
    SmallVector<User*> work(global.user_begin(), global.user_end());
    SmallPtrSet<User*, 32> seen;
    while (!work.empty()) {
        User* user = work.pop_back_val();
        if (!seen.insert(user).second) {
            continue;
        }
        if (auto* inst = dyn_cast<Instruction>(user)) {
            Function* owner = inst->getFunction();
            usedNative |= native.contains(owner);
            usedCapsule |= capsule.contains(owner);
            continue;
        }
        for (User* next : user->users()) {
            work.push_back(next);
        }
    }
}

struct CapsuleDomainsPass : public PassInfoMixin<CapsuleDomainsPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        bpf::MaterializeFunctionClasses(module);
        SmallVector<Function*> nativeRoots;
        SmallVector<Function*> capsuleRoots;
        for (Function& func : module) {
            func.setMetadata(bpf::md::Native, nullptr);
            func.setMetadata(bpf::md::Capsule, nullptr);
            if (bpf::IsEntryProgram(func)) {
                nativeRoots.push_back(&func);
            }
            for (Instruction& inst : instructions(func)) {
                auto* call = dyn_cast<CallBase>(&inst);
                if (!call || !IsBoundaryCall(*call)) {
                    continue;
                }
                Function* root = call->getCalledFunction();
                if (!root) {
                    report_fatal_error("bpf-capsule-domains: capsule boundary lost its static target");
                }
                capsuleRoots.push_back(root);
            }
        }

        // The throw marker is itself a managed-only boundary. Its immediate
        // wrapper may be an otherwise-unreferenced libc/language-runtime
        // symbol such as abort(), so ordinary forward reachability need not
        // discover it before GlobalDCE. Seed the direct caller into the
        // Capsule domain (bpf-lower-capsule-exit lowers it afterwards). If a
        // native entry actually reaches that caller, the normal
        // domain-overlap diagnostic below rejects the program instead of
        // emitting a native call into managed control state.
        if (Function* marker = module.getFunction(bpf::sym::ExitMarker)) {
            for (User* user : marker->users()) {
                auto* call = dyn_cast<CallBase>(user);
                if (call && call->getCalledOperand()->stripPointerCasts() == marker) {
                    capsuleRoots.push_back(call->getFunction());
                }
            }
        }

        SmallPtrSet<Function*, 32> native;
        SmallPtrSet<Function*, 32> capsule;
        if (!Reach(module, nativeRoots, /*native=*/true, native)) {
            return PreservedAnalyses::all();
        }

        // A function whose address survives the normal optimizer is part of an
        // opaque callback/table surface. LLVM cannot, in general, recover
        // which indirect load will call it (interpreters keep jobs and
        // builtins in such tables). If native reachability did not already
        // claim it, conservatively place it and its forward closure in the
        // Capsule domain. This keeps the partition exact at the native
        // boundary without workload-specific callback discovery.
        for (Function& func : module) {
            if (!func.isDeclaration() && !bpf::IsEntryProgram(func) && !IsCompilerDriver(func) &&
                func.hasAddressTaken(nullptr, /*IgnoreCallbackUses=*/false,
                    /*IgnoreAssumeLikeCalls=*/true,
                    /*IgnoreLLVMUsed=*/true) &&
                !native.contains(&func)) {
                capsuleRoots.push_back(&func);
            }
        }
        if (!Reach(module, capsuleRoots, /*native=*/false, capsule)) {
            return PreservedAnalyses::all();
        }

        for (Function* func : capsule) {
            if (native.contains(func)) {
                func->getContext().emitError(Twine("bpf-capsule-domains: function ") + func->getName() +
                    " is reachable from both native code and a "
                    "capsule_call; split the shared code explicitly");
                return PreservedAnalyses::all();
            }
        }

        MDNode* empty = MDNode::get(module.getContext(), {});
        for (Function* func : native) {
            func->setMetadata(bpf::md::Native, empty);
        }
        for (Function* func : capsule) {
            func->setMetadata(bpf::md::Capsule, empty);
        }

        for (GlobalVariable& global : module.globals()) {
            global.setMetadata(bpf::md::Native, nullptr);
            global.setMetadata(bpf::md::Capsule, nullptr);
            if (global.isDeclaration() || global.getName().starts_with("llvm.")) {
                continue;
            }
            bool usedNative = false;
            bool usedCapsule = false;
            FindGlobalOwners(global, native, capsule, usedNative, usedCapsule);
            if (usedNative && usedCapsule && !global.hasSection()) {
                global.getContext().emitError(Twine("bpf-capsule-domains: unsectioned global ") + global.getName() +
                    " is shared by native and Capsule code; put "
                    "deliberately shared storage in an ELF section");
                return PreservedAnalyses::all();
            }
            if (usedNative) {
                global.setMetadata(bpf::md::Native, empty);
            }
            if (usedCapsule) {
                global.setMetadata(bpf::md::Capsule, empty);
            }
        }

        bpf::stats() << "bpf-capsule-domains: " << native.size() << " native, " << capsule.size() << " Capsule functions\n";
        return PreservedAnalyses::all();
    }
};

} // namespace

bool RegisterCapsuleDomainsPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-capsule-domains") {
        return false;
    }
    manager.addPass(CapsuleDomainsPass());
    return true;
}
