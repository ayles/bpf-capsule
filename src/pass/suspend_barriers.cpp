// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-add/remove-suspend-barriers: fence the O2 run against illegal code
// motion across managed calls.
//
// During O2, Capsule functions are ordinary IR and FunctionAttrs proves a
// small managed leaf `memory(none) willreturn` bottom-up. Every rule the
// optimizer has then says calls to it are transparent: GVN may CSE a
// readonly BPF helper (map lookup) across one, LICM may hoist loads over
// it, and an unused "pure" call may be deleted outright. After stackify all
// of that is wrong — every managed call is a suspension point, execution
// may resume in a different BPF program invocation, and neither a verifier
// capability's liveness may be extended across it nor the call itself
// removed (it mutates fiber state that only exists post-stackify). The
// optimizer can thereby manufacture violations from legal source: a fresh
// post-call lookup CSE'd into a pre-call pointer is a stale capability in
// the next invocation.
//
// The mechanism: plant a call to an external, UNDEFINED marker in the entry
// block of every Capsule function. An unknowable call may touch any memory
// and may not return, so bottom-up inference can never prove a Capsule
// function pure — every call into Capsule code becomes a full memory fence
// in LLVM's own legality model. Entry-block-per-function rather than
// per-call-site: the poison is transitive up the call graph for free,
// covers indirect calls (whose sites cannot be enumerated), and costs one
// instruction per function.
//
// Cost model: the fence blocks memory optimization only — SSA scalar
// dataflow crosses managed calls untouched — and each blocked edge sits
// next to a dispatcher round trip that dwarfs the reload it preserves.
// Making it narrower is hard by construction: LLVM's effect system has no
// way to say "invalidates verifier capabilities", and fencing only the
// calls that really suspend is circular — stackify decides suspension
// later, and here every managed call suspends. A finer fence only becomes
// meaningful for callees proven non-suspending before O2.
//
// The remove pass deletes the zero-runtime-cost markers once generic
// optimization is over; stackify must never see them (an unresolved call
// in managed code would be rejected). The fence therefore spans exactly
// the default<O2> stage, which is visible in the pipeline string.
#include "suspend_barriers.h"

#include "common.h"
#include "runtime_symbols.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/ErrorHandling.h>

using namespace llvm;

namespace {

struct AddSuspendBarriersPass : public PassInfoMixin<AddSuspendBarriersPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        Function* barrier = module.getFunction(bpf::sym::SuspendBarrier);
        if (barrier && !barrier->isDeclaration()) {
            report_fatal_error(Twine("bpf-add-suspend-barriers: reserved function is defined: ") + bpf::sym::SuspendBarrier);
        }
        SmallVector<Function*> capsule;
        for (Function& function : module) {
            if (!function.empty() && bpf::IsCapsuleFunction(function)) {
                capsule.push_back(&function);
            }
        }
        if (capsule.empty()) {
            return PreservedAnalyses::all();
        }
        if (!barrier) {
            barrier = Function::Create(
                FunctionType::get(Type::getVoidTy(module.getContext()), false), GlobalValue::ExternalLinkage, bpf::sym::SuspendBarrier, module);
        }
        for (Function* function : capsule) {
            IRBuilder<> builder(&*function->getEntryBlock().getFirstInsertionPt());
            builder.CreateCall(barrier);
        }
        bpf::stats() << "bpf-add-suspend-barriers: " << capsule.size() << " functions fenced\n";
        return PreservedAnalyses::none();
    }
};

struct RemoveSuspendBarriersPass : public PassInfoMixin<RemoveSuspendBarriersPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        Function* barrier = module.getFunction(bpf::sym::SuspendBarrier);
        if (!barrier) {
            return PreservedAnalyses::all();
        }
        SmallVector<CallBase*> calls;
        for (User* user : barrier->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledOperand()->stripPointerCasts() != barrier) {
                report_fatal_error(Twine("bpf-remove-suspend-barriers: address of ") + bpf::sym::SuspendBarrier + " escapes");
            }
            calls.push_back(call);
        }
        for (CallBase* call : calls) {
            call->eraseFromParent();
        }
        barrier->eraseFromParent();
        bpf::stats() << "bpf-remove-suspend-barriers: " << calls.size() << " barriers removed\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterSuspendBarrierPasses(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name == "bpf-add-suspend-barriers") {
        manager.addPass(AddSuspendBarriersPass());
        return true;
    }
    if (name == "bpf-remove-suspend-barriers") {
        manager.addPass(RemoveSuspendBarriersPass());
        return true;
    }
    return false;
}
