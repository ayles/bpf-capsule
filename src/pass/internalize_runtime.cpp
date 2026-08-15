// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-internalize-runtime: close the linked freestanding image after O2 so the
// following domain analysis and GlobalDCE see its real reachable surface.
#include "internalize_runtime.h"
#include "common.h"
#include "target.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>

using namespace llvm;

namespace {

bool UsesFloatingPoint(Function& func) {
    auto isFp = [](Type* type) { return type->isFPOrFPVectorTy(); };
    if (isFp(func.getReturnType())) {
        return true;
    }
    for (auto&& arg : func.args()) {
        if (isFp(arg.getType())) {
            return true;
        }
    }
    for (auto&& inst : instructions(func)) {
        if (isFp(inst.getType())) {
            return true;
        }
        for (auto&& op : inst.operands()) {
            if (isFp(op->getType())) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

PreservedAnalyses InternalizeRuntimePass::run(Module& module, ModuleAnalysisManager&) {
    // Runtime routines a program never calls still cost verification: the
    // freestanding libc's public symbols (exp, log, the soft-float family)
    // keep external linkage, which shields them — and everything they call —
    // from O2's DCE. Each survivor becomes a managed function the verifier
    // must check, and the branchiest (soft-float division and the math
    // series built on it) burn the whole million-instruction budget when
    // validated against unknown arguments. After this point nothing can
    // introduce new uses, so internalize everything that is not part of the
    // load-time ABI. The existing GlobalDCE stage then removes the dead set;
    // this pass does not duplicate that reachability algorithm.
    auto isAbi = [](Function& f) {
        return f.hasSection() || // entry programs, .ksyms
            f.getName().starts_with("__bpf_capsule_trampoline") || f.getName().starts_with("bpf_heap_") ||
            // Unmanaged runtime leaves must stay external: each is a
            // global subprogram the verifier checks exactly once.
            bpf::IsUnmanagedRuntime(f.getName());
    };
    unsigned internalized = 0;
    for (auto&& func : module) {
        if (!func.isDeclaration() && !isAbi(func)) {
            internalized += !func.hasInternalLinkage();
            func.setLinkage(GlobalValue::InternalLinkage);
        }
    }
    // bpf-soft-float owns the complete scalar f32/f64 lowering contract. A
    // survivor here is a compiler bug, not a second run-time FP policy.
    for (auto&& func : module) {
        if (!func.isDeclaration() && UsesFloatingPoint(func)) {
            func.getContext().emitError(Twine("bpf-internalize-runtime: floating point survived software lowering in ") + func.getName());
            return PreservedAnalyses::none();
        }
    }
    if (internalized) {
        bpf::stats() << "bpf-internalize-runtime: " << internalized << " definitions internalized\n";
    }
    return internalized ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
