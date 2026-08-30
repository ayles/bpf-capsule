// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-internalize: close the linked freestanding image after O2 so the
// following domain analysis and GlobalDCE see its real reachable surface.
#include "internalize.h"

#include "common.h"
#include "runtime_symbols.h"
#include "target.h"

#include <llvm/IR/Module.h>

using namespace llvm;

PreservedAnalyses InternalizePass::run(Module& module, ModuleAnalysisManager&) {
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
    bpf::MaterializeFunctionClasses(module);
    auto isAbi = [](Function& f) {
        return f.hasSection() || // entry programs, .ksyms
            bpf::HasFunctionClass(f, bpf::cls::Trampoline) || bpf::HasFunctionClass(f, bpf::cls::HeapAccessor) ||
            // Nosuspend leaves must stay external: each is a global
            // subprogram the verifier checks exactly once.
            bpf::HasFunctionClass(f, bpf::cls::NoSuspend);
    };
    unsigned internalized = 0;
    for (auto&& func : module) {
        if (!func.isDeclaration() && !isAbi(func)) {
            internalized += !func.hasInternalLinkage();
            func.setLinkage(GlobalValue::InternalLinkage);
        }
    }
    if (internalized) {
        bpf::stats() << "bpf-internalize: " << internalized << " definitions internalized\n";
    }
    return internalized ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool RegisterInternalizePass(StringRef name, ModulePassManager& manager) {
    if (name != "bpf-internalize") {
        return false;
    }
    manager.addPass(InternalizePass());
    return true;
}
