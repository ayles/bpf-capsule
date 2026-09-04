// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-internalize: close the linked guest image after O2 so the
// following domain analysis and GlobalDCE see its real reachable surface.
#include "internalize.h"

#include "common.h"
#include "runtime_symbols.h"
#include "target.h"

#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/Module.h>

using namespace llvm;

PreservedAnalyses InternalizePass::run(Module& module, ModuleAnalysisManager&) {
    // Runtime routines a program never calls still cost verification: the
    // C library's public symbols keep external linkage, which shields them —
    // and everything they call — from O2's DCE. Each survivor becomes a
    // managed function the verifier must check. After this point nothing can
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
    unsigned internalizedFunctions = 0;
    for (auto&& func : module) {
        if (!func.isDeclaration() && !isAbi(func)) {
            internalizedFunctions += !func.hasInternalLinkage();
            func.setLinkage(GlobalValue::InternalLinkage);
        }
    }

    // At this point the link is complete. Unsectioned globals and aliases
    // therefore have no external consumer left either. Keep sectioned values:
    // maps and entry-visible data are part of the loaded-object ABI.
    unsigned internalizedGlobals = 0;
    for (GlobalVariable& global : module.globals()) {
        if (!global.isDeclaration() && !global.hasSection()) {
            internalizedGlobals += !global.hasInternalLinkage();
            global.setLinkage(GlobalValue::InternalLinkage);
        }
    }
    unsigned internalizedAliases = 0;
    for (GlobalAlias& alias : module.aliases()) {
        GlobalObject* object = alias.getAliaseeObject();
        bool abi = object && object->hasSection();
        if (auto* function = dyn_cast_or_null<Function>(object)) {
            abi |= isAbi(*function);
        }
        if (!abi) {
            internalizedAliases += !alias.hasInternalLinkage();
            alias.setLinkage(GlobalValue::InternalLinkage);
        }
    }
    if (internalizedFunctions || internalizedGlobals || internalizedAliases) {
        bpf::stats() << "bpf-internalize: " << internalizedFunctions << " functions, " << internalizedGlobals << " globals and " << internalizedAliases
                     << " aliases internalized\n";
    }
    return internalizedFunctions || internalizedGlobals || internalizedAliases ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool RegisterInternalizePass(StringRef name, ModulePassManager& manager) {
    if (name != "bpf-internalize") {
        return false;
    }
    manager.addPass(InternalizePass());
    return true;
}
