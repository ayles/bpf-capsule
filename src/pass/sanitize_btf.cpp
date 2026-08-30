// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "sanitize_btf.h"

#include "common.h"

#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

#include <cctype>
#include <string>

using namespace llvm;

namespace {

// Kernel BTF accepts only C identifiers, but Rust debug info names types
// like `<core::fmt::Error as core::fmt::Debug>::{vtable_type}` and functions
// like `grow_amortized<alloc::alloc::Global>`. One invalid name makes the
// kernel reject the WHOLE .BTF, libbpf then loads without func_info, every
// subprogram silently becomes static, and the verifier walks the trampoline
// dispatch until "8193 jumps is too complex". Sanitize every BTF-visible
// debug-info name to [A-Za-z0-9_].
struct SanitizeBtfNamesPass : public PassInfoMixin<SanitizeBtfNamesPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        unsigned changes = 0;
        DebugInfoFinder finder;
        finder.processModule(module);
        auto fix = [&](DINode* node, MDString* raw) {
            if (!raw) {
                return;
            }
            StringRef name = raw->getString();
            if (name.empty() || llvm::all_of(name, [](char c) { return isalnum((unsigned char)c) || c == '_'; })) {
                return;
            }
            std::string clean = name.str();
            for (auto&& c : clean) {
                if (!isalnum((unsigned char)c) && c != '_') {
                    c = '_';
                }
            }
            MDString* neat = MDString::get(module.getContext(), clean);
            for (unsigned i = 0; i < node->getNumOperands(); i++) {
                if (node->getOperand(i).get() == raw) {
                    node->replaceOperandWith(i, neat);
                    ++changes;
                }
            }
        };
        for (DIType* type : finder.types()) {
            if (auto* comp = dyn_cast<DICompositeType>(type)) {
                fix(comp, comp->getRawName());
            } else if (auto* derived = dyn_cast<DIDerivedType>(type)) {
                fix(derived, derived->getRawName());
            }
        }
        for (DISubprogram* sp : finder.subprograms()) {
            fix(sp, sp->getRawName());
        }
        for (auto&& func : module) {
            if (DISubprogram* sp = func.getSubprogram()) {
                fix(sp, sp->getRawName());
            }
        }
        for (DIGlobalVariableExpression* gve : finder.global_variables()) {
            if (auto* gv = gve->getVariable()) {
                fix(gv, gv->getRawName());
            }
        }
        // The kernel also rejects the whole .BTF when any FUNC's prototype
        // has an unnamed argument ("Invalid arg#N") — same silent
        // degradation as an invalid name. BTF argument names come from the
        // subprogram's retained parameter variables, so a pass that rebuilds
        // a subprogram without recreating them (or a body whose records were
        // dropped) yields anonymous arguments. Guarantee every prototype
        // position a named parameter variable, synthesizing `a<N>` when one
        // is missing or unnamed.
        if (!module.debug_compile_units().empty()) {
            DIBuilder db(module, false, *module.debug_compile_units_begin());
            for (auto&& func : module) {
                DISubprogram* sp = func.getSubprogram();
                if (!sp || !sp->getType()) {
                    continue;
                }
                DITypeArray types = sp->getType()->getTypeArray();
                if (types.size() <= 1) {
                    continue;
                }
                unsigned params = types.size() - 1;
                SmallVector<DILocalVariable*, 8> byPosition(params + 1, nullptr);
                SmallVector<Metadata*> keep;
                for (MDNode* node : sp->getRetainedNodes()) {
                    auto* var = dyn_cast<DILocalVariable>(node);
                    if (var && var->isParameter() && var->getArg() <= params) {
                        byPosition[var->getArg()] = var;
                    }
                    keep.push_back(node);
                }
                bool repair = false;
                for (unsigned i = 1; i <= params; i++) {
                    if (!byPosition[i] || byPosition[i]->getName().empty()) {
                        repair = true;
                    }
                }
                if (!repair) {
                    continue;
                }
                SmallVector<Metadata*> retained;
                for (Metadata* node : keep) {
                    auto* var = dyn_cast<DILocalVariable>(node);
                    if (var && var->isParameter() && var->getArg() <= params && var->getName().empty()) {
                        continue; // replaced below with a named variable
                    }
                    retained.push_back(node);
                }
                for (unsigned i = 1; i <= params; i++) {
                    if (byPosition[i] && !byPosition[i]->getName().empty()) {
                        continue;
                    }
                    DIType* type = types[i];
                    if (!type) {
                        type = db.createBasicType("int", 32, dwarf::DW_ATE_signed);
                    }
                    retained.push_back(db.createParameterVariable(sp, "a" + Twine(i - 1).str(), i, sp->getFile(), 0, type, true));
                }
                sp->replaceRetainedNodes(MDNode::get(module.getContext(), retained));
                ++changes;
            }
            db.finalize();
        }

        // Upstream optimizers (rustc's own release pipeline) split globals
        // into fragments while both halves keep the ORIGINAL variable's
        // debug info. The BTF emitter ignores fragment expressions, so the
        // datasec entry claims the full type's size for a half-sized global
        // and the kernel rejects the whole .BTF ("Invalid size"). A debug
        // attachment that no longer matches its global is worse than none.
        const DataLayout& dl = module.getDataLayout();
        for (auto&& g : module.globals()) {
            SmallVector<DIGlobalVariableExpression*> attachments;
            g.getDebugInfo(attachments);
            if (attachments.empty() || !g.getValueType()->isSized()) {
                continue;
            }
            bool bad = false;
            uint64_t bytes = dl.getTypeAllocSize(g.getValueType());
            for (auto* gve : attachments) {
                if (gve->getExpression() && gve->getExpression()->getNumElements()) {
                    bad = true;
                }
                DIType* type = gve->getVariable() ? gve->getVariable()->getType() : nullptr;
                if (type && type->getSizeInBits() && type->getSizeInBits() != bytes * 8) {
                    bad = true;
                }
            }
            if (bad) {
                g.eraseMetadata(module.getContext().getMDKindID("dbg"));
                ++changes;
            }
        }
        if (changes) {
            bpf::stats() << "bpf-sanitize-btf: " << changes << " debug records repaired\n";
        }
        return changes ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // namespace

bool RegisterSanitizeBtfNamesPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-sanitize-btf") {
        return false;
    }
    manager.addPass(SanitizeBtfNamesPass());
    return true;
}
