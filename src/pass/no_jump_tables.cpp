// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "no_jump_tables.h"

#include "common.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// Wide switches — the trampoline's allocation-unit dispatch is one in every
// program — must not become .jumptables indirect jumps: this pass runs for
// targets without a working insn-array flow (BPF_MAP_TYPE_INSN_ARRAY,
// PTR_TO_INSN, libbpf relocation, the base+index lowering). The attribute
// travels in the bitcode, so every llc invocation lowers switches as compare
// trees without needing backend flags. Runs after stackify: the trampoline
// and step functions must already exist to be stamped.
struct NoJumpTablesPass : public PassInfoMixin<NoJumpTablesPass> {
    PreservedAnalyses run(Function& func, FunctionAnalysisManager&) {
        Attribute existing = func.getFnAttribute("no-jump-tables");
        if (existing.isStringAttribute() && existing.getValueAsString() == "true") {
            return PreservedAnalyses::all();
        }
        func.addFnAttr("no-jump-tables", "true");
        bpf::stats() << "bpf-no-jump-tables: disabled jump tables in " << func.getName() << "\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterNoJumpTablesPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-no-jump-tables") {
        return false;
    }
    manager.addPass(NoJumpTablesPass());
    return true;
}
