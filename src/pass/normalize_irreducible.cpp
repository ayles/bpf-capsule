// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "normalize_irreducible.h"

#include "common.h"

#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/CycleAnalysis.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

using namespace llvm;

namespace {

// LLVM's FixIrreduciblePass can redirect only br/callbr predecessors.  O2 can
// legitimately leave a switch on an edge which the pass must redirect.  Put a
// one-way block on precisely those edges: the switch and its case structure
// remain intact, while FixIrreducible sees an unconditional branch.
class NormalizeIrreduciblePass : public PassInfoMixin<NormalizeIrreduciblePass> {
public:
    PreservedAnalyses run(Function& function, FunctionAnalysisManager& analyses) {
        CycleInfo& cycles = analyses.getResult<CycleAnalysis>(function);
        DenseSet<std::pair<BasicBlock*, BasicBlock*>> seen;
        SmallVector<std::pair<BasicBlock*, BasicBlock*>, 8> edges;
        auto addEdge = [&](BasicBlock* predecessor, BasicBlock* successor) {
            if (seen.insert({predecessor, successor}).second) {
                edges.push_back({predecessor, successor});
            }
        };

        auto supported = [](const BasicBlock* block) {
            const Instruction* terminator = block->getTerminator();
            return isa<UncondBrInst, CondBrInst, CallBrInst>(terminator);
        };
        auto collect = [&](auto&& self, Cycle* cycle) -> void {
            for (Cycle* child : cycle->children()) {
                self(self, child);
            }
            if (cycle->isReducible()) {
                return;
            }

            BasicBlock* header = cycle->getHeader();
            for (BasicBlock* predecessor : predecessors(header)) {
                if (cycle->contains(predecessor) && !supported(predecessor)) {
                    addEdge(predecessor, header);
                }
            }
            for (BasicBlock* entry : cycle->entries()) {
                for (BasicBlock* predecessor : predecessors(entry)) {
                    if (cycle->contains(predecessor) || supported(predecessor)) {
                        continue;
                    }
                    for (BasicBlock* successor : successors(predecessor)) {
                        if (cycle->contains(successor)) {
                            addEdge(predecessor, successor);
                        }
                    }
                }
            }
        };
        for (Cycle* cycle : cycles.toplevel_cycles()) {
            collect(collect, cycle);
        }

        DenseMap<BasicBlock*, unsigned> blockOrder;
        for (auto [index, block] : enumerate(function)) {
            blockOrder[&block] = index;
        }
        llvm::sort(edges, [&](const auto& left, const auto& right) {
            return std::pair(blockOrder.lookup(left.first), blockOrder.lookup(left.second)) <
                std::pair(blockOrder.lookup(right.first), blockOrder.lookup(right.second));
        });

        for (auto [predecessor, successor] : edges) {
            Instruction* terminator = predecessor->getTerminator();
            if (!isa<SwitchInst>(terminator)) {
                report_fatal_error(
                    Twine("bpf-normalize-irreducible: unsupported ") + terminator->getOpcodeName() + " predecessor in function " + function.getName());
            }
            unsigned index = 0;
            while (index != terminator->getNumSuccessors() && terminator->getSuccessor(index) != successor) {
                ++index;
            }
            if (index == terminator->getNumSuccessors() || !SplitCriticalEdge(terminator, index, CriticalEdgeSplittingOptions().setMergeIdenticalEdges())) {
                report_fatal_error(Twine("bpf-normalize-irreducible: cannot split switch edge in function ") + function.getName());
            }
        }

        if (!edges.empty()) {
            bpf::stats() << "bpf-normalize-irreducible: " << edges.size() << " switch edges normalized in " << function.getName() << "\n";
        }
        return edges.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterNormalizeIrreduciblePass(StringRef name, FunctionPassManager& manager) {
    if (name != "bpf-normalize-irreducible") {
        return false;
    }
    manager.addPass(NormalizeIrreduciblePass());
    return true;
}
