// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "inline_policy.h"

#include "common.h"

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// Capsule-aware inlining veto. LLVM's cost model prices an inlined copy at
// its instruction count on a conventional CPU; in Capsule an inlined LOOP is
// re-expanded by stackify's chunking at every copy and re-verified in every
// caller context against the one-million-instruction budget, and code bloat
// itself costs runtime on the instruction-bound cores this targets. Letting
// the generic model decide makes SQLite and QuickJS unloadable and puts tens
// of thousands of instructions behind three PureDOOM string helpers.
//
// Small loop-free helpers are the opposite case: inlining one deletes a
// managed call — the most expensive primitive in the machine — and
// multiplies nothing. So the veto is structural and bounded: functions with
// loops or beyond a size cap become noinline (alwaysinline is honored
// only for C99-style definitions with no out-of-line body); everything
// small and straight-line stays subject to LLVM's normal cost model.
// Stackify separately inlines single-use helpers under the same size policy.

class InlinePolicyPass : public PassInfoMixin<InlinePolicyPass> {
public:
    PreservedAnalyses run(Function& function, FunctionAnalysisManager& manager) {
        if (function.isDeclaration()) {
            return PreservedAnalyses::all();
        }
        bpf::MaterializeFunctionClasses(*function.getParent());
        // A managed variadic function owns the caller-laid argument tail in
        // its software frame. Inlining it would move llvm.va_start into a
        // non-variadic caller and destroy the frame boundary that gives the
        // cursor meaning. This is an ABI veto, not the size-policy veto below:
        // Stackify must never reconsider it as a single-use helper.
        if (function.isVarArg()) {
            function.removeFnAttr(Attribute::AlwaysInline);
            function.addFnAttr(Attribute::NoInline);
            return PreservedAnalyses::none();
        }
        // Heap accessors stay inlinable regardless of shape: each is a
        // memory access, and a call at every access clobbers the
        // caller-saved registers and spills the caller past its native
        // frame.
        if (bpf::HasFunctionClass(function, bpf::cls::HeapAccessor)) {
            return PreservedAnalyses::none();
        }
        // Pointer-argument call glue must fold into its entry: a global
        // subprogram cannot accept the entry's native stack pointers.
        if (bpf::HasFunctionClass(function, bpf::cls::EntryGlue)) {
            return PreservedAnalyses::none();
        }
        LoopInfo& loops = manager.getResult<LoopAnalysis>(function);
        // Static alloca bytes count too: inlining copies the buffers into
        // every caller's native frame (a helper-visible print buffer
        // duplicated across one merged unit overflowed its 512-byte
        // budget), and stackify can budget one owner far better than N.
        uint64_t allocaBytes = 0;
        const DataLayout& layout = function.getParent()->getDataLayout();
        for (Instruction& inst : llvm::instructions(function)) {
            if (auto* alloca = dyn_cast<AllocaInst>(&inst)) {
                auto* count = dyn_cast<ConstantInt>(alloca->getArraySize());
                allocaBytes += count ? layout.getTypeAllocSize(alloca->getAllocatedType()) * count->getZExtValue() : 512;
            }
        }
        bool multiplies = !loops.empty() || function.getInstructionCount() > bpf::CompactInlineIrLimit || allocaBytes > 256;
        if (!multiplies) {
            return PreservedAnalyses::none();
        }
        bool policyChanged = false;
        if (function.hasFnAttribute(Attribute::AlwaysInline)) {
            // A C99 `inline` definition has no out-of-line copy, so it has to
            // be inlined. Everything else keeps its own frame: hand-written
            // alwaysinline in legacy ports often exists only to flatten the
            // call graph, which stackify does without native stack cost.
            if (function.hasAvailableExternallyLinkage() || function.isDiscardableIfUnused()) {
                return PreservedAnalyses::none();
            }
            function.removeFnAttr(Attribute::AlwaysInline);
            policyChanged = true;
        }
        // Preserve the distinction between a source/call-site noinline
        // contract and this pass's conservative pre-O2 veto. The latter may
        // be reconsidered after O2, when Stackify can prove that inlining a
        // compact function duplicates no source IR.
        if (!function.hasFnAttribute(Attribute::NoInline)) {
            function.addFnAttr(Attribute::NoInline);
            function.addFnAttr(bpf::InlinePolicyVetoAttr);
            policyChanged = true;
        }
        if (policyChanged) {
            bpf::stats() << "bpf-inline-policy: kept " << function.getName() << " out of line\n";
        }
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterInlinePolicyPass(StringRef name, FunctionPassManager& manager) {
    if (name != "bpf-inline-policy") {
        return false;
    }
    manager.addPass(InlinePolicyPass());
    return true;
}
