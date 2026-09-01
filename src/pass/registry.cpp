// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Pass name registration, one hook per pass file, exposed as a plain
// function for bpf-capsule-ld (which links the passes statically — there is
// no opt plugin). The pipeline itself is composed by bpf-capsule-ld: which
// passes run, and in what order, is that tool's statement about the target.
#include "registry.h"

#include "atomics.h"
#include "capsule_domains.h"
#include "define_undef.h"
#include "expand_i128.h"
#include "expand_mem.h"
#include "expand_sret.h"
#include "internalize.h"
#include "lower_arena_sext.h"
#include "lower_capsule_call.h"
#include "lower_capsule_exit.h"
#include "lower_sdiv.h"
#include "memory.h"
#include "inline_policy.h"
#include "normalize_irreducible.h"
#include "no_jump_tables.h"
#include "sanitize_btf.h"
#include "scalarize_agg.h"
#include "softfloat.h"
#include "split_shift63.h"
#include "stackify.h"
#include "suspend_barriers.h"
#include "validate_no_float.h"

#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Scalar/InferAddressSpaces.h>

using namespace llvm;

void RegisterCapsulePipelineCallbacks(llvm::PassBuilder& PB) {
    PB.registerPipelineParsingCallback([](StringRef Name, ModulePassManager& PM, ArrayRef<PassBuilder::PipelineElement>) {
        if (RegisterMemoryPass(Name, PM) || RegisterExpandSretPass(Name, PM) || RegisterExpandI128Pass(Name, PM) || RegisterSanitizeBtfNamesPass(Name, PM) ||
            RegisterLowerSDivPass(Name, PM) || RegisterLowerCapsuleCallPass(Name, PM) || RegisterCapsuleDomainsPass(Name, PM) ||
            RegisterLowerCapsuleExitPass(Name, PM) || RegisterSuspendBarrierPasses(Name, PM) || RegisterStackifyPass(Name, PM) ||
            RegisterSoftFloatPass(Name, PM) || RegisterInternalizePass(Name, PM)) {
            return true;
        }
        return false;
    });
    PB.registerPipelineParsingCallback([](StringRef Name, FunctionPassManager& PM, ArrayRef<PassBuilder::PipelineElement>) {
        if (RegisterExpandMemPass(Name, PM) || RegisterDefineUndefPass(Name, PM) || RegisterScalarizeAggPass(Name, PM) ||
            RegisterLowerArenaSignedLoadsPass(Name, PM) || RegisterAtomicsPasses(Name, PM) || RegisterSplitShift63Pass(Name, PM) ||
            RegisterInlinePolicyPass(Name, PM) || RegisterNormalizeIrreduciblePass(Name, PM) || RegisterNoJumpTablesPass(Name, PM) ||
            RegisterValidateNoFloatPass(Name, PM)) {
            return true;
        }
        if (Name == "bpf-infer-as") {
            PM.addPass(InferAddressSpacesPass(0));
            return true;
        }
        return false;
    });
}
