// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "llvm/Pass.h"

namespace llvm {
class TargetPassConfig;
} // namespace llvm

namespace bpf {

// Join independently allocated and placed machine functions, then repair
// old-ISA branches in the final flattened layout.
void AddMachineFlattenPasses(llvm::TargetPassConfig& config, llvm::AnalysisID mergeAfter, llvm::AnalysisID finalizeAfter);

} // namespace bpf
