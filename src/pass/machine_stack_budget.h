// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "llvm/Pass.h"

namespace bpf {

// Module pass over the complete set of post-RA MachineFunctions.  The pass
// contracts late-flattened functions into their emitted BPF subprograms and
// writes an exact remaining native-stack budget onto every allocation unit.
llvm::AnalysisID MachineStackBudgetPassID();

} // namespace bpf
