// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>

// Two passes share one file because bpf-finalize-atomic-load-store re-checks
// LowerAtomicsPass::IsPreservedLoadStore before stripping atomic markers.
bool RegisterAtomicsPasses(llvm::StringRef name, llvm::FunctionPassManager& manager);
