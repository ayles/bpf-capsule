// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "llvm/Pass.h"

#include <cstdint>
#include <map>

namespace llvm {
class Function;
class TargetPassConfig;
} // namespace llvm

namespace bpf {

enum class SpillForm : uint8_t { Native, Scalar, Arena };
struct SpillValue {
    SpillForm form = SpillForm::Native;
    uint64_t mask = UINT64_MAX;
};

// Frame indices, sizes, alignments and lifetimes belong to LLVM. Only the
// representation needed when leaving the native stack is ours.
using SpillPlan = std::map<int, SpillValue>;
SpillPlan ReadSpillPlan(const llvm::Function& function);
void AddSpillSlotPlanPasses(llvm::TargetPassConfig& config);

} // namespace bpf
