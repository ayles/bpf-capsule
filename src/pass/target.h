// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>

#include <cstdint>

// No target capability reaches the pass library: a capability is expressed
// as which passes bpf-capsule-ld composes into the pipeline, and only that
// tool converts a --kernel floor into the composition. What remains here is
// fixed compiler policy every pass agrees on.

namespace bpf {

inline constexpr uint64_t MaxFiberStackBytes = 2u * 1024u * 1024u;

// Bytes at the low end of one fiber stack slice that managed stack descent
// must never enter. The stack has one deliberately simple ownership split:
// the low half is post-RA transient spill storage and the upper half is
// managed frames/VLAs. Policy lives here because Stackify folds the boundary
// (plus the module's largest outgoing push) into every claim/carve check,
// while the MIR spill pass proves its relocated words fit below it.
uint64_t TransientReserveBytes(uint64_t fiberStackBytes);

} // namespace bpf
