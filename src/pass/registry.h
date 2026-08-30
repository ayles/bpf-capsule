// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/Passes/PassBuilder.h>

// Register every capsule pass name (and the "bpf-capsule" pipeline alias)
// with a PassBuilder. bpf-capsule-ld links the passes statically and calls
// this directly; no opt plugin is involved.
void RegisterCapsulePipelineCallbacks(llvm::PassBuilder& PB);
