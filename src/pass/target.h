// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>

#include <cstdint>

// One knob: the oldest kernel the output has to load on. Everything else is
// derived, in two layers.
//
//   version  ->  features    what this kernel actually has
//   features ->  strategy    what we therefore have to do
//
// Keeping those apart matters. Signed division is a cpu-v4 instruction (6.6),
// not an arena feature (6.9). Collapse both onto one version test and you get
// the right answer for the versions you happened to try and the wrong one for
// the next.
//
// Individual strategies remain forceable only for compiler experiments; the
// installed pipeline exposes the kernel floor as its sole compatibility choice.

namespace bpf {

// major * 1000 + minor, so 6.9 is 6009. Parsed from -bpf-target.
unsigned Version();

// ------------------------------------------------------------- features

bool HasArena();               // bpf_arena + addr_space_cast              6.9
bool HasCpuV4();               // sdiv, smod, gotol, ldsx                  6.6
bool HasArenaSignedLoads();    // ldsx from PTR_TO_ARENA        7.0
bool HasInsnArrayJumpTables(); // verifier/libbpf support for .jumptables

// ------------------------------------------------------------- strategy

// Data-dependent managed loops run in automatically sized native chunks and
// suspend only at a chunk boundary. This is resumable on every target and does
// not ask users to guess a loop budget or change the ABI between kernel tiers.
bool UseArena();              // else: overlapping array-map regions
bool LowerSignedDivision();   // no cpu v4: synthesize sdiv/srem
bool LowerArenaSignedLoads(); // no arena ldsx: unsigned load + ALU sign extension
bool UseJumpTables();         // else: switches lower as compare trees

// Consequences of the memory model, not of the kernel version.
bool InternalizeEarly();

// Fixed target policy. These values are compiler invariants rather than a
// user-facing tuning surface.
unsigned MaxStepGroups();          // the kernel caps subprograms at 256
unsigned MaxInlinedInstructions(); // folding a callee in costs frame space

// Bytes reserved in a frame for each variable-length array. The frame is
// laid out once, so a VLA cannot size itself; it gets this much and a
// run-time check.
unsigned DynamicAllocaBytes();

// Runtime routines that run UNMANAGED: ordinary calls, no trampoline round
// trip, verified once each as global subprograms. Policy lives here because
// two passes must agree — stackify (does not manage them) and
// bpf-internalize-runtime (must NOT internalize them, or the verifier walks into every
// call site). Only branch-light leaves qualify; anything with a real loop
// (soft-float division) exhausts the budget when checked against unknown
// arguments.
bool IsUnmanagedRuntime(llvm::StringRef name);

} // namespace bpf
