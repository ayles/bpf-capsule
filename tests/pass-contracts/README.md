# Compiler pass contracts

Each case records one complete, small compiler state before and after a pass:

- `ir/<case>.before.ll` is the pass's input contract.
- `ir/<case>.after.ll` is the exact expected output contract.
- machine passes use the analogous `mir/` form because post-allocation state
  cannot be represented in LLVM IR.
- `machine-pipeline/` contains the deliberate cross-pass cases that cannot be
  decomposed into isolated MIR passes: `dispatch-locality` retains allocation-
  unit provenance across stock placement, while `jump-table-locality` proves
  that placement, rebuilt dispatch leaves, the jump table, and emitted block
  labels remain one consistent ownership graph.

The test harness parses and prints both snapshots with the LLVM version used to
build `bpf-capsule-ld`, removes only the bitcode container's `ModuleID`, and
compares the entire result. Inputs and expectations must already be in that
canonical spelling. A failure therefore produces a reviewable semantic diff,
not a list of loosely matched `FileCheck` fragments.

Fixtures should be the smallest module that exercises every distinct branch of
one pass. Keep unrelated optimization out of the pipeline string. Validation
passes use an unchanged before/after pair for accepted input and a separate
diagnostic case for rejected input.

MIR cases are parsed and printed by the pinned `llc` with `-simplify-mir`.
CTest loads the same pass object files as `bpf-capsule-ld`; there is no
test-only implementation or duplicated pass registration.
