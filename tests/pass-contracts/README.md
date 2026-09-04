# Compiler pass contracts

Each case records one complete, small compiler state before and after a pass:

- `ir/<case>.before.ll` is the pass's input contract.
- `ir/<case>.after.ll` is the exact expected output contract.
- machine passes use the analogous `mir/` form because post-allocation state
  cannot be represented in LLVM IR.
- `machine-pipeline/` contains the deliberate cross-pass cases that cannot be
  decomposed into isolated MIR passes: `dispatch-locality`,
  `jump-table-locality`, `router-shared-suffix`, and `hierarchy-rehash` cover
  placement, rebuilt dispatch ownership, and the relocation model together.

The test harness parses and prints both snapshots with the LLVM version used to
build `bpf-capsule-ld`, removes only the bitcode container's `ModuleID`, and
compares the entire result. Inputs and expectations must already be in that
canonical spelling. A failure therefore produces a reviewable semantic diff,
not a list of loosely matched `FileCheck` fragments.

Fixtures should be the smallest module that exercises every distinct branch of
one pass. Keep unrelated optimization out of the pipeline string. Validation
passes use an unchanged before/after pair for accepted input and a separate
diagnostic case for rejected input.

MIR cases are parsed, transformed, and printed by `bpf-capsule-ld` with the
same `-run-pass` and `-simplify-mir` interface as LLVM's `llc`. There is no
test-only pass module or duplicated registration path.

`machine-pipeline` fixtures use the linker's static relocation model. It lets
LLVM reuse the loaded jump-table address in `jump-table-locality` and
`hierarchy-rehash`; an expectation containing a second address load is stale.
