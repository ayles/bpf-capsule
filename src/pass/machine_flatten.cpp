// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Join temporary BPF allocation units after register allocation.
//
// Stackify deliberately exposes disconnected pieces of the application step
// as ordinary IR functions. LLVM therefore selects and allocates each piece
// independently. This module pass is placed between post-RA machine passes:
// the legacy pass manager first finishes those passes for every function,
// runs this once with all MachineFunctions resident, then resumes the normal
// BPF pre-emission pipeline. No serialized BPF instruction or ELF record is
// inspected or rewritten.
#include "machine_flatten.h"

#include "common.h"
#include "runtime_symbols.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineConstantPool.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/TargetMachine.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>

using namespace llvm;

namespace {

cl::opt<bool> EnableMachineFlatten("bpf-machine-flatten", cl::desc("Join independently allocated BPF functions before emission"), cl::init(true), cl::Hidden);

cl::opt<unsigned> MachineFlattenConditionalBranchSpan(
    "bpf-machine-flatten-conditional-branch-span", cl::desc("Maximum flattened-machine conditional span before a local relay"), cl::init(8192), cl::Hidden);

cl::opt<unsigned> MachineFlattenV3BranchSpan(
    "bpf-machine-flatten-v3-branch-span", cl::desc("Maximum flattened-machine cpu=v3 branch span (testing)"), cl::init(30000), cl::Hidden);

cl::opt<unsigned> MachineFlattenV3RelayStep(
    "bpf-machine-flatten-v3-relay-step", cl::desc("Flattened-machine cpu=v3 branch-island step (testing)"), cl::init(26000), cl::Hidden);

std::optional<unsigned> metadataClass(const Function& function, StringRef name) {
    MDNode* metadata = function.getMetadata(name);
    if (!metadata || metadata->getNumOperands() != 1) {
        return std::nullopt;
    }
    auto* value = mdconst::dyn_extract<ConstantInt>(metadata->getOperand(0));
    if (!value || value->getValue().getActiveBits() > 32) {
        report_fatal_error(Twine("bpf-machine-flatten: malformed ") + name + " on " + function.getName());
    }
    return unsigned(value->getZExtValue());
}

struct ClonedBody {
    MachineBasicBlock* First;
    MachineBasicBlock* Last;
};

// Clone one already allocated MachineFunction. MachineBasicBlocks cannot be
// spliced between MachineFunctions: LLVM allocates their instructions and
// operands from the owning function's allocator. Cloning gives the final
// function ordinary ownership while preserving the selected physical
// registers, stack offsets and debug locations byte-for-byte.
ClonedBody cloneFunctionBody(MachineFunction& destination, MachineFunction& source) {
    if (source.empty()) {
        report_fatal_error(Twine("bpf-machine-flatten: empty allocation unit ") + source.getName());
    }

    DenseMap<const MachineBasicBlock*, MachineBasicBlock*> blocks;
    for (MachineBasicBlock& oldBlock : source) {
        // Target passes can synthesize blocks with no originating IR block.
        // Give those clones the source entry's provenance so the final layout
        // can still recover the complete disconnected allocation unit from
        // the merged machine CFG.
        const BasicBlock* provenance = oldBlock.getBasicBlock();
        if (!provenance) {
            provenance = &source.getFunction().getEntryBlock();
        }
        MachineBasicBlock* block = destination.CreateMachineBasicBlock(provenance);
        block->setAlignment(oldBlock.getAlignment(), oldBlock.getMaxBytesForAlignment());
        block->setIsEHPad(oldBlock.isEHPad());
        block->setIsEHScopeEntry(oldBlock.isEHScopeEntry());
        block->setIsEHContTarget(oldBlock.isEHContTarget());
        block->setIsEHFuncletEntry(oldBlock.isEHFuncletEntry());
        block->setIsCleanupFuncletEntry(oldBlock.isCleanupFuncletEntry());
        block->setSectionID(oldBlock.getSectionID());
        if (oldBlock.hasLabelMustBeEmitted()) {
            block->setLabelMustBeEmitted();
        }
        for (const auto& liveIn : oldBlock.liveins()) {
            block->addLiveIn(liveIn);
        }
        destination.push_back(block);
        blocks[&oldBlock] = block;
    }

    // A jump-table operand is just an index into its MachineFunction's
    // side table.  Copy that table now that every destination block exists,
    // then rewrite the operands below.  BPF v4 lowers switches to inline
    // long-jump tables, so rejecting JTI here would gratuitously disable the
    // target's best dispatcher exactly at the ownership boundary this pass
    // is meant to cross.
    DenseMap<unsigned, unsigned> jumpTables;
    if (const MachineJumpTableInfo* sourceInfo = source.getJumpTableInfo()) {
        MachineJumpTableInfo* destinationInfo = destination.getOrCreateJumpTableInfo(sourceInfo->getEntryKind());
        for (auto&& [index, entry] : enumerate(sourceInfo->getJumpTables())) {
            std::vector<MachineBasicBlock*> targets;
            targets.reserve(entry.MBBs.size());
            for (MachineBasicBlock* target : entry.MBBs) {
                MachineBasicBlock* mapped = blocks.lookup(target);
                if (!mapped) {
                    report_fatal_error(Twine("bpf-machine-flatten: cross-function jump-table target in ") + source.getName());
                }
                targets.push_back(mapped);
            }
            jumpTables[unsigned(index)] = destinationInfo->createJumpTableIndex(targets);
        }
    }

    // A constant-pool operand is another index into function-owned state.
    // Selection commonly creates one for large integer constants (wasm3 does
    // so in its opcode dispatcher). The values are IR Constants in the same
    // Module, so the destination pool can safely own references to them. BPF
    // has no target-specific MachineConstantPoolValue implementation; retain
    // an explicit rejection in case that backend contract ever changes.
    DenseMap<unsigned, unsigned> constantPool;
    if (const MachineConstantPool* sourcePool = source.getConstantPool()) {
        MachineConstantPool* destinationPool = destination.getConstantPool();
        for (auto&& [index, entry] : enumerate(sourcePool->getConstants())) {
            if (entry.isMachineConstantPoolEntry()) {
                report_fatal_error(Twine("bpf-machine-flatten: target-specific constant pool entry in ") + source.getName());
            }
            constantPool[unsigned(index)] = destinationPool->getConstantPoolIndex(entry.Val.ConstVal, entry.getAlign());
        }
    }

    DenseMap<const MDNode*, MDNode*> debugLocations;
    DISubprogram* rootSubprogram = destination.getFunction().getSubprogram();
    for (MachineBasicBlock& oldBlock : source) {
        MachineBasicBlock* block = blocks.lookup(&oldBlock);
        for (MachineInstr& instruction : oldBlock) {
            MachineInstr* clone = destination.CloneMachineInstr(&instruction);
            if (rootSubprogram && clone->getDebugLoc()) {
                clone->setDebugLoc(
                    DebugLoc::replaceInlinedAtSubprogram(clone->getDebugLoc(), *rootSubprogram, destination.getFunction().getContext(), debugLocations));
            }
            if (!instruction.memoperands_empty()) {
                SmallVector<MachineMemOperand*, 2> memory;
                for (MachineMemOperand* operand : instruction.memoperands()) {
                    memory.push_back(destination.getMachineMemOperand(operand, operand->getAAInfo()));
                }
                clone->setMemRefs(destination, memory);
            }
            block->insert(block->end(), clone);
        }
    }

    // Machine operands and the explicit CFG both name blocks. Remap them only
    // after every clone exists so backedges and arbitrary layout order work.
    for (MachineBasicBlock& oldBlock : source) {
        MachineBasicBlock* block = blocks.lookup(&oldBlock);
        for (MachineInstr& instruction : *block) {
            for (MachineOperand& operand : instruction.operands()) {
                if (operand.isMBB()) {
                    MachineBasicBlock* target = blocks.lookup(operand.getMBB());
                    if (!target) {
                        report_fatal_error(Twine("bpf-machine-flatten: cross-function block operand in ") + source.getName());
                    }
                    operand.setMBB(target);
                } else if (operand.isJTI()) {
                    auto mapped = jumpTables.find(unsigned(operand.getIndex()));
                    if (mapped == jumpTables.end()) {
                        report_fatal_error(Twine("bpf-machine-flatten: missing jump table in ") + source.getName());
                    }
                    operand.setIndex(int(mapped->second));
                } else if (operand.isCPI()) {
                    auto mapped = constantPool.find(unsigned(operand.getIndex()));
                    if (mapped == constantPool.end()) {
                        report_fatal_error(Twine("bpf-machine-flatten: missing constant pool entry in ") + source.getName());
                    }
                    operand.setIndex(int(mapped->second));
                } else if (operand.isFI()) {
                    // This pass runs after PEI. A surviving frame index means
                    // the target pipeline order no longer matches the
                    // flattening ownership contract.
                    std::string detail;
                    raw_string_ostream stream(detail);
                    stream << "frame index " << operand.getIndex() << " in ";
                    instruction.print(stream);
                    stream.flush();
                    report_fatal_error(Twine("bpf-machine-flatten: unresolved function-local ") + detail + " in " + source.getName());
                }
            }
        }
        for (auto successor = oldBlock.succ_begin(); successor != oldBlock.succ_end(); ++successor) {
            block->addSuccessor(blocks.lookup(*successor), oldBlock.getSuccProbability(successor));
        }
    }

    MachineFrameInfo& destinationFrame = destination.getFrameInfo();
    const MachineFrameInfo& sourceFrame = source.getFrameInfo();
    destinationFrame.setStackSize(std::max(destinationFrame.getStackSize(), sourceFrame.getStackSize()));
    destinationFrame.ensureMaxAlignment(sourceFrame.getMaxAlign());
    destinationFrame.setMaxCallFrameSize(std::max(destinationFrame.getMaxCallFrameSize(), sourceFrame.getMaxCallFrameSize()));
    destinationFrame.setHasCalls(destinationFrame.hasCalls() || sourceFrame.hasCalls());
    destination.ensureAlignment(source.getAlignment());
    destination.setHasInlineAsm(destination.hasInlineAsm() || source.hasInlineAsm());
    return {blocks.lookup(&source.front()), blocks.lookup(&source.back())};
}

const Function* directFunctionTarget(const MachineInstr& instruction) {
    if (!instruction.isCall()) {
        return nullptr;
    }
    for (const MachineOperand& operand : instruction.operands()) {
        if (operand.isGlobal()) {
            return dyn_cast<Function>(operand.getGlobal());
        }
    }
    return nullptr;
}

void placeDispatchHierarchy(MachineFunction& function, ArrayRef<Function*> units, const DenseMap<const Function*, ClonedBody>& bodies) {
    DenseMap<const Function*, SmallVector<Function*, 16>> children;
    SmallPtrSet<const Function*, 32> seen;
    for (MachineBasicBlock& block : function) {
        for (MachineInstr& instruction : block) {
            if (const Function* target = directFunctionTarget(instruction); target && bodies.contains(target)) {
                const BasicBlock* provenance = block.getBasicBlock();
                const Function* parent = provenance ? provenance->getParent() : nullptr;
                if (!parent || (parent != &function.getFunction() && !bodies.contains(parent))) {
                    report_fatal_error(Twine("bpf-machine-flatten: allocation unit has an unknown dispatch parent: ") + target->getName());
                }
                if (!seen.insert(target).second) {
                    report_fatal_error(Twine("bpf-machine-flatten: allocation unit has multiple machine call sites: ") + target->getName());
                }
                children[parent].push_back(const_cast<Function*>(target));
            }
        }
    }

    // Every source MachineFunction has already received LLVM's ordinary block
    // placement independently. Preserve that order inside it, but lay the
    // temporary terminal-call hierarchy out as compact windows:
    //
    //   root dispatcher, router 0, router 0's regions, router 1, ...
    //
    // Putting each region immediately after its individual comparison leaf
    // interleaves application bodies with the comparison tree. On cpu=v3 that
    // turns thousands of otherwise local tree edges into long branches and
    // makes relay insertion dominate the emitted program.
    SmallPtrSet<const Function*, 32> placed;
    std::function<void(const Function*)> placeChildren = [&](const Function* parent) {
        auto found = children.find(parent);
        if (found == children.end()) {
            return;
        }
        for (Function* child : found->second) {
            const ClonedBody& body = bodies.find(child)->second;
            function.splice(function.end(), body.First->getIterator(), std::next(body.Last->getIterator()));
            if (!placed.insert(child).second) {
                report_fatal_error(Twine("bpf-machine-flatten: allocation unit appears twice in dispatch hierarchy: ") + child->getName());
            }
            placeChildren(child);
        }
    };
    placeChildren(&function.getFunction());

    for (Function* unit : units) {
        if (!placed.contains(unit)) {
            report_fatal_error(Twine("bpf-machine-flatten: allocation unit is absent from dispatch hierarchy: ") + unit->getName());
        }
    }
    function.RenumberBlocks();
}

void makeCallsTerminalBranches(MachineFunction& function, const DenseMap<const Function*, ClonedBody>& bodies) {
    const TargetInstrInfo* instructions = function.getSubtarget().getInstrInfo();
    SmallVector<std::pair<MachineInstr*, MachineBasicBlock*>, 32> calls;
    for (MachineBasicBlock& block : function) {
        for (MachineInstr& instruction : block) {
            const Function* target = directFunctionTarget(instruction);
            if (target) {
                if (auto found = bodies.find(target); found != bodies.end()) {
                    calls.push_back({&instruction, found->second.First});
                }
            }
        }
    }

    for (auto [call, entry] : calls) {
        MachineBasicBlock* block = call->getParent();
        DebugLoc location = call->getDebugLoc();
        // The generated dispatcher call is tail-only by construction. Replace
        // it and any target return sequence with a CFG edge into the already
        // allocated body; the unit's RET remains the flattened step's RET.
        block->erase(call->getIterator(), block->end());
        while (!block->succ_empty()) {
            block->removeSuccessor(block->succ_begin());
        }
        // Bodies are deliberately adjacent to their dispatcher leaf. A plain
        // fallthrough is both the shortest possible dispatch edge and avoids
        // every v3 long-branch relay for the leaf-to-body transfer.
        if (!block->isLayoutSuccessor(entry)) {
            instructions->insertUnconditionalBranch(*block, entry, location);
        }
        block->addSuccessor(entry);
    }
}

void validateFlattenContract(Function& root, ArrayRef<Function*> units) {
    for (Function* unit : units) {
        if (unit->getReturnType() != root.getReturnType() || unit->getCallingConv() != root.getCallingConv() || unit->isVarArg()) {
            report_fatal_error(Twine("bpf-machine-flatten: incompatible terminal ABI between ") + unit->getName() + " and " + root.getName());
        }

        unsigned dispatchCalls = 0;
        for (User* user : unit->users()) {
            auto* call = dyn_cast<CallBase>(user);
            Function* caller = call ? call->getFunction() : nullptr;
            if (!call || call->getCalledOperand()->stripPointerCasts() != unit ||
                (caller != &root && (!caller || !caller->getMetadata(bpf::md::FlattenUnit)))) {
                report_fatal_error(Twine("bpf-machine-flatten: allocation unit has a non-dispatch use: ") + unit->getName());
            }
            ++dispatchCalls;
        }
        if (dispatchCalls != 1) {
            report_fatal_error(Twine("bpf-machine-flatten: allocation unit must have exactly one root dispatch: ") + unit->getName());
        }
    }
}

void removeUnreachableBlocks(MachineFunction& function) {
    SmallPtrSet<MachineBasicBlock*, 32> reachable;
    SmallVector<MachineBasicBlock*, 32> worklist{&function.front()};
    while (!worklist.empty()) {
        MachineBasicBlock* block = worklist.pop_back_val();
        if (!reachable.insert(block).second) {
            continue;
        }
        worklist.append(block->succ_begin(), block->succ_end());
    }

    SmallVector<MachineBasicBlock*, 32> dead;
    for (MachineBasicBlock& block : function) {
        if (!reachable.contains(&block)) {
            dead.push_back(&block);
        }
    }
    for (MachineBasicBlock* block : dead) {
        while (!block->succ_empty()) {
            block->removeSuccessor(block->succ_begin());
        }
    }
    for (MachineBasicBlock* block : dead) {
        function.erase(block);
    }
}

uint64_t instructionSlots(const MachineInstr& instruction) {
    if (instruction.isMetaInstruction() || instruction.isInlineAsm()) {
        return 0;
    }
    return instruction.getDesc().getSize() == 16 ? 2 : 1;
}

// cpu=v3 encodes every branch displacement in signed 16 bits. cpu=v4 can use
// a long unconditional jump, but a conditional branch may still expand past
// a target JIT's native range: arm64, for example, has a signed 19-bit
// conditional displacement and one BPF instruction can expand to many native
// instructions. Old arm64 JIT sizing passes have a second constraint: while
// sizing a backward conditional they use the target's absolute native offset
// as a provisional displacement. Therefore a short loop late in a giant BPF
// function can fail before the real displacement is known.
//
// Flattening is intentionally later than LLVM's block placement, so establish
// both invariants on the final layout. Every forward conditional is local and
// every backward conditional targets an adjacent forward relay. v4 carries
// the rest with GOTOL; v3 chains ordinary unconditional branch islands within
// its signed-16-bit encoding.
// Relays carry no state and create neither a continuation nor a BPF call frame.
unsigned relaxFlattenedBranches(MachineFunction& function) {
    const bool v4 = function.getTarget().getTargetCPU() == "v4";

    // Measured arm64 arena expansion turns a roughly 17k-slot conditional
    // edge into B.cond's 262k-native-instruction limit. Eight thousand final
    // BPF slots leaves more than a twofold margin on the supported JITs. The
    // old sizing-pass defect is independent of this forward-span budget and
    // is handled below by relaying every backward conditional.
    const int64_t conditionalSpan = MachineFlattenConditionalBranchSpan;
    if (conditionalSpan < 1) {
        report_fatal_error("bpf-machine-flatten: conditional branch span must be positive");
    }
    const int64_t v3EncodableSpan = MachineFlattenV3BranchSpan;
    const int64_t v3RelayStep = MachineFlattenV3RelayStep;
    if (!v4 && (v3EncodableSpan < 1 || v3RelayStep < 1 || v3RelayStep >= v3EncodableSpan)) {
        report_fatal_error("bpf-machine-flatten: cpu=v3 relay step must be positive and smaller than its branch span");
    }

    const TargetInstrInfo* instructions = function.getSubtarget().getInstrInfo();
    unsigned relays = 0;

    struct Request {
        MachineInstr* Branch;
        MachineBasicBlock* Target;
        SmallVector<MachineBasicBlock*, 4> Boundaries;
    };

    // Plan a complete relay chain for every far edge in one layout scan. An
    // older implementation added only one relay layer per fixed-point round
    // and linearly searched every block for every edge. That is quadratic in
    // large flattened programs and made ordinary SQLite/QuickJS links take
    // tens of minutes. Boundary lookup below is logarithmic, and each request
    // contains every relay needed to reach its target in the current layout.
    //
    // Other shared islands can still make a formerly short edge long, so keep
    // the outer fixed point. Every new relay lies strictly closer to its
    // destination than its source, which is the termination invariant.
    for (uint64_t round = 0;; ++round) {
        DenseMap<const MachineBasicBlock*, int64_t> blockOffset;
        DenseMap<const MachineInstr*, int64_t> instructionOffset;
        SmallVector<MachineBasicBlock*> layout;
        SmallVector<int64_t> layoutOffsets;
        int64_t offset = 0;
        for (MachineBasicBlock& block : function) {
            layout.push_back(&block);
            layoutOffsets.push_back(offset);
            blockOffset[&block] = offset;
            for (MachineInstr& instruction : block) {
                instructionOffset[&instruction] = offset;
                offset += instructionSlots(instruction);
            }
        }

        auto relayBoundary = [&](int64_t source, bool forward) -> MachineBasicBlock* {
            if (forward) {
                const int64_t desired = source + v3RelayStep;
                auto upper = std::upper_bound(layoutOffsets.begin(), layoutOffsets.end(), desired);
                if (upper == layoutOffsets.begin()) {
                    return nullptr;
                }
                --upper;
                if (*upper <= source) {
                    return nullptr;
                }
                return layout[std::distance(layoutOffsets.begin(), upper)];
            }

            const int64_t desired = source - v3RelayStep;
            auto lower = std::lower_bound(layoutOffsets.begin(), layoutOffsets.end(), desired);
            if (lower == layoutOffsets.end() || *lower >= source) {
                return nullptr;
            }
            return layout[std::distance(layoutOffsets.begin(), lower)];
        };

        auto appendV3Chain = [&](int64_t source, int64_t destination, SmallVectorImpl<MachineBasicBlock*>& boundaries) {
            while (true) {
                const int64_t span = destination - source - 1;
                if (span >= -v3EncodableSpan && span <= v3EncodableSpan) {
                    return;
                }
                MachineBasicBlock* before = relayBoundary(source, span > 0);
                if (!before) {
                    report_fatal_error(Twine("bpf-machine-flatten: no basic-block boundary available for a branch relay in ") + function.getName());
                }
                const int64_t next = blockOffset.lookup(before);
                if ((span > 0 && next <= source) || (span < 0 && next >= source)) {
                    report_fatal_error(Twine("bpf-machine-flatten: branch relay did not advance in ") + function.getName());
                }
                boundaries.push_back(before);
                source = next;
            }
        };

        SmallVector<Request> requests;
        for (MachineBasicBlock& block : function) {
            for (MachineInstr& branch : block) {
                if (!branch.isBranch()) {
                    continue;
                }
                const bool conditional = branch.isConditionalBranch();
                if (v4 && !conditional) {
                    continue;
                }
                MachineBasicBlock* target = nullptr;
                for (MachineOperand& operand : branch.operands()) {
                    if (operand.isMBB()) {
                        target = operand.getMBB();
                        break;
                    }
                }
                if (!target) {
                    continue;
                }
                int64_t source = instructionOffset.lookup(&branch);
                int64_t destination = blockOffset.lookup(target);
                int64_t span = destination - source - 1;
                const int64_t encodableSpan = conditional ? conditionalSpan : v3EncodableSpan;
                // During an old arm64 JIT's sizing pass, a backward target is
                // already known while the next-instruction offset is not. Its
                // absolute native position is therefore checked as the
                // provisional displacement. No BPF-slot cutoff can bound that
                // target-independently, so never leave a backward conditional.
                const bool backwardConditional = conditional && span < 0;
                if (span >= -encodableSpan && span <= encodableSpan && !backwardConditional) {
                    continue;
                }

                Request request{&branch, target, {}};
                if (conditional) {
                    // Keep the condition itself adjacent on both ISAs. The
                    // relay's unconditional edge is either GOTOL-capable (v4)
                    // or is chained below at V3RelayStep intervals (v3).
                    MachineBasicBlock* before = branch.getParent()->getNextNode();
                    // A conditional in the final layout block uses a relay
                    // appended directly after that block on either ISA.
                    // Represent that insertion boundary as null; the relay
                    // itself then becomes the new final block and is a real
                    // branch target, not unreachable padding.  On v3 the
                    // appended relay's own unconditional edge chains from
                    // the end of the current layout.
                    request.Boundaries.push_back(before);
                    if (!v4) {
                        appendV3Chain(before ? blockOffset.lookup(before) : offset, destination, request.Boundaries);
                    }
                } else {
                    appendV3Chain(source, destination, request.Boundaries);
                }
                requests.push_back(std::move(request));
            }
        }
        if (requests.empty()) {
            function.RenumberBlocks();
            return relays;
        }
        if (round == 0) {
            unsigned rootToRoot = 0;
            unsigned rootToUnit = 0;
            unsigned unitToSame = 0;
            unsigned unitToOther = 0;
            unsigned other = 0;
            for (const Request& request : requests) {
                const BasicBlock* sourceIr = request.Branch->getParent()->getBasicBlock();
                const BasicBlock* targetIr = request.Target->getBasicBlock();
                const Function* sourceOwner = sourceIr ? sourceIr->getParent() : nullptr;
                const Function* targetOwner = targetIr ? targetIr->getParent() : nullptr;
                bool sourceRoot = sourceOwner == &function.getFunction();
                bool targetRoot = targetOwner == &function.getFunction();
                bool sourceUnit = sourceOwner && sourceOwner->getMetadata(bpf::md::FlattenUnit);
                bool targetUnit = targetOwner && targetOwner->getMetadata(bpf::md::FlattenUnit);
                if (sourceRoot && targetRoot) {
                    ++rootToRoot;
                } else if (sourceRoot && targetUnit) {
                    ++rootToUnit;
                } else if (sourceUnit && targetUnit && sourceOwner == targetOwner) {
                    ++unitToSame;
                } else if (sourceUnit && targetUnit) {
                    ++unitToOther;
                } else {
                    ++other;
                }
            }
            bpf::stats() << "machine-flatten: initial far-edge classes root/root=" << rootToRoot << " root/unit=" << rootToUnit << " unit/same=" << unitToSame
                         << " unit/other=" << unitToOther << " other=" << other << "\n";
        }
        // Intern the chains from target back to source. Large comparison trees
        // commonly have thousands of edges to one default target; identical
        // suffixes are stateless and can share the same island DAG.
        std::map<std::pair<MachineBasicBlock*, MachineBasicBlock*>, MachineBasicBlock*> islands;
        for (Request& request : requests) {
            MachineBasicBlock* next = request.Target;
            for (MachineBasicBlock* before : llvm::reverse(request.Boundaries)) {
                const auto key = std::make_pair(before, next);
                auto found = islands.find(key);
                if (found != islands.end()) {
                    next = found->second;
                    continue;
                }

                if (before) {
                    auto position = before->getIterator();
                    if (position != function.begin()) {
                        MachineBasicBlock* previous = &*std::prev(position);
                        if (previous->canFallThrough()) {
                            instructions->insertUnconditionalBranch(*previous, before, request.Branch->getDebugLoc());
                            if (!previous->isSuccessor(before)) {
                                previous->addSuccessor(before);
                            }
                        }
                    }
                }

                MachineBasicBlock* relay = function.CreateMachineBasicBlock(request.Branch->getParent()->getBasicBlock());
                if (before) {
                    function.insert(before->getIterator(), relay);
                } else {
                    function.push_back(relay);
                }
                instructions->insertUnconditionalBranch(*relay, next, request.Branch->getDebugLoc());
                relay->addSuccessor(next);
                for (const auto& liveIn : next->liveins()) {
                    relay->addLiveIn(liveIn);
                }
                islands.emplace(key, relay);
                next = relay;
                ++relays;
            }

            MachineBasicBlock* branchBlock = request.Branch->getParent();
            for (MachineOperand& operand : request.Branch->operands()) {
                if (operand.isMBB() && operand.getMBB() == request.Target) {
                    operand.setMBB(next);
                    break;
                }
            }
            if (branchBlock->isSuccessor(request.Target)) {
                branchBlock->replaceSuccessor(request.Target, next);
            }
        }
        bpf::stats() << "machine-flatten: branch relay round " << round + 1 << ", " << requests.size() << " far branches, " << islands.size()
                     << " branch islands\n";
        function.RenumberBlocks();
    }
}

// Linux 5.15's initial CFG walk has two layout-sensitive corner cases. A
// conditional branch to its own fallthrough presents the same edge twice and
// is misidentified as a backedge. A real loop whose cycle-closing edge is an
// implicit layout fallthrough is rejected unless that edge comes from a jump
// instruction. LLVM is free to create both forms during block placement, and
// flattening changes placement again after the ordinary target passes have
// finished, so repair the final MachineFunction here.
//
// Only cyclic SCCs are touched. Ordinary acyclic fallthrough remains free, and
// a redundant conditional is deleted rather than replaced. The explicit jump
// is `goto +0`: it changes neither control flow nor register state.
unsigned repairV3VerifierCycles(MachineFunction& function) {
    if (function.getTarget().getTargetCPU() == "v4") {
        return 0;
    }

    const TargetInstrInfo* instructions = function.getSubtarget().getInstrInfo();
    unsigned changed = 0;
    for (MachineBasicBlock& block : function) {
        MachineBasicBlock* next = block.getNextNode();
        if (!next || block.succ_size() != 1 || !block.isSuccessor(next)) {
            continue;
        }

        MachineInstr* branch = nullptr;
        for (MachineInstr& instruction : llvm::reverse(block)) {
            if (!instruction.isDebugInstr()) {
                branch = &instruction;
                break;
            }
        }
        if (!branch || !branch->isConditionalBranch()) {
            continue;
        }

        bool targetsNext = llvm::any_of(branch->operands(), [&](const MachineOperand& operand) { return operand.isMBB() && operand.getMBB() == next; });
        if (targetsNext) {
            branch->eraseFromParent();
            ++changed;
        }
    }

    std::map<MachineBasicBlock*, unsigned> component;
    std::set<unsigned> cyclic;
    unsigned nextComponent = 1;
    for (auto iterator = scc_begin(&function); !iterator.isAtEnd(); ++iterator, ++nextComponent) {
        bool hasCycle = iterator->size() > 1;
        if (!hasCycle && !iterator->empty()) {
            hasCycle = iterator->front()->isSuccessor(iterator->front());
        }
        for (MachineBasicBlock* block : *iterator) {
            component[block] = nextComponent;
        }
        if (hasCycle) {
            cyclic.insert(nextComponent);
        }
    }

    for (MachineBasicBlock& block : function) {
        MachineBasicBlock* target = block.getNextNode();
        if (!target || !block.isSuccessor(target)) {
            continue;
        }
        unsigned id = component[&block];
        if (!id || component[target] != id || !cyclic.contains(id)) {
            continue;
        }

        MachineInstr* last = nullptr;
        for (MachineInstr& instruction : llvm::reverse(block)) {
            if (!instruction.isDebugInstr()) {
                last = &instruction;
                break;
            }
        }
        if (last && last->isBranch()) {
            continue;
        }
        instructions->insertUnconditionalBranch(block, target, last ? last->getDebugLoc() : DebugLoc());
        ++changed;
    }
    return changed;
}

struct BPFMachineFlatten final : ModulePass {
    static char ID;

    BPFMachineFlatten()
        : ModulePass(ID) {
    }

    StringRef getPassName() const override {
        return "BPF post-allocation function flattening";
    }

    void getAnalysisUsage(AnalysisUsage& usage) const override {
        usage.addRequired<MachineModuleInfoWrapperPass>();
        usage.addPreserved<MachineModuleInfoWrapperPass>();
    }

    bool runOnModule(Module& module) override {
        DenseMap<unsigned, Function*> roots;
        DenseMap<unsigned, SmallVector<Function*, 32>> units;
        for (Function& function : module) {
            if (auto cls = metadataClass(function, bpf::md::FlattenRoot)) {
                if (!roots.try_emplace(*cls, &function).second) {
                    report_fatal_error(Twine("bpf-machine-flatten: duplicate output root for class ") + Twine(*cls));
                }
            }
            if (auto cls = metadataClass(function, bpf::md::FlattenUnit)) {
                units[*cls].push_back(&function);
            }
        }
        if (units.empty()) {
            return false;
        }

        MachineModuleInfo& machineModule = getAnalysis<MachineModuleInfoWrapperPass>().getMMI();
        for (auto& [cls, classUnits] : units) {
            Function* root = roots.lookup(cls);
            if (!root) {
                report_fatal_error(Twine("bpf-machine-flatten: no output root for class ") + Twine(cls));
            }
            validateFlattenContract(*root, classUnits);
            MachineFunction* destination = machineModule.getMachineFunction(*root);
            if (!destination) {
                report_fatal_error(Twine("bpf-machine-flatten: root was not selected: ") + root->getName());
            }

            DenseMap<const Function*, ClonedBody> bodies;
            for (Function* unit : classUnits) {
                MachineFunction* source = machineModule.getMachineFunction(*unit);
                if (!source) {
                    report_fatal_error(Twine("bpf-machine-flatten: allocation unit was not selected: ") + unit->getName());
                }
                bodies[unit] = cloneFunctionBody(*destination, *source);
            }
            // The functions have already been placed independently. Join
            // their complete layouts in dispatch-hierarchy order; every call
            // is terminal and disappears below, so these are placement edges,
            // not emitted BPF call frames or function slots.
            placeDispatchHierarchy(*destination, classUnits, bodies);
            makeCallsTerminalBranches(*destination, bodies);
            removeUnreachableBlocks(*destination);
            destination->RenumberBlocks();
            root->setMetadata(bpf::md::FlattenedUnits,
                MDNode::get(module.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(module.getContext()), classUnits.size()))));
            // Subsequent MachineFunction passes, including AsmPrinter, skip
            // available_externally functions. Keep their IR bodies and MFs
            // alive until final emission because cloned debug/memory metadata
            // can still point into their allocators.
            for (Function* unit : classUnits) {
                unit->setLinkage(GlobalValue::AvailableExternallyLinkage);
            }
            bpf::stats() << "machine-flatten: merged " << classUnits.size() << " allocation units into " << root->getName() << ", " << destination->size()
                         << " machine blocks before final placement\n";
        }
        return true;
    }
};

// The ordinary MachineBlockPlacement pass runs independently on the root and
// every temporary unit before the module pass above joins them. Only target
// branch/verifier repairs belong after that final layout.
struct BPFMachineFlattenFinalize final : MachineFunctionPass {
    static char ID;

    BPFMachineFlattenFinalize()
        : MachineFunctionPass(ID) {
    }

    StringRef getPassName() const override {
        return "BPF flattened-function finalization";
    }

    bool runOnMachineFunction(MachineFunction& function) override {
        auto units = metadataClass(function.getFunction(), bpf::md::FlattenedUnits);
        if (!units) {
            // Linux 5.15 applies the same layout-sensitive CFG check to
            // emitted allocation subprograms. They are no longer flattened,
            // but their bounded native loops still need explicit cycle-closing
            // jumps after MachineBlockPlacement has chosen the final order.
            if (!function.getFunction().getMetadata(bpf::md::AllocationUnit)) {
                return false;
            }
            unsigned verifierCfgFixes = repairV3VerifierCycles(function);
            if (verifierCfgFixes) {
                bpf::stats() << "machine-finalize: " << function.getName() << ", " << verifierCfgFixes << " old-verifier CFG fixes\n";
            }
            return verifierCfgFixes != 0;
        }
        // Allocation units already return through valid BPF exits. Preserving
        // those local exits avoids routing thousands of terminal paths across
        // the complete flattened function through one artificial epilogue.
        unsigned relays = relaxFlattenedBranches(function);
        unsigned verifierCfgFixes = repairV3VerifierCycles(function);
        // Explicit cycle-closing jumps can lengthen unrelated branches which
        // cross them. Re-check v3 after the final old-verifier CFG repair.
        relays += relaxFlattenedBranches(function);
        bpf::stats() << "machine-flatten: " << *units << " allocation units -> " << function.getName() << ", " << function.size() << " placed machine blocks, "
                     << relays << " branch relays, " << verifierCfgFixes << " old-verifier CFG fixes\n";
        return relays || verifierCfgFixes;
    }
};

char BPFMachineFlatten::ID = 0;
char BPFMachineFlattenFinalize::ID = 0;
static RegisterPass<BPFMachineFlatten> RegisterMachineFlatten("bpf-machine-flatten", "BPF post-allocation function flattening", false, false);
static RegisterPass<BPFMachineFlattenFinalize> RegisterMachineFlattenFinalize(
    "bpf-machine-flatten-finalize", "BPF flattened-function finalization", false, false);

} // namespace

void bpf::AddMachineFlattenPasses(TargetPassConfig& config, AnalysisID mergeAfter, AnalysisID finalizeAfter) {
    if (EnableMachineFlatten) {
        config.insertPass(mergeAfter, &BPFMachineFlatten::ID);
        config.insertPass(&BPFMachineFlatten::ID, &BPFMachineFlattenFinalize::ID);
        return;
    }
    config.insertPass(finalizeAfter, &BPFMachineFlattenFinalize::ID);
}
