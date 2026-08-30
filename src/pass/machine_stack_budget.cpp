// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Derive Capsule's physical-frame budget from the selected machine program.
//
// Linux charges the complete BPF-to-BPF call path, not each function in
// isolation.  Source-level constants are therefore unsound: inlining, spills,
// a native wrapper, or a fixed-memory accessor can all change the remaining
// part of the 512-byte limit after register allocation.
//
// Allocation units are special only because machine-flatten joins every unit
// in a class into one output root.  Those functions occupy one emitted frame,
// whose size is the maximum of their independently allocated frames.  This
// pass contracts each class into that one physical call-graph node, measures
// every other frame, and stores `512 - fixed path` on its allocation units.
#include "machine_stack_budget.h"

#include "common.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace {

// These are kernel ABI limits, not tuning policy.  Thirty-two bytes is the
// interpreter's stack granularity on every supported kernel; using it also
// makes an object safe when JIT compilation is disabled.  Linux permits the
// entry plus seven nested BPF frames.
constexpr uint64_t KernelStackBytes = 512;
constexpr uint64_t PortableStackGranule = 32;
constexpr unsigned KernelCallFrames = 8;

std::optional<unsigned> metadataClass(const Function& function, StringRef name) {
    MDNode* metadata = function.getMetadata(name);
    if (!metadata) {
        return std::nullopt;
    }
    auto* value = metadata->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(metadata->getOperand(0)) : nullptr;
    if (!value || value->getValue().getActiveBits() > 32) {
        report_fatal_error(Twine("bpf-machine-stack-budget: malformed ") + name + " on " + function.getName(), /*gen_crash_diag=*/false);
    }
    return unsigned(value->getZExtValue());
}

bool isStackMemoryOpcode(StringRef name) {
    // Keep this final-frame accounting predicate aligned with the broader
    // instruction classifier in unified_spills_mir.cpp. That pass needs
    // operand semantics; this one only needs the complete load/store family.
    return name == "LDD" || name == "LDW" || name == "LDW32" || name == "LDH" || name == "LDH32" || name == "LDB" || name == "LDB32" || name == "STD" ||
        name == "STW" || name == "STW32" || name == "STH" || name == "STH32" || name == "STB" || name == "STB32" ||
        (name.starts_with("ST") && name.contains("_imm"));
}

// MachineFrameInfo is normally exact after PEI.  Also inspect final r10
// accesses because target-created stack words are not always reflected back
// into MFI (the spill relocator deliberately has to make the same check).
uint64_t portableFrameBytes(const MachineFunction& machine) {
    uint64_t raw = machine.getFrameInfo().getStackSize();
    const TargetInstrInfo* instructions = machine.getSubtarget().getInstrInfo();
    const TargetRegisterInfo* registers = machine.getSubtarget().getRegisterInfo();
    for (const MachineBasicBlock& block : machine) {
        for (const MachineInstr& instruction : block) {
            if (!isStackMemoryOpcode(instructions->getName(instruction.getOpcode())) || instruction.getNumOperands() < 3 ||
                !instruction.getOperand(1).isReg() || !instruction.getOperand(2).isImm()) {
                continue;
            }
            Register base = instruction.getOperand(1).getReg();
            if (!base.isPhysical() || registers->getName(base) != StringRef("R10")) {
                continue;
            }
            int64_t offset = instruction.getOperand(2).getImm();
            if (offset < 0) {
                raw = std::max<uint64_t>(raw, uint64_t(-offset));
            }
        }
    }
    return alignTo(std::max<uint64_t>(raw, 1), PortableStackGranule);
}

struct Node {
    std::optional<unsigned> FlattenClass;
    SmallVector<Function*, 8> Members;
    Function* Root = nullptr;
    bool VariableFrame = false;
    uint64_t FixedFloor = 0;
    SmallVector<unsigned, 8> Successors;
};

StringRef nodeName(const Node& node) {
    if (node.Root) {
        return node.Root->getName();
    }
    return node.Members.front()->getName();
}

std::string printPath(ArrayRef<Node> nodes, ArrayRef<unsigned> path) {
    std::string result;
    raw_string_ostream out(result);
    for (auto&& [index, node] : enumerate(path)) {
        if (index) {
            out << " -> ";
        }
        out << nodeName(nodes[node]);
    }
    return result;
}

SmallVector<unsigned, 16> prefixPath(unsigned node, ArrayRef<int> predecessor) {
    SmallVector<unsigned, 16> path;
    for (int current = int(node); current >= 0; current = predecessor[current]) {
        path.push_back(unsigned(current));
    }
    std::reverse(path.begin(), path.end());
    return path;
}

SmallVector<unsigned, 16> suffixPath(unsigned node, ArrayRef<int> successor) {
    SmallVector<unsigned, 16> path;
    for (int current = int(node); current >= 0; current = successor[current]) {
        path.push_back(unsigned(current));
    }
    return path;
}

struct BPFMachineStackBudget final : ModulePass {
    static char ID;

    BPFMachineStackBudget()
        : ModulePass(ID) {
    }

    StringRef getPassName() const override {
        return "BPF post-allocation call-stack budgeting";
    }

    void getAnalysisUsage(AnalysisUsage& usage) const override {
        usage.addRequired<MachineModuleInfoWrapperPass>();
        usage.addPreserved<MachineModuleInfoWrapperPass>();
    }

    bool runOnModule(Module& module) override {
        MachineModuleInfo& machineModule = getAnalysis<MachineModuleInfoWrapperPass>().getMMI();
        DenseMap<const Function*, MachineFunction*> machines;
        for (Function& function : module) {
            if (function.isDeclaration()) {
                continue;
            }
            if (MachineFunction* machine = machineModule.getMachineFunction(function)) {
                machines[&function] = machine;
            }
        }

        std::map<unsigned, unsigned> classNodes;
        DenseMap<const Function*, unsigned> nodeOf;
        std::vector<Node> nodes;
        auto classOf = [&](const Function& function) -> std::optional<unsigned> {
            std::optional<unsigned> root = metadataClass(function, bpf::md::FlattenRoot);
            std::optional<unsigned> unit = metadataClass(function, bpf::md::FlattenUnit);
            if (root && unit && *root != *unit) {
                report_fatal_error(Twine("bpf-machine-stack-budget: conflicting flatten classes on ") + function.getName(), /*gen_crash_diag=*/false);
            }
            return root ? root : unit;
        };

        // First create the contracted late-flatten nodes.
        for (auto& [function, machine] : machines) {
            std::optional<unsigned> cls = classOf(*function);
            if (!cls) {
                continue;
            }
            auto [position, inserted] = classNodes.try_emplace(*cls, nodes.size());
            if (inserted) {
                Node node;
                node.FlattenClass = *cls;
                nodes.push_back(std::move(node));
            }
            nodeOf[function] = position->second;
        }
        // Every other selected function is one emitted BPF subprogram.
        for (auto& [function, machine] : machines) {
            if (nodeOf.contains(function)) {
                continue;
            }
            unsigned index = nodes.size();
            nodes.emplace_back();
            nodeOf[function] = index;
        }
        for (auto& [function, machine] : machines) {
            Node& node = nodes[nodeOf.lookup(function)];
            node.Members.push_back(const_cast<Function*>(function));
            if (function->getMetadata(bpf::md::FlattenRoot)) {
                if (node.Root) {
                    report_fatal_error(Twine("bpf-machine-stack-budget: duplicate output roots ") + node.Root->getName() + " and " + function->getName(),
                        /*gen_crash_diag=*/false);
                }
                node.Root = const_cast<Function*>(function);
            }
            if (function->getMetadata(bpf::md::AllocationUnit)) {
                node.VariableFrame = true;
            } else {
                node.FixedFloor = std::max(node.FixedFloor, portableFrameBytes(*machine));
            }
        }
        for (Node& node : nodes) {
            if (node.FlattenClass && !node.Root) {
                report_fatal_error(
                    Twine("bpf-machine-stack-budget: flatten class ") + Twine(*node.FlattenClass) + " has no output root", /*gen_crash_diag=*/false);
            }
        }

        // A function reference is either a direct BPF call or a callback
        // pseudo-function relocation.  The verifier walks both.  Declarations
        // denote helpers/kfuncs and do not allocate another BPF frame.
        for (auto& [caller, machine] : machines) {
            unsigned from = nodeOf.lookup(caller);
            std::set<unsigned> successors;
            for (const MachineBasicBlock& block : *machine) {
                for (const MachineInstr& instruction : block) {
                    for (const MachineOperand& operand : instruction.operands()) {
                        if (!operand.isGlobal()) {
                            continue;
                        }
                        auto* callee = dyn_cast<Function>(operand.getGlobal());
                        if (!callee || callee->isDeclaration()) {
                            continue;
                        }
                        auto found = nodeOf.find(callee);
                        if (found == nodeOf.end()) {
                            report_fatal_error(
                                Twine("bpf-machine-stack-budget: selected function ") + caller->getName() + " references unselected " + callee->getName(),
                                /*gen_crash_diag=*/false);
                        }
                        unsigned to = found->second;
                        // machine-flatten removes every call whose target is
                        // a unit of the caller's class.  A call back to the
                        // root is not removed and must remain a recursion
                        // error below.
                        bool removedByFlatten = from == to && callee->getMetadata(bpf::md::FlattenUnit);
                        if (!removedByFlatten) {
                            successors.insert(to);
                        }
                    }
                }
            }
            nodes[from].Successors.append(successors.begin(), successors.end());
        }
        for (Node& node : nodes) {
            llvm::sort(node.Successors);
            node.Successors.erase(std::unique(node.Successors.begin(), node.Successors.end()), node.Successors.end());
        }

        SmallVector<unsigned, 8> entries;
        for (auto& [function, machine] : machines) {
            if (bpf::IsEntryProgram(*function)) {
                entries.push_back(nodeOf.lookup(function));
            }
        }
        llvm::sort(entries);
        entries.erase(std::unique(entries.begin(), entries.end()), entries.end());

        // Topologically order exactly the graph the kernel can reach.  BPF
        // recursion is illegal independently of stack bytes, so diagnose it
        // here with physical (post-flatten) function names.
        std::vector<uint8_t> color(nodes.size());
        SmallVector<unsigned, 32> active;
        SmallVector<unsigned, 32> postorder;
        auto visit = [&](auto&& self, unsigned node) -> void {
            if (color[node] == 2) {
                return;
            }
            if (color[node] == 1) {
                auto first = llvm::find(active, node);
                SmallVector<unsigned, 16> cycle(first, active.end());
                cycle.push_back(node);
                report_fatal_error(Twine("bpf-machine-stack-budget: recursive BPF call path: ") + printPath(nodes, cycle), /*gen_crash_diag=*/false);
            }
            color[node] = 1;
            active.push_back(node);
            for (unsigned successor : nodes[node].Successors) {
                self(self, successor);
            }
            active.pop_back();
            color[node] = 2;
            postorder.push_back(node);
        };
        for (unsigned entry : entries) {
            visit(visit, entry);
        }
        SmallVector<unsigned, 32> order(postorder.rbegin(), postorder.rend());

        std::vector<bool> reachable(nodes.size());
        for (unsigned node : order) {
            reachable[node] = true;
        }

        // A managed call suspends before another allocation unit executes, so
        // an emitted call path must contain at most one variable Capsule
        // frame.  Enforce that architectural fact rather than inventing a
        // policy for sharing 512 bytes between nested dispatch roots.
        std::vector<std::set<unsigned>> previousVariables(nodes.size());
        for (unsigned node : order) {
            if (nodes[node].VariableFrame) {
                if (!previousVariables[node].empty()) {
                    unsigned previous = *previousVariables[node].begin();
                    report_fatal_error(Twine("bpf-machine-stack-budget: nested physical Capsule frames are unsupported: ") + nodeName(nodes[previous]) +
                            " reaches " + nodeName(nodes[node]),
                        /*gen_crash_diag=*/false);
                }
                previousVariables[node].insert(node);
            }
            for (unsigned successor : nodes[node].Successors) {
                previousVariables[successor].insert(previousVariables[node].begin(), previousVariables[node].end());
            }
        }

        // The verifier's other hard call-stack limit is independent of frame
        // size.  Compute it from the same contracted graph.
        std::vector<unsigned> callFrames(nodes.size());
        std::vector<int> callPredecessor(nodes.size(), -1);
        for (unsigned entry : entries) {
            callFrames[entry] = 1;
        }
        for (unsigned node : order) {
            if (!callFrames[node]) {
                continue;
            }
            if (callFrames[node] > KernelCallFrames) {
                SmallVector<unsigned, 16> path = prefixPath(node, callPredecessor);
                report_fatal_error(Twine("bpf-machine-stack-budget: BPF call path has ") + Twine(callFrames[node]) + " frames; kernel limit is " +
                        Twine(KernelCallFrames) + ": " + printPath(nodes, path),
                    /*gen_crash_diag=*/false);
            }
            for (unsigned successor : nodes[node].Successors) {
                if (callFrames[successor] < callFrames[node] + 1) {
                    callFrames[successor] = callFrames[node] + 1;
                    callPredecessor[successor] = int(node);
                }
            }
        }

        constexpr uint64_t Invalid = std::numeric_limits<uint64_t>::max();
        // Longest fixed-only entry prefix.  Propagation stops at a variable
        // frame; that frame's budget accounts for the suffix separately.
        std::vector<uint64_t> prefix(nodes.size(), Invalid);
        std::vector<int> prefixPredecessor(nodes.size(), -1);
        for (unsigned entry : entries) {
            if (!nodes[entry].VariableFrame) {
                prefix[entry] = nodes[entry].FixedFloor;
            }
        }
        for (unsigned node : order) {
            if (nodes[node].VariableFrame) {
                continue;
            }
            if (prefix[node] != Invalid && prefix[node] > KernelStackBytes) {
                SmallVector<unsigned, 16> path = prefixPath(node, prefixPredecessor);
                report_fatal_error(Twine("bpf-machine-stack-budget: native BPF call path uses ") + Twine(prefix[node]) + " stack bytes; kernel limit is " +
                        Twine(KernelStackBytes) + ": " + printPath(nodes, path),
                    /*gen_crash_diag=*/false);
            }
            if (prefix[node] == Invalid) {
                continue;
            }
            for (unsigned successor : nodes[node].Successors) {
                if (nodes[successor].VariableFrame) {
                    continue;
                }
                uint64_t candidate = prefix[node] + nodes[successor].FixedFloor;
                if (prefix[successor] == Invalid || prefix[successor] < candidate) {
                    prefix[successor] = candidate;
                    prefixPredecessor[successor] = int(node);
                }
            }
        }

        // Longest fixed-only suffix, in reverse topological order.
        std::vector<uint64_t> suffix(nodes.size(), Invalid);
        std::vector<int> suffixSuccessor(nodes.size(), -1);
        for (unsigned node : postorder) {
            if (nodes[node].VariableFrame) {
                continue;
            }
            uint64_t best = nodes[node].FixedFloor;
            for (unsigned successor : nodes[node].Successors) {
                if (nodes[successor].VariableFrame || suffix[successor] == Invalid) {
                    continue;
                }
                uint64_t candidate = nodes[node].FixedFloor + suffix[successor];
                if (candidate > best) {
                    best = candidate;
                    suffixSuccessor[node] = int(successor);
                }
            }
            suffix[node] = best;
        }

        bool changed = false;
        for (unsigned variable = 0; variable < nodes.size(); ++variable) {
            Node& node = nodes[variable];
            if (!node.VariableFrame) {
                continue;
            }
            // Unreachable temporary units are not part of a loaded program;
            // retain the absolute per-function budget so code generation can
            // still emit them deterministically.
            uint64_t before = 0;
            int beforeNode = -1;
            for (unsigned candidate = 0; candidate < nodes.size(); ++candidate) {
                if (prefix[candidate] == Invalid || !llvm::is_contained(nodes[candidate].Successors, variable)) {
                    continue;
                }
                if (beforeNode < 0 || before < prefix[candidate]) {
                    before = prefix[candidate];
                    beforeNode = int(candidate);
                }
            }
            uint64_t after = 0;
            int afterNode = -1;
            for (unsigned successor : node.Successors) {
                if (suffix[successor] != Invalid && after < suffix[successor]) {
                    after = suffix[successor];
                    afterNode = int(successor);
                }
            }
            uint64_t fixed = before + after;
            uint64_t budget = reachable[variable] ? (fixed < KernelStackBytes ? KernelStackBytes - fixed : 0) : KernelStackBytes;

            SmallVector<unsigned, 16> path;
            if (beforeNode >= 0) {
                path = prefixPath(unsigned(beforeNode), prefixPredecessor);
            }
            path.push_back(variable);
            if (afterNode >= 0) {
                SmallVector<unsigned, 16> tail = suffixPath(unsigned(afterNode), suffixSuccessor);
                path.append(tail.begin(), tail.end());
            }
            if (reachable[variable] && (budget < PortableStackGranule || node.FixedFloor > budget)) {
                report_fatal_error(Twine("bpf-machine-stack-budget: no physical Capsule frame fits call path ") + printPath(nodes, path) +
                        "; fixed frames use " + Twine(fixed) + " bytes and the merged root itself requires " + Twine(node.FixedFloor) + " bytes",
                    /*gen_crash_diag=*/false);
            }

            for (Function* member : node.Members) {
                if (!member->getMetadata(bpf::md::AllocationUnit)) {
                    continue;
                }
                member->setMetadata(bpf::md::NativeStackBudget,
                    MDNode::get(module.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(module.getContext()), budget))));
                changed = true;
            }
            bpf::stats() << "machine-stack-budget: " << nodeName(node) << " gets " << budget << " native bytes; fixed path " << fixed
                         << " bytes: " << printPath(nodes, path) << "\n";
        }
        return changed;
    }
};

char BPFMachineStackBudget::ID = 0;
static RegisterPass<BPFMachineStackBudget> RegisterMachineStackBudget("bpf-machine-stack-budget", "BPF post-allocation call-stack budgeting", false, false);

} // namespace

AnalysisID bpf::MachineStackBudgetPassID() {
    return &BPFMachineStackBudget::ID;
}
