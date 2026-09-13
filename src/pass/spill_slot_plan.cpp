// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Preserve representations while spills are separate LLVM frame objects.
// StackSlotColoring owns lifetime-based reuse; stack IDs keep incompatible
// reload requirements apart. Before PEI, restore the default stack ID and
// record the surviving frame indices for the late relocator.
#include "spill_slot_plan.h"

#include "common.h"

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;

namespace {

constexpr StringLiteral PlanMetadata = "bpf.capsule.spill.plan";
constexpr StringLiteral PendingMetadata = "bpf.capsule.spill.plan.pending";

enum class ValueKind { Bottom, Scalar, Arena, Native };
struct Value {
    ValueKind kind = ValueKind::Bottom;
    uint64_t mask = 0;
    bool operator==(const Value&) const = default;
};

Value scalar(uint64_t mask = UINT64_MAX) {
    return {ValueKind::Scalar, mask};
}

Value join(Value a, Value b) {
    if (a.kind == ValueKind::Bottom) {
        return b;
    }
    if (b.kind == ValueKind::Bottom) {
        return a;
    }
    if (a.kind != b.kind) {
        return {ValueKind::Native};
    }
    return a.kind == ValueKind::Scalar ? scalar(a.mask | b.mask) : a;
}

struct Values {
    MachineFunction& function;
    const TargetInstrInfo& instructions;
    const TargetRegisterInfo& registers;
    std::map<Register, Value> virtuals;
    std::map<int, Value> slots;
    SmallPtrSet<const llvm::Value*, 8> contextObjects;

    explicit Values(MachineFunction& f)
        : function(f)
        , instructions(*f.getSubtarget().getInstrInfo())
        , registers(*f.getSubtarget().getRegisterInfo()) {
        for (const Argument& arg : f.getFunction().args()) {
            if (arg.hasAttribute(bpf::md::Borrowed)) {
                contextObjects.insert(&arg);
            }
        }
    }

    int slotOf(const MachineInstr& instruction) const {
        for (const MachineOperand& operand : instruction.operands()) {
            if (operand.isFI() && operand.getIndex() >= 0 && function.getFrameInfo().isSpillSlotObjectIndex(operand.getIndex())) {
                return operand.getIndex();
            }
        }
        return -1;
    }

    static Value typeOf(const Type* type) {
        if (const auto* pointer = dyn_cast<PointerType>(type)) {
            return {pointer->getAddressSpace() == 1 ? ValueKind::Arena : ValueKind::Native};
        }
        if (type->isIntegerTy()) {
            return scalar();
        }
        return {ValueKind::Native};
    }

    Value operand(const MachineInstr& use, const MachineOperand& input, unsigned depth = 0) {
        if (input.isImm()) {
            return scalar(static_cast<uint64_t>(input.getImm()));
        }
        if (!input.isReg() || !input.getReg()) {
            return {ValueKind::Native};
        }
        Register reg = input.getReg();
        if (reg.isVirtual()) {
            return virtuals[reg];
        }
        if (depth >= 8) {
            return {ValueKind::Native};
        }
        for (auto it = std::next(use.getReverseIterator()); it != use.getParent()->rend(); ++it) {
            if (!it->modifiesRegister(reg, &registers)) {
                continue;
            }
            if (it->isCall()) {
                if (StringRef(registers.getName(reg)) != "R0") {
                    return {ValueKind::Native};
                }
                for (const MachineOperand& callee : it->operands()) {
                    if (callee.isGlobal()) {
                        if (const auto* f = dyn_cast<Function>(callee.getGlobal())) {
                            return typeOf(f->getReturnType());
                        }
                    }
                }
                return {ValueKind::Native};
            }
            return produced(*it, depth + 1);
        }
        StringRef name = registers.getName(reg);
        if (use.getParent()->isEntryBlock() && name.size() == 2 && (name[0] == 'R' || name[0] == 'W') && name[1] >= '1' && name[1] <= '5') {
            unsigned index = name[1] - '1';
            if (index < function.getFunction().arg_size()) {
                return typeOf(function.getFunction().getArg(index)->getType());
            }
        }
        return {ValueKind::Native};
    }

    Value produced(const MachineInstr& instruction, unsigned depth = 0) {
        StringRef op = instructions.getName(instruction.getOpcode());
        if (op == "ADDR_SPACE_CAST") {
            return instruction.getOperand(3).getImm() == 1 ? Value{ValueKind::Arena} : scalar();
        }
        if (op == "LD_imm64" || op.starts_with("MOV_ri")) {
            return instruction.getOperand(1).isImm() ? scalar(static_cast<uint64_t>(instruction.getOperand(1).getImm())) : Value{ValueKind::Native};
        }
        if (op == "COPY" || op == "MOV_rr" || op == "MOV_rr_32" || op == "MOV_32_64" || op == "SUBREG_TO_REG" || op == "EXTRACT_SUBREG") {
            return operand(instruction, instruction.getOperand(1), depth);
        }
        if (instruction.isInlineAsm()) {
            if (!instruction.getOperand(0).isSymbol() || instruction.getOperand(0).getSymbolName()[0]) {
                return {ValueKind::Native};
            }
            Value result;
            for (unsigned i = 0; i < instruction.getNumOperands(); ++i) {
                const MachineOperand& output = instruction.getOperand(i);
                if (!output.isReg() || !output.isDef()) {
                    continue;
                }
                unsigned input;
                if (!instruction.isRegTiedToUseOperand(i, &input)) {
                    return {ValueKind::Native};
                }
                result = join(result, operand(instruction, instruction.getOperand(input), depth));
            }
            return result;
        }
        if (instruction.mayLoad()) {
            int slot = slotOf(instruction);
            if (slot >= 0) {
                return slots[slot];
            }
            // Context loads can produce packet pointers despite their integer
            // IR type. MachinePointerInfo retains their original IR address.
            for (const MachineMemOperand* memory : instruction.memoperands()) {
                if (memory->getValue() && contextObjects.contains(getUnderlyingObject(memory->getValue()))) {
                    return {ValueKind::Native};
                }
            }
            // v3 also loads narrow values into 64-bit registers. Their MMO
            // width still proves zero high bits, except for MEMSX loads.
            if (!op.ends_with("SX")) {
                for (const MachineMemOperand* memory : instruction.memoperands()) {
                    if (memory->getSize().hasValue()) {
                        uint64_t bytes = memory->getSize().getValue().getKnownMinValue();
                        if (bytes && bytes < 8) {
                            return scalar(maskTrailingOnes<uint64_t>(bytes * 8));
                        }
                    }
                }
            }
            return scalar();
        }
        Value inputs;
        unsigned arena = 0;
        for (const MachineOperand& input : instruction.operands()) {
            if (input.isImm() || (input.isReg() && !input.isDef())) {
                Value value = operand(instruction, input, depth);
                if (value.kind == ValueKind::Native || value.kind == ValueKind::Bottom) {
                    return value;
                }
                arena += value.kind == ValueKind::Arena;
                inputs = join(inputs, value);
            }
        }
        if (op == "PHI") {
            return inputs;
        }
        if (op.starts_with("ADD_") || op.starts_with("SUB_")) {
            if (arena) {
                return arena == 1 ? Value{ValueKind::Arena} : Value{ValueKind::Native};
            }
            return scalar();
        }
        if (arena) {
            return {ValueKind::Native};
        }
        if (op.starts_with("AND_") && instruction.getNumOperands() > 2 && instruction.getOperand(2).isImm()) {
            return scalar(operand(instruction, instruction.getOperand(1), depth).mask & static_cast<uint64_t>(instruction.getOperand(2).getImm()));
        }
        if ((op.starts_with("SLL_") || op.starts_with("SRL_")) && instruction.getOperand(2).isImm()) {
            unsigned shift = instruction.getOperand(2).getImm() & 63;
            uint64_t mask = operand(instruction, instruction.getOperand(1), depth).mask;
            return scalar(op.starts_with("SLL_") ? mask << shift : mask >> shift);
        }
        static constexpr StringRef ScalarOps[] = {"MUL_", "DIV_", "MOD_", "SDIV_", "SMOD_", "AND_", "OR_", "XOR_", "SLL_", "SRL_", "SRA_", "NEG_", "MOVSX_",
            "BSWAP", "BE", "LE", "CMPXCHG", "XADD", "XCHG"};
        for (StringRef family : ScalarOps) {
            if (op.starts_with(family)) {
                return scalar();
            }
        }
        return {ValueKind::Native};
    }

    void solve() {
        for (bool changed = true; changed;) {
            changed = false;
            for (const MachineBasicBlock& block : function) {
                for (const MachineInstr& instruction : block) {
                    for (const MachineOperand& output : instruction.operands()) {
                        if (output.isReg() && output.isDef() && output.getReg().isVirtual()) {
                            Value& previous = virtuals[output.getReg()];
                            Value next = produced(instruction);
                            // Register-class width is LLVM's fact, including
                            // zero extension when a GPR32 value is copied into
                            // a full-width spill. Do not truncate native pointers
                            // returned by context-load instructions.
                            if (next.kind == ValueKind::Scalar && registers.getRegSizeInBits(output.getReg(), function.getRegInfo()) == 32) {
                                next.mask &= UINT32_MAX;
                            }
                            next = join(previous, next);
                            changed |= previous != next;
                            previous = next;
                        }
                    }
                    int index = slotOf(instruction);
                    if (index >= 0 && instruction.mayStore()) {
                        Value& previous = slots[index];
                        Value next = join(previous, operand(instruction, instruction.getOperand(0)));
                        changed |= previous != next;
                        previous = next;
                    }
                }
            }
        }
    }
};

struct BPFSpillSlotPlan : MachineFunctionPass {
    static char ID;
    BPFSpillSlotPlan()
        : MachineFunctionPass(ID) {
    }
    void getAnalysisUsage(AnalysisUsage& usage) const override {
        usage.setPreservesAll();
        MachineFunctionPass::getAnalysisUsage(usage);
    }
    bool runOnMachineFunction(MachineFunction& function) override {
        if (!function.getFunction().getMetadata(bpf::md::AllocationUnit)) {
            return false;
        }
        const MachineFrameInfo& frame = function.getFrameInfo();
        bool hasSpills = false;
        for (int index = 0; index < frame.getObjectIndexEnd(); ++index) {
            hasSpills |= !frame.isDeadObjectIndex(index) && frame.isSpillSlotObjectIndex(index);
        }
        if (!hasSpills) {
            return false;
        }
        Values values(function);
        values.solve();
        // BPF's spill hooks emit frame-index operands without memory operands.
        // Add the standard FixedStack identity while it is still explicit;
        // StackSlotColoring updates it and PEI preserves it after removing FI.
        for (MachineBasicBlock& block : function) {
            for (MachineInstr& instruction : block) {
                int index = values.slotOf(instruction);
                if (index < 0 || !instruction.memoperands_empty() || (!instruction.mayLoad() && !instruction.mayStore())) {
                    continue;
                }
                uint64_t size = function.getFrameInfo().getObjectSize(index);
                instruction.addMemOperand(function,
                    function.getMachineMemOperand(MachinePointerInfo::getFixedStack(function, index),
                        instruction.mayStore() ? MachineMemOperand::MOStore : MachineMemOperand::MOLoad, size, function.getFrameInfo().getObjectAlign(index)));
            }
        }
        LLVMContext& context = function.getFunction().getContext();
        SmallVector<Metadata*> representations;
        std::map<std::pair<ValueKind, uint64_t>, unsigned> ids;
        for (const auto& [index, value] : values.slots) {
            if (value.kind != ValueKind::Scalar && value.kind != ValueKind::Arena) {
                continue;
            }
            auto key = std::make_pair(value.kind, value.mask);
            auto found = ids.find(key);
            // Stack IDs are bytes. Excess representations simply stay native.
            if (found == ids.end() && ids.size() == 255) {
                continue;
            }
            auto [it, inserted] = ids.try_emplace(key, ids.size() + 1);
            if (inserted) {
                representations.push_back(MDNode::get(context,
                    {ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(context), value.kind == ValueKind::Arena)),
                        ConstantAsMetadata::get(ConstantInt::get(Type::getInt64Ty(context), value.mask))}));
            }
            function.getFrameInfo().setStackID(index, it->second);
        }
        function.getFunction().setMetadata(PendingMetadata, MDNode::get(context, representations));
        return true;
    }
};

struct BPFFinishSpillSlotPlan : MachineFunctionPass {
    static char ID;
    BPFFinishSpillSlotPlan()
        : MachineFunctionPass(ID) {
    }
    void getAnalysisUsage(AnalysisUsage& usage) const override {
        usage.setPreservesAll();
        MachineFunctionPass::getAnalysisUsage(usage);
    }
    bool runOnMachineFunction(MachineFunction& function) override {
        Function& ir = function.getFunction();
        MDNode* representations = ir.getMetadata(PendingMetadata);
        if (!representations) {
            return false;
        }
        LLVMContext& context = ir.getContext();
        MachineFrameInfo& frame = function.getFrameInfo();
        SmallVector<Metadata*> slots;
        for (int index = 0; index < frame.getObjectIndexEnd(); ++index) {
            if (frame.isDeadObjectIndex(index) || !frame.isSpillSlotObjectIndex(index)) {
                continue;
            }
            unsigned id = frame.getStackID(index);
            if (id) {
                slots.push_back(
                    MDNode::get(context, {ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(context), index)), representations->getOperand(id - 1)}));
                frame.setStackID(index, 0);
            }
        }
        ir.setMetadata(PlanMetadata, slots.empty() ? nullptr : MDNode::get(context, slots));
        ir.setMetadata(PendingMetadata, nullptr);
        return true;
    }
};

char BPFSpillSlotPlan::ID = 0;
char BPFFinishSpillSlotPlan::ID = 0;
static RegisterPass<BPFSpillSlotPlan> Plan("bpf-spill-slot-plan", "Preserve LLVM spill slot representations", false, false);
static RegisterPass<BPFFinishSpillSlotPlan> Finish("bpf-finish-spill-slot-plan", "Record LLVM's colored spill slots", false, false);

} // namespace

bpf::SpillPlan bpf::ReadSpillPlan(const Function& function) {
    SpillPlan result;
    if (MDNode* plan = function.getMetadata(PlanMetadata)) {
        for (const MDOperand& operand : plan->operands()) {
            auto* entry = dyn_cast_or_null<MDNode>(operand);
            auto* index = entry && entry->getNumOperands() == 2 ? mdconst::dyn_extract<ConstantInt>(entry->getOperand(0)) : nullptr;
            auto* value = entry && entry->getNumOperands() == 2 ? dyn_cast_or_null<MDNode>(entry->getOperand(1)) : nullptr;
            auto* kind = value && value->getNumOperands() == 2 ? mdconst::dyn_extract<ConstantInt>(value->getOperand(0)) : nullptr;
            auto* mask = value && value->getNumOperands() == 2 ? mdconst::dyn_extract<ConstantInt>(value->getOperand(1)) : nullptr;
            if (!index || !kind || !mask || kind->getZExtValue() > 1) {
                report_fatal_error("bpf-unified-spills: malformed LLVM spill plan", false);
            }
            result[index->getSExtValue()] = {kind->isOne() ? SpillForm::Arena : SpillForm::Scalar, mask->getZExtValue()};
        }
    }
    return result;
}

void bpf::AddSpillSlotPlanPasses(TargetPassConfig& config) {
    config.insertPass(&RAGreedyLegacyID, &BPFSpillSlotPlan::ID);
    config.insertPass(&StackSlotColoringID, &BPFFinishSpillSlotPlan::ID);
}
