// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Replace sign-extending loads with a zero-extending load and an explicit
// register sign extension.
//
// CPU v4 folds a narrow load feeding a signed operation into BPF_MEMSX. A
// kernel between the arena (6.9) and native signed arena loads (7.0) rejects
// that load mode from an arena pointer, and Capsule keeps globals, the heap
// and every fiber stack in the arena, so almost every narrow signed load in a
// managed program lands on one. bpf-lower-arena-sext fences the loads that
// exist before code generation; loads that reach selection later, notably
// reloads of relocated spill slots, arrive unfenced. This pass runs after
// selection and rewrites whatever BPF_MEMSX remains. It needs no provenance
// analysis: the same rewrite is correct for a real BPF stack slot, which the
// kernel would have accepted, and one extra register operation is the whole
// cost.
#include "common.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/RegisterTargetPassConfigCallback.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

namespace {

cl::opt<bool> ArenaSignedLoadLowering(
    "bpf-machine-arena-sext", cl::desc("Lower sign-extending loads for targets that reject them from arena memory"), cl::init(false), cl::Hidden);

// The selected load, the zero-extending load of the same width, and the
// register sign extension that restores its value.
struct Lowering {
    StringRef Signed;
    StringRef Plain;
    StringRef Extend;
};

constexpr Lowering Lowerings[] = {
    {"LDBSX", "LDB32", "MOVSX_rr_8"},
    {"LDHSX", "LDH32", "MOVSX_rr_16"},
    {"LDWSX", "LDW32", "MOVSX_rr_32"},
};

unsigned opcodeByName(const TargetInstrInfo& instructions, StringRef name) {
    for (unsigned opcode = 0, end = instructions.getNumOpcodes(); opcode < end; ++opcode) {
        if (instructions.getName(opcode) == name) {
            return opcode;
        }
    }
    report_fatal_error(Twine("bpf-machine-arena-sext: the target has no ") + name + " instruction", /*gen_crash_diag=*/false);
}

unsigned subRegisterIndexByName(const TargetRegisterInfo& registers, StringRef name) {
    for (unsigned index = 1, end = registers.getNumSubRegIndices(); index < end; ++index) {
        if (registers.getSubRegIndexName(index) == name) {
            return index;
        }
    }
    report_fatal_error(Twine("bpf-machine-arena-sext: the target has no ") + name + " subregister index", /*gen_crash_diag=*/false);
}

class BPFMachineArenaSext : public MachineFunctionPass {
public:
    static char ID;

    BPFMachineArenaSext()
        : MachineFunctionPass(ID) {
    }

    StringRef getPassName() const override {
        return "BPF sign-extending load lowering";
    }

    bool runOnMachineFunction(MachineFunction& function) override {
        const TargetInstrInfo& instructions = *function.getSubtarget().getInstrInfo();
        const TargetRegisterInfo& registers = *function.getSubtarget().getRegisterInfo();
        MachineRegisterInfo& virtualRegisters = function.getRegInfo();

        SmallVector<std::pair<MachineInstr*, const Lowering*>> work;
        for (MachineBasicBlock& block : function) {
            for (MachineInstr& instruction : block) {
                for (const Lowering& lowering : Lowerings) {
                    if (instructions.getName(instruction.getOpcode()) == lowering.Signed) {
                        work.emplace_back(&instruction, &lowering);
                        break;
                    }
                }
            }
        }
        if (work.empty()) {
            return false;
        }

        const unsigned lowWord = subRegisterIndexByName(registers, "sub_32");
        for (auto&& [instruction, lowering] : work) {
            const MachineOperand& destination = instruction->getOperand(0);
            if (!destination.getReg().isVirtual()) {
                report_fatal_error(Twine("bpf-machine-arena-sext: ") + lowering->Signed + " reached register allocation in " + function.getName(),
                    /*gen_crash_diag=*/false);
            }
            const unsigned plain = opcodeByName(instructions, lowering->Plain);
            const unsigned extend = opcodeByName(instructions, lowering->Extend);
            MachineBasicBlock& block = *instruction->getParent();
            const DebugLoc& location = instruction->getDebugLoc();

            Register narrow = virtualRegisters.createVirtualRegister(instructions.getRegClass(instructions.get(plain), 0));
            Register wide = virtualRegisters.createVirtualRegister(virtualRegisters.getRegClass(destination.getReg()));
            BuildMI(block, *instruction, location, instructions.get(plain), narrow)
                .add(instruction->getOperand(1))
                .add(instruction->getOperand(2))
                .cloneMemRefs(*instruction);
            BuildMI(block, *instruction, location, instructions.get(TargetOpcode::SUBREG_TO_REG), wide).addReg(narrow, RegState::Kill).addImm(lowWord);
            BuildMI(block, *instruction, location, instructions.get(extend), destination.getReg()).addReg(wide, RegState::Kill);
            instruction->eraseFromParent();
        }
        bpf::stats() << "bpf-machine-arena-sext: " << function.getName() << ", " << work.size() << " sign-extending loads lowered\n";
        return true;
    }
};

char BPFMachineArenaSext::ID = 0;
static RegisterPass<BPFMachineArenaSext> RegisterMachineArenaSext("bpf-machine-arena-sext", "BPF sign-extending load lowering", false, false);

// Immediately after selection: every BPF_MEMSX in the function is visible,
// registers are still virtual, and no later Capsule or BPF pass introduces
// another one.
static RegisterTargetPassConfigCallback RegisterArenaSextPipeline([](TargetMachine& machine, PassManagerBase&, TargetPassConfig* config) {
    if (ArenaSignedLoadLowering && machine.getTargetTriple().isBPF()) {
        config->insertPass(&FinalizeISelID, &BPFMachineArenaSext::ID);
    }
});

} // namespace
