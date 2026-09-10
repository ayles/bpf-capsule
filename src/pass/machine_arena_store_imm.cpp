// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Replace a store-immediate whose offset needs a register with a register
// store, for target JITs that lose the arena address while forming it.
//
// The arm64 JIT of Linux 6.10 through 6.17 computes an arena store's address
// into its second scratch register, and then, when the byte offset does not
// fit the scaled unsigned immediate of an arm64 store (a negative offset, one
// not a multiple of the access width, or one past 4095 units), materializes
// that offset into the same scratch register before the store. The address is
// gone by the time the store issues, so the write lands at a nonsense address,
// faults, and the arena's exception fixup swallows it silently. Loads and
// register stores pick a different scratch register and are unaffected.
//
// Introduced by 339af577ec05 ("bpf: Add arm64 JIT support for PROBE_MEM32
// pseudo instructions"), first released in 6.10, and fixed by be708ed300e1
// ("bpf/arm64: Fix BPF_ST into arena memory"), first released in 6.18, which
// gives the address a scratch register of its own. The fix carries no stable
// tag and 6.12.y does not have it, so the 6.12 LTS is affected throughout.
// https://lore.kernel.org/r/20251030121715.55214-1-puranjay@kernel.org
//
// Capsule builds software frames whose locals and outgoing linkage sit below
// the frame pointer, so every constant written into a frame is exactly this
// instruction shape; a dropped store of a return region id ends a computation
// early and reports it as a success. Feeding the value through a register
// instead costs one instruction and only for the offsets that would take the
// broken path.
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
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Target/RegisterTargetPassConfigCallback.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;

namespace {

cl::opt<bool> ArenaStoreImmediateLowering(
    "bpf-machine-arena-store-imm", cl::desc("Feed a store-immediate through a register when its offset needs one"), cl::init(false), cl::Hidden);

// The selected store-immediate, the register store of the same width, and the
// access width the target scales its immediate offset by.
struct Lowering {
    StringRef Immediate;
    StringRef Register;
    int64_t Width;
};

constexpr Lowering Lowerings[] = {
    {"STB_imm", "STB", 1},
    {"STH_imm", "STH", 2},
    {"STW_imm", "STW", 4},
    {"STD_imm", "STD", 8},
};

// Exactly the arm64 JIT's is_lsi_offset(): the scaled unsigned immediate form
// of an arm64 store. Anything else takes the register-offset path.
bool OffsetFitsScaledImmediate(int64_t offset, int64_t width) {
    return offset >= 0 && offset <= 0xfff * width && offset % width == 0;
}

unsigned opcodeByName(const TargetInstrInfo& instructions, StringRef name) {
    for (unsigned opcode = 0, end = instructions.getNumOpcodes(); opcode < end; ++opcode) {
        if (instructions.getName(opcode) == name) {
            return opcode;
        }
    }
    report_fatal_error(Twine("bpf-machine-arena-store-imm: the target has no ") + name + " instruction", /*gen_crash_diag=*/false);
}

class BPFMachineArenaStoreImm : public MachineFunctionPass {
public:
    static char ID;

    BPFMachineArenaStoreImm()
        : MachineFunctionPass(ID) {
    }

    StringRef getPassName() const override {
        return "BPF store-immediate lowering";
    }

    bool runOnMachineFunction(MachineFunction& function) override {
        const TargetInstrInfo& instructions = *function.getSubtarget().getInstrInfo();
        MachineRegisterInfo& virtualRegisters = function.getRegInfo();

        SmallVector<std::pair<MachineInstr*, const Lowering*>> work;
        for (MachineBasicBlock& block : function) {
            for (MachineInstr& instruction : block) {
                for (const Lowering& lowering : Lowerings) {
                    if (instructions.getName(instruction.getOpcode()) != lowering.Immediate) {
                        continue;
                    }
                    // A frame index still stands in for the base here; the
                    // target resolves those against its own stack pointer and
                    // never takes the broken path.
                    const MachineOperand& base = instruction.getOperand(1);
                    const MachineOperand& offset = instruction.getOperand(2);
                    if (base.isReg() && offset.isImm() && !OffsetFitsScaledImmediate(offset.getImm(), lowering.Width)) {
                        work.emplace_back(&instruction, &lowering);
                    }
                    break;
                }
            }
        }
        if (work.empty()) {
            return false;
        }

        const unsigned move = opcodeByName(instructions, "MOV_ri");
        const unsigned wideMove = opcodeByName(instructions, "LD_imm64");
        for (auto&& [instruction, lowering] : work) {
            const unsigned store = opcodeByName(instructions, lowering->Register);
            MachineBasicBlock& block = *instruction->getParent();
            const DebugLoc& location = instruction->getDebugLoc();
            const int64_t value = instruction->getOperand(0).getImm();
            // MOV_ri carries a sign-extended 32-bit field. A store-immediate
            // of a wider value keeps its bits through the 64-bit form.
            const bool wide = !isInt<32>(value);
            const unsigned materialize = wide ? wideMove : move;

            Register held = virtualRegisters.createVirtualRegister(instructions.getRegClass(instructions.get(store), 0));
            BuildMI(block, *instruction, location, instructions.get(materialize), held).addImm(value);
            BuildMI(block, *instruction, location, instructions.get(store))
                .addReg(held, RegState::Kill)
                .add(instruction->getOperand(1))
                .add(instruction->getOperand(2))
                .cloneMemRefs(*instruction);
            instruction->eraseFromParent();
        }
        bpf::stats() << "bpf-machine-arena-store-imm: " << function.getName() << ", " << work.size() << " store-immediates lowered\n";
        return true;
    }
};

char BPFMachineArenaStoreImm::ID = 0;
static RegisterPass<BPFMachineArenaStoreImm> RegisterMachineArenaStoreImm("bpf-machine-arena-store-imm", "BPF store-immediate lowering", false, false);

// Immediately after selection, beside the sign-extending load lowering:
// registers are still virtual and no later pass introduces another
// store-immediate.
static RegisterTargetPassConfigCallback RegisterArenaStoreImmPipeline([](TargetMachine& machine, PassManagerBase&, TargetPassConfig* config) {
    if (ArenaStoreImmediateLowering && machine.getTargetTriple().isBPF()) {
        config->insertPass(&FinalizeISelID, &BPFMachineArenaStoreImm::ID);
    }
});

} // namespace
