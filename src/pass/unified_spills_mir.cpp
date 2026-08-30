// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-unified-spills — physical spill slots to unified fiber memory.
//
// The 512-byte BPF stack is consumed by register spills, created by the
// register allocator below anything an IR pass can reach. This pass runs
// post-PEI, before the stock machine block-placement pass. Flattening joins
// the independently allocated regions at that boundary, so placement sees
// the real emitted CFG; a final pass then repairs target/verifier layout
// constraints while stock LLVM still owns branch offsets, relocations,
// symbols and BTF emission.
//
// Spill words whose contents are provably scalar move into a transient extent
// at the low end of the current fiber's existing unified stack. Managed
// frames grow down from the high end; an anchor supplies the resolved backing
// pointer and current managed SP. Stackify bounds every descent against the
// transient reserve, while this pass proves that the relocated extent fits in
// that reserve; no per-spill collision check is needed.
// Words holding a rematerializable ld_imm64+const pointer are deleted and
// their reloads recomputed; everything else stays on the real BPF stack. No
// register can be reserved without rebuilding LLVM, so the managed base is
// borrowed: a spill saves one register to a fixed stack slot, loads the base,
// stores through it and restores. Fills are cheaper: the destination is its
// own scratch.
//
// The verifier drives the analysis:
//  - a scalar reloaded from map memory is unbounded, and `map_ptr += scalar`
//    with unbounded smin is rejected at the add: track AND-masks (including
//    alignment masks from shifts) and re-apply the mask after the fill —
//    identity on the value, umin/umax for the verifier;
//  - a mask can still be too wide for an access at [ptr + disp]: at a
//    pointer-add the masked tainted addend becomes a pending obligation with
//    budget = region_size - mask, checked against disp+width at every access
//    through that pointer; a violation pins the source word to the stack;
//  - storing a maybe-uninitialized register is itself rejected: the borrow
//    register at each spill site must be definitely written.
//
// This pass avoids BPF target internals (no such headers ship with stock
// LLVM): opcodes are classified by name, registers matched by name.
#include "common.h"
#include "machine_flatten.h"
#include "machine_stack_budget.h"
#include "runtime_symbols.h"
#include "target.h"
#include "bpf_capsule_abi.h"

#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/RegisterTargetPassConfigCallback.h"
#include "llvm/Target/TargetMachine.h"

#include <bit>
#include <bitset>
#include <map>
#include <set>
#include <string_view>
#include <vector>

using namespace llvm;

static cl::opt<int> UnifiedSpillLimit(
    "bpf-unified-spill-limit", cl::init(512), cl::desc("Optional cap on the post-RA call-graph-derived Capsule frame budget"));
static cl::opt<bool> UnifiedSpillPipeline(
    "bpf-unified-spill-pipeline", cl::init(false), cl::desc("Run post-RA spill relocation and machine flattening in normal llc"));

namespace {

// ------------------------------------------------------------ opcode classes

struct OpInfo {
    enum Kind { Other, LdImm64, Load, Store, StoreImm, Alu, Copy, Call, Branch, Ret, Atomic, AddrSpaceCast } kind = Other;
    enum AluOp { None, Mov, Add, Sub, And, Sll, Srl, OtherAlu } alu = None;
    int width = 0;       // memory ops: bytes
    bool immSrc = false; // ALU: _ri form
    bool is32 = false;   // ALU32 / 32-bit dst
};

constexpr bool IsAtomicOpcodeName(std::string_view name) {
    return name.starts_with("XADD") || name.starts_with("XAND") || (name.starts_with("XOR") && !name.starts_with("XOR_")) || name.starts_with("XXOR") ||
        name.starts_with("XF") || name.starts_with("XCHG") || name.starts_with("CMPXCHG");
}

constexpr bool IsImmediateAluOpcodeName(std::string_view name) {
    auto token = [&](std::string_view spelling) {
        size_t at = name.find(spelling);
        return at != std::string_view::npos && (at + spelling.size() == name.size() || name[at + spelling.size()] == '_');
    };
    return token("_ri") || token("_i");
}

// The one-character distinction is easy to regress and changes verifier
// taint propagation rather than merely code quality.
static_assert(!IsAtomicOpcodeName("XOR_rr"));
static_assert(!IsAtomicOpcodeName("XOR_ri"));
static_assert(IsAtomicOpcodeName("XORD"));
static_assert(IsAtomicOpcodeName("XFXORD"));
static_assert(!IsImmediateAluOpcodeName("XOR_rr"));
static_assert(IsImmediateAluOpcodeName("XOR_ri"));
static_assert(IsImmediateAluOpcodeName("XOR_ri_32"));
static_assert(!IsImmediateAluOpcodeName("ODD_iota_name"));

OpInfo classifyName(StringRef n) {
    OpInfo o;
    auto mem = [&](OpInfo::Kind k, int w) {
        o.kind = k;
        o.width = w;
        return o;
    };
    if (n == "LD_imm64") {
        o.kind = OpInfo::LdImm64;
        return o;
    }
    if (n == "COPY") {
        o.kind = OpInfo::Copy;
        return o;
    }
    if (n == "ADDR_SPACE_CAST") {
        o.kind = OpInfo::AddrSpaceCast;
        return o;
    }
    if (n == "LDD") {
        return mem(OpInfo::Load, 8);
    }
    if (n == "LDW" || n == "LDW32") {
        return mem(OpInfo::Load, 4);
    }
    if (n == "LDH" || n == "LDH32") {
        return mem(OpInfo::Load, 2);
    }
    if (n == "LDB" || n == "LDB32") {
        return mem(OpInfo::Load, 1);
    }
    if (n == "STD") {
        return mem(OpInfo::Store, 8);
    }
    if (n == "STW" || n == "STW32") {
        return mem(OpInfo::Store, 4);
    }
    if (n == "STH" || n == "STH32") {
        return mem(OpInfo::Store, 2);
    }
    if (n == "STB" || n == "STB32") {
        return mem(OpInfo::Store, 1);
    }
    if (n.starts_with("ST") && n.contains("_imm")) {
        return mem(OpInfo::StoreImm, n.starts_with("STD") ? 8 : n.starts_with("STW") ? 4 : n.starts_with("STH") ? 2 : 1);
    }
    if (n.starts_with("JAL")) {
        o.kind = OpInfo::Call;
        return o;
    }
    if (n == "RETURN" || n.starts_with("RET")) {
        o.kind = OpInfo::Ret;
        return o;
    }
    if (n.starts_with("J")) {
        o.kind = OpInfo::Branch;
        return o;
    }
    // Atomic xor is XORW32/XORD — one underscore away from the plain ALU xor
    // (XOR_rr, XOR_ri), which must fall through to the ALU roots below so its
    // taint propagates. XF* covers the fetch variants (XFADD, XFOR, XFXOR...).
    if (IsAtomicOpcodeName(std::string_view(n.data(), n.size()))) {
        o.kind = OpInfo::Atomic;
        return o;
    }
    // ALU: ROOT[_32]?_(rr|ri)[_32]?
    auto root = [&](StringRef r, OpInfo::AluOp op) {
        if (n.starts_with(r)) {
            o.kind = OpInfo::Alu;
            o.alu = op;
            o.immSrc = IsImmediateAluOpcodeName(std::string_view(n.data(), n.size()));
            o.is32 = n.contains("32");
            return true;
        }
        return false;
    };
    if (root("MOV_", OpInfo::Mov) || root("ADD_", OpInfo::Add) || root("SUB_", OpInfo::Sub) || root("AND_", OpInfo::And) || root("SLL_", OpInfo::Sll) ||
        root("SRL_", OpInfo::Srl)) {
        return o;
    }
    if (root("MUL_", OpInfo::OtherAlu) || root("DIV_", OpInfo::OtherAlu) || root("MOD_", OpInfo::OtherAlu) || root("OR_", OpInfo::OtherAlu) ||
        root("XOR_", OpInfo::OtherAlu) || root("SRA_", OpInfo::OtherAlu) || root("NEG", OpInfo::OtherAlu) || root("BSWAP", OpInfo::OtherAlu) ||
        root("BE", OpInfo::OtherAlu) || root("LE", OpInfo::OtherAlu)) {
        return o;
    }
    return o;
}

// MachineInstr::defs() covers the conventional leading-def operand layout.
// INLINEASM instead interleaves descriptor immediates, explicit uses and
// implicit defs, so a dataflow pass must inspect every operand's def flag.
template <typename Visitor>
void ForEachRegisterDef(MachineInstr& instruction, Visitor&& visit) {
    for (MachineOperand& operand : instruction.operands()) {
        if (operand.isReg() && operand.isDef()) {
            visit(operand);
        }
    }
}

// ------------------------------------------------------------- value lattice

// A mask is usable only if one AND-immediate can re-apply it after a unified
// reload: a 32-bit value mask through ALU32 (which also proves the zero
// upper half), or a sign-extended immediate through ALU64 (alignment masks).
bool maskEncodable(uint64_t m) {
    return m <= 0xffffffffull || (uint64_t)(int64_t)(int32_t)(uint32_t)m == m;
}

// What a register (or stack word) holds, as far as relocation cares.
//   Scalar  — provably not a pointer: safe through map memory
//   Masked  — scalar known to fit under an AND mask (re-appliable)
//   Remat   — ld_imm64(global)+const: delete the spill, recompute at reloads
//   Unknown — could be a verifier-tracked pointer: stays on the stack
struct Val {
    //   Arena — a bpf_arena pointer built by ADDR_SPACE_CAST from a scalar.
    //           It cannot be stored as a pointer (map memory does not keep
    //           the type), but it can be cast back to its address, stored as
    //           a scalar, and cast forward again on reload — so it counts as
    //           relocatable, unlike any other pointer.
    enum K : uint8_t { Bot, Scalar, Masked, Remat, Arena, Unknown } k = Bot;
    const GlobalValue* gv = nullptr;
    int64_t add = 0;
    uint64_t msk = 0;

    static Val scalar() {
        return {Scalar, nullptr, 0, 0};
    }
    static Val masked(uint64_t m) {
        return maskEncodable(m) ? Val{Masked, nullptr, 0, m} : Val{Scalar, nullptr, 0, 0};
    }
    static Val unknown() {
        return {Unknown, nullptr, 0, 0};
    }
    static Val arena() {
        return {Arena, nullptr, 0, 0};
    }
    static Val remat(const GlobalValue* g, int64_t a) {
        return {Remat, g, a, 0};
    }
    bool scalarish() const {
        return k == Scalar || k == Masked;
    }
    bool operator==(const Val& o) const {
        if (k != o.k) {
            return false;
        }
        if (k == Remat) {
            return gv == o.gv && add == o.add;
        }
        if (k == Masked) {
            return msk == o.msk;
        }
        return true;
    }
};

Val join(const Val& a, const Val& b) {
    if (a.k == Val::Bot) {
        return b;
    }
    if (b.k == Val::Bot) {
        return a;
    }
    if (a == b) {
        return a;
    }
    if (a.k == Val::Masked && b.k == Val::Masked) {
        return Val::masked(a.msk | b.msk);
    }
    if (a.scalarish() && b.scalarish()) {
        return Val::scalar();
    }
    return Val::unknown();
}

struct State {
    // Only r0-r9 carry values worth tracking; r10 is the frame pointer and
    // is handled structurally, so it needs no lattice slot.
    Val reg[11];
    uint16_t initMask = 0;
    std::map<int32_t, Val> stack;
    bool reachable = false;

    bool merge(const State& o) {
        bool ch = false;
        if (!reachable) {
            *this = o;
            return true;
        }
        for (int i = 0; i < 11; i++) {
            Val j = join(reg[i], o.reg[i]);
            if (!(j == reg[i])) {
                reg[i] = j;
                ch = true;
            }
        }
        uint16_t m = initMask & o.initMask;
        if (m != initMask) {
            initMask = m;
            ch = true;
        }
        // Unlike register Bot, an absent stack word on one reachable edge is
        // not a useful identity: the other edge's store is not definite. A
        // later load must remain unknown/pinned (and the verifier may reject
        // the original uninitialized path), never be moved to pre-existing
        // unified memory as though every path had initialized it.
        for (auto& [k, v] : stack) {
            if (!o.stack.contains(k) && v.k != Val::Unknown) {
                v = Val::unknown();
                ch = true;
            }
        }
        for (auto& [k, v] : o.stack) {
            auto it = stack.find(k);
            if (it == stack.end()) {
                stack[k] = Val::unknown();
                ch = true;
            } else {
                Val j = join(it->second, v);
                if (!(j == it->second)) {
                    it->second = j;
                    ch = true;
                }
            }
        }
        return ch;
    }
};

struct Access {
    MachineInstr* mi;
    int32_t off;
    int width;
    bool isStore;
    Val seen;
    uint16_t initMask;
};

// A real-stack object whose address is passed to a helper.  Almost every
// source alloca has already moved to the managed/addressable stack before
// instruction selection; the important remaining case is the compiler-owned
// ARRAY-map lookup key.  PEI emits it as `dst = r10; dst += constant`.
// Relocating scalar spills around that object is safe, but the address-forming
// immediate must follow the object's new packed stack offset.
struct StackAddress {
    MachineInstr* add;
    int32_t off;
    int32_t objectLow;
    int32_t objectHigh;
};

//   UnifiedArena — relocated like Unified, but the value is cast to its address
//               before the store and back to a pointer after the load.
enum class SlotClass { Stack, Unified, UnifiedArena, Remat };

// ---------------------------------------------------------------------- pass

struct BPFUnifiedSpillsMIR : MachineFunctionPass {
    static constexpr unsigned PhysicalRegisterTableSize = 1024;

    static char ID;
    BPFUnifiedSpillsMIR()
        : MachineFunctionPass(ID) {
    }
    StringRef getPassName() const override {
        return "BPF spill slots to unified fiber stack";
    }

    const TargetInstrInfo* TII = nullptr;
    // Whether a relocated scalar has to come back with verifier-visible
    // bounds. It does when addresses are map values, whose arithmetic the
    // verifier bounds-checks; it does not with bpf_arena, where the mapping
    // itself catches out-of-range accesses and pointer arithmetic needs no
    // proof. Skipping the taint/budget analysis there is most of the pass's
    // cost on large functions.
    bool regsDone = false;
    bool emittedOpcodesDone = false;
    std::vector<OpInfo> opInfo;            // by opcode
    std::vector<bool> opInfoDone;          // classified in this instance
    int regIdx[PhysicalRegisterTableSize]; // phys reg -> 0..10, -1 other
    unsigned regOf[11];                    // 0..10 -> 64-bit phys reg
    unsigned wregOf[11];                   // 0..10 -> 32-bit phys reg
    unsigned opSTD = 0, opSTDimm = 0, opSTWimm = 0, opLDD = 0, opLDimm = 0, opADDri = 0, opANDri = 0, opANDri32 = 0;
    unsigned opCast = 0, opMOVri32 = 0, opJULTri = 0, opJMP = 0, opRET = 0;
    std::set<MachineInstr*> arenaRepairStackAccesses;
    std::set<int32_t> arenaPointerStackWords;

    const OpInfo& info(const MachineInstr& MI) {
        unsigned op = MI.getOpcode();
        if (op >= opInfo.size()) {
            opInfo.resize(op + 1);
        }
        if (opInfoDone.size() < opInfo.size()) {
            opInfoDone.resize(opInfo.size());
        }
        if (!opInfoDone[op]) {
            opInfo[op] = classifyName(TII->getName(op));
            opInfoDone[op] = true;
        }
        return opInfo[op];
    }

    int ridx(const MachineOperand& mo) const {
        if (!mo.isReg() || !mo.getReg().isPhysical()) {
            return -1;
        }
        unsigned r = mo.getReg().id();
        return r < PhysicalRegisterTableSize ? regIdx[r] : -1;
    }

    bool runOnMachineFunction(MachineFunction& MF) override;
    unsigned fixArenaPointerArithmetic(MachineFunction& MF);
    bool analyze(MachineFunction& MF, std::vector<Access>& accesses, std::vector<StackAddress>& stackAddresses, int32_t& frameLow, std::string& bailWhy,
        int physicalLimit);
};

char BPFUnifiedSpillsMIR::ID = 0;

// LLVM's ordinary integer view of an arena address leaves two verifier-invalid
// instruction forms after allocation:
//
//   scalar += arena_pointer       (a commuted GEP)
//   scalar -= arena_pointer       (an integer pointer difference)
//
// The first must keep the pointer in the ADD destination. The second must cast
// the pointer operand back to its scalar address before SUB; when both operands
// are arena pointers, both are scalarized. Pointer-minus-scalar remains normal
// arena address arithmetic.
//
// Repair this after allocation, where operand order and liveness are final. A
// live pointer is copied to a dead register, or saved and restored through one
// native stack word which the spill planner pins in its reserved slack.
unsigned BPFUnifiedSpillsMIR::fixArenaPointerArithmetic(MachineFunction& MF) {
    unsigned mov = 0, castOp = 0, stdOp = 0, lddOp = 0;
    for (unsigned op = 0; op < TII->getNumOpcodes(); op++) {
        StringRef name = TII->getName(op);
        if (name == "MOV_rr") {
            mov = op;
        } else if (name == "ADDR_SPACE_CAST") {
            castOp = op;
        } else if (name == "STD") {
            stdOp = op;
        } else if (name == "LDD") {
            lddOp = op;
        }
    }
    if (!mov || !castOp || !stdOp || !lddOp) {
        report_fatal_error("bpf-arena-arith: required opcodes not found");
    }

    arenaRepairStackAccesses.clear();
    arenaPointerStackWords.clear();
    int32_t frameLow = 0;
    for (MachineBasicBlock& block : MF) {
        for (MachineInstr& MI : block) {
            const OpInfo& oi = info(MI);
            if ((oi.kind == OpInfo::Load || oi.kind == OpInfo::Store || oi.kind == OpInfo::StoreImm) && MI.getNumOperands() >= 3 && MI.getOperand(1).isReg() &&
                MI.getOperand(2).isImm() && ridx(MI.getOperand(1)) == 10) {
                frameLow = std::min(frameLow, (int32_t)MI.getOperand(2).getImm());
            }
        }
    }
    const int32_t pointerSaveOffset = (frameLow & ~7) - 8;

    std::map<MachineInstr*, uint16_t> deadAfter;
    const TargetRegisterInfo* TRI = MF.getSubtarget().getRegisterInfo();
    const MachineRegisterInfo& MRI = MF.getRegInfo();
    for (MachineBasicBlock& block : MF) {
        LivePhysRegs live(*TRI);
        live.addLiveOuts(block);
        for (auto it = block.rbegin(); it != block.rend(); ++it) {
            uint16_t dead = 0;
            for (int reg = 0; reg <= 9; reg++) {
                if (live.available(MRI, regOf[reg])) {
                    dead |= 1u << reg;
                }
            }
            deadAfter[&*it] = dead;
            live.stepBackward(*it);
        }
    }

    struct ArenaFacts {
        std::bitset<11> May;
        std::bitset<11> Must;
        // LLVM can spill an arena pointer before the prohibited arithmetic
        // which this pass repairs.  Track exact 64-bit frame words as part of
        // the same lattice; otherwise an LDD turns a definite pointer into an
        // apparently scalar register and the commuted ADD is missed.
        std::set<int32_t> StackMay;
        std::set<int32_t> StackMust;
    };

    unsigned fixed = 0;
    auto step = [&](MachineBasicBlock& block, MachineInstr& MI, ArenaFacts& arena, bool repair) {
        const OpInfo& oi = info(MI);
        int addDest = -1, addSource = -1, addBorrowed = -1;
        bool addDestMust = false, addSourceMust = false;

        if (repair && oi.kind == OpInfo::Alu && oi.alu == OpInfo::Add && !oi.immSrc && !oi.is32 && MI.getNumOperands() >= 3 && MI.getOperand(0).isReg() &&
            MI.getOperand(1).isReg() && MI.getOperand(2).isReg()) {
            int d = ridx(MI.getOperand(0));
            int lhs = ridx(MI.getOperand(1));
            int rhs = ridx(MI.getOperand(2));
            if (d >= 0 && d == lhs && rhs >= 0 && !arena.May.test(lhs) && arena.May.test(rhs)) {
                Register scalar = MI.getOperand(1).getReg();
                Register pointer = MI.getOperand(2).getReg();
                bool scalarKill = MI.getOperand(1).isKill();
                bool pointerKill = MI.getOperand(2).isKill();

                Register destination = pointer;
                if (!pointerKill) {
                    uint16_t dead = deadAfter[&MI];
                    for (int candidate = 0; candidate <= 9; candidate++) {
                        if (candidate != d && candidate != rhs && (dead & (1u << candidate))) {
                            addBorrowed = candidate;
                            break;
                        }
                    }
                    if (addBorrowed >= 0) {
                        destination = regOf[addBorrowed];
                        BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(mov), destination).addReg(pointer);
                    } else {
                        MachineInstr* save =
                            BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(stdOp)).addReg(pointer).addReg(regOf[10]).addImm(pointerSaveOffset);
                        arenaRepairStackAccesses.insert(save);
                    }
                }

                MI.getOperand(0).setReg(destination);
                MI.getOperand(1).setReg(destination);
                MI.getOperand(1).setIsKill(true);
                MI.getOperand(2).setReg(scalar);
                MI.getOperand(2).setIsKill(scalarKill);
                MachineInstr* resultMove =
                    BuildMI(block, std::next(MI.getIterator()), MI.getDebugLoc(), TII->get(mov), scalar).addReg(destination, RegState::Kill);
                if (!pointerKill && addBorrowed < 0) {
                    MachineInstr* restore = BuildMI(block, std::next(resultMove->getIterator()), MI.getDebugLoc(), TII->get(lddOp), pointer)
                                                .addReg(regOf[10])
                                                .addImm(pointerSaveOffset);
                    arenaRepairStackAccesses.insert(restore);
                }
                addDest = d;
                addSource = rhs;
                // Both registers hold the same pointer after the operand
                // swap and result move, so their definite-pointer facts are
                // intentionally identical.
                addDestMust = arena.Must.test(rhs);
                addSourceMust = arena.Must.test(rhs);
                fixed++;
            }
        }

        int subDest = -1, subSource = -1, subBorrowed = -1;
        bool subSourcePreserved = false;
        if (repair && oi.kind == OpInfo::Alu && oi.alu == OpInfo::Sub && !oi.immSrc && !oi.is32 && MI.getNumOperands() >= 3 && MI.getOperand(0).isReg() &&
            MI.getOperand(1).isReg() && MI.getOperand(2).isReg()) {
            int d = ridx(MI.getOperand(0));
            int lhs = ridx(MI.getOperand(1));
            int rhs = ridx(MI.getOperand(2));
            if (d >= 0 && d == lhs && rhs >= 0 && arena.May.test(rhs)) {
                if (!arena.Must.test(rhs) || (arena.May.test(lhs) && !arena.Must.test(lhs))) {
                    errs() << "bpf-arena-arith: ambiguous pointer difference in " << MF.getName() << " (lhs r" << lhs << " may=" << arena.May.test(lhs)
                           << " must=" << arena.Must.test(lhs) << ", rhs r" << rhs << " may=" << arena.May.test(rhs) << " must=" << arena.Must.test(rhs)
                           << "): ";
                    MI.print(errs());
                    report_fatal_error(Twine("bpf-arena-arith: ambiguous pointer difference in ") + MF.getName());
                }

                if (arena.Must.test(lhs)) {
                    BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(castOp), MI.getOperand(1).getReg())
                        .addReg(MI.getOperand(1).getReg())
                        .addImm(1)
                        .addImm(0);
                }

                if (rhs != lhs) {
                    Register pointer = MI.getOperand(2).getReg();
                    bool pointerKill = MI.getOperand(2).isKill();
                    Register scalar = pointer;
                    if (!pointerKill) {
                        uint16_t dead = deadAfter[&MI];
                        for (int candidate = 0; candidate <= 9; candidate++) {
                            if (candidate != d && candidate != rhs && (dead & (1u << candidate))) {
                                subBorrowed = candidate;
                                break;
                            }
                        }
                        if (subBorrowed >= 0) {
                            scalar = regOf[subBorrowed];
                            BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(mov), scalar).addReg(pointer);
                            subSourcePreserved = true;
                        } else {
                            MachineInstr* save =
                                BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(stdOp)).addReg(pointer).addReg(regOf[10]).addImm(pointerSaveOffset);
                            arenaRepairStackAccesses.insert(save);
                            subSourcePreserved = true;
                        }
                    }
                    BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(castOp), scalar).addReg(scalar).addImm(1).addImm(0);
                    MI.getOperand(2).setReg(scalar);
                    MI.getOperand(2).setIsKill(true);

                    if (!pointerKill && subBorrowed < 0) {
                        MachineInstr* restore =
                            BuildMI(block, std::next(MI.getIterator()), MI.getDebugLoc(), TII->get(lddOp), pointer).addReg(regOf[10]).addImm(pointerSaveOffset);
                        arenaRepairStackAccesses.insert(restore);
                    }
                }
                subDest = d;
                subSource = rhs;
                fixed++;
            }
        }

        bool resultMayArena = false, resultMustArena = false;
        int result = -1;
        if (arenaRepairStackAccesses.count(&MI) && oi.kind == OpInfo::Load) {
            result = ridx(MI.getOperand(0));
            resultMayArena = resultMustArena = true;
        } else if (oi.kind == OpInfo::Load && oi.width == 8 && MI.getNumOperands() >= 3 && MI.getOperand(0).isReg() && MI.getOperand(1).isReg() &&
            MI.getOperand(2).isImm() && ridx(MI.getOperand(1)) == 10) {
            result = ridx(MI.getOperand(0));
            int64_t off64 = MI.getOperand(2).getImm();
            if (off64 >= INT32_MIN && off64 <= INT32_MAX && off64 % 8 == 0) {
                int32_t off = (int32_t)off64;
                resultMayArena = arena.StackMay.count(off);
                resultMustArena = arena.StackMust.count(off);
            }
        } else if (oi.kind == OpInfo::AddrSpaceCast && MI.getNumOperands() > 3 && MI.getOperand(3).isImm()) {
            result = ridx(MI.getOperand(0));
            resultMayArena = resultMustArena = MI.getOperand(3).getImm() == 1;
        } else if (oi.kind == OpInfo::Copy && MI.getNumOperands() > 1) {
            result = ridx(MI.getOperand(0));
            int source = ridx(MI.getOperand(1));
            resultMayArena = source >= 0 && arena.May.test(source);
            resultMustArena = source >= 0 && arena.Must.test(source);
        } else if (oi.kind == OpInfo::Alu && MI.getNumOperands() > 1) {
            result = ridx(MI.getOperand(0));
            if (oi.alu == OpInfo::Mov && !oi.immSrc) {
                int source = ridx(MI.getOperand(1));
                resultMayArena = source >= 0 && arena.May.test(source);
                resultMustArena = source >= 0 && arena.Must.test(source);
            } else if (oi.alu == OpInfo::Add && !oi.is32) {
                int lhs = ridx(MI.getOperand(1));
                int rhs = !oi.immSrc && MI.getNumOperands() > 2 ? ridx(MI.getOperand(2)) : -1;
                bool lhsMay = lhs >= 0 && arena.May.test(lhs);
                bool rhsMay = rhs >= 0 && arena.May.test(rhs);
                bool lhsMust = lhs >= 0 && arena.Must.test(lhs);
                bool rhsMust = rhs >= 0 && arena.Must.test(rhs);
                resultMayArena = lhsMay || rhsMay;
                resultMustArena = (lhsMust && !rhsMay) || (rhsMust && !lhsMay);
            } else if (oi.alu == OpInfo::Sub && !oi.is32) {
                int lhs = ridx(MI.getOperand(1));
                int rhs = !oi.immSrc && MI.getNumOperands() > 2 ? ridx(MI.getOperand(2)) : -1;
                bool rhsMay = rhs >= 0 && arena.May.test(rhs);
                resultMayArena = lhs >= 0 && arena.May.test(lhs) && !rhsMay;
                resultMustArena = lhs >= 0 && arena.Must.test(lhs) && !rhsMay;
            }
        }

        // A narrow or unaligned write destroys the pointer type of every
        // overlapping spill word.  An exact STD replaces that word with the
        // source register's current arena facts.  Use half-open byte ranges:
        // BPF frame offsets are negative, but their ordering is ordinary.
        if ((oi.kind == OpInfo::Store || oi.kind == OpInfo::StoreImm) && oi.width > 0 && MI.getNumOperands() >= 3 && MI.getOperand(1).isReg() &&
            MI.getOperand(2).isImm() && ridx(MI.getOperand(1)) == 10) {
            int64_t off64 = MI.getOperand(2).getImm();
            if (off64 >= INT32_MIN && off64 <= INT32_MAX) {
                int32_t off = (int32_t)off64;
                auto eraseOverlaps = [&](std::set<int32_t>& words) {
                    for (auto it = words.begin(); it != words.end();) {
                        int64_t wordBegin = *it;
                        int64_t wordEnd = wordBegin + 8;
                        int64_t storeEnd = off64 + oi.width;
                        if (wordBegin < storeEnd && off64 < wordEnd) {
                            it = words.erase(it);
                        } else {
                            ++it;
                        }
                    }
                };
                eraseOverlaps(arena.StackMay);
                eraseOverlaps(arena.StackMust);

                if (oi.kind == OpInfo::Store && oi.width == 8 && off % 8 == 0 && MI.getOperand(0).isReg()) {
                    int source = ridx(MI.getOperand(0));
                    if (source >= 0 && arena.May.test(source)) {
                        arena.StackMay.insert(off);
                    }
                    if (source >= 0 && arena.Must.test(source)) {
                        arena.StackMust.insert(off);
                    }
                }
            }
        }

        ForEachRegisterDef(MI, [&](MachineOperand& def) {
            int reg = ridx(def);
            if (reg >= 0) {
                arena.May.reset(reg);
                arena.Must.reset(reg);
            }
        });
        if (result >= 0) {
            arena.May.set(result, resultMayArena);
            arena.Must.set(result, resultMustArena);
        }
        if (oi.kind == OpInfo::Call) {
            for (int reg = 0; reg <= 5; reg++) {
                arena.May.reset(reg);
                arena.Must.reset(reg);
            }
        }

        // The added instructions around a repaired operation are skipped by
        // this iterator. Record the facts after each complete sequence.
        if (addDest >= 0) {
            arena.May.set(addDest);
            arena.Must.set(addDest, addDestMust);
            arena.May.set(addSource);
            arena.Must.set(addSource, addSourceMust);
            if (addBorrowed >= 0) {
                arena.May.set(addBorrowed);
                arena.Must.set(addBorrowed, addDestMust);
            }
        }
        if (subDest >= 0) {
            arena.May.reset(subDest);
            arena.Must.reset(subDest);
            if (subSource != subDest && !subSourcePreserved) {
                arena.May.reset(subSource);
                arena.Must.reset(subSource);
            }
            if (subBorrowed >= 0) {
                arena.May.reset(subBorrowed);
                arena.Must.reset(subBorrowed);
            }
        }
    };

    // May uses union at a CFG join; Must uses intersection. A continuation
    // reload is scalar to the verifier while the uninterrupted path can carry
    // the same semantic pointer as PTR_TO_ARENA. Before scalarizing a pointer
    // difference, normalize every mixed operand on its pointer-carrying
    // incoming edges. This is edge-specific and type-correct on both paths;
    // blindly casting a mixed value in the join block would not be.
    std::map<MachineBasicBlock*, ArenaFacts> incoming, outgoing;
    std::set<MachineBasicBlock*> reachable;
    auto analyzeFacts = [&]() {
        incoming.clear();
        outgoing.clear();
        reachable = {&MF.front()};
        std::vector<MachineBasicBlock*> work{&MF.front()};
        while (!work.empty()) {
            MachineBasicBlock* block = work.back();
            work.pop_back();
            ArenaFacts state = incoming[block];
            for (MachineInstr& MI : *block) {
                step(*block, MI, state, false);
            }
            outgoing[block] = state;
            for (MachineBasicBlock* successor : block->successors()) {
                bool changed = false;
                if (reachable.insert(successor).second) {
                    incoming[successor] = state;
                    changed = true;
                } else {
                    ArenaFacts joined = incoming[successor];
                    joined.May |= state.May;
                    joined.Must &= state.Must;
                    joined.StackMay.insert(state.StackMay.begin(), state.StackMay.end());
                    for (auto it = joined.StackMust.begin(); it != joined.StackMust.end();) {
                        if (!state.StackMust.count(*it)) {
                            it = joined.StackMust.erase(it);
                        } else {
                            ++it;
                        }
                    }
                    if (joined.May != incoming[successor].May || joined.Must != incoming[successor].Must || joined.StackMay != incoming[successor].StackMay ||
                        joined.StackMust != incoming[successor].StackMust) {
                        incoming[successor] = joined;
                        changed = true;
                    }
                }
                if (changed) {
                    work.push_back(successor);
                }
            }
        }
    };

    // Register allocation can realize a mixed pointer/scalar PHI through one
    // native-stack word instead of one physical register. When that value is
    // consumed by a pointer difference, scalarize its definite-pointer
    // reaching stores just as the register case below scalarizes pointer
    // incoming edges. Stop at the nearest overlapping write on every path:
    // physical stack offsets are reusable, so older stores are another value.
    auto normalizeMixedStackLoad = [&](MachineInstr& load) {
        const OpInfo& loadInfo = info(load);
        if (loadInfo.kind != OpInfo::Load || loadInfo.width != 8 || load.getNumOperands() < 3 || !load.getOperand(1).isReg() || !load.getOperand(2).isImm() ||
            ridx(load.getOperand(1)) != 10) {
            report_fatal_error(Twine("bpf-arena-arith: malformed mixed stack origin in ") + MF.getName());
        }
        int64_t offset64 = load.getOperand(2).getImm();
        if (offset64 < INT32_MIN || offset64 > INT32_MAX || offset64 % 8) {
            report_fatal_error(Twine("bpf-arena-arith: unaligned mixed stack origin in ") + MF.getName());
        }

        DenseMap<MachineInstr*, ArenaFacts> factsBefore;
        for (MachineBasicBlock& block : MF) {
            if (!reachable.count(&block)) {
                continue;
            }
            ArenaFacts state = incoming[&block];
            for (MachineInstr& instruction : block) {
                factsBefore[&instruction] = state;
                step(block, instruction, state, false);
            }
        }

        struct SearchPoint {
            MachineBasicBlock* Block;
            MachineInstr* StopBefore;
        };
        SmallVector<SearchPoint, 8> work{{load.getParent(), &load}};
        SmallPtrSet<MachineBasicBlock*, 16> visited;
        SmallVector<MachineInstr*, 4> pointerStores;

        while (!work.empty()) {
            SearchPoint point = work.pop_back_val();
            if (!visited.insert(point.Block).second) {
                continue;
            }

            MachineInstr* reaching = nullptr;
            for (MachineInstr& instruction : *point.Block) {
                if (&instruction == point.StopBefore) {
                    break;
                }
                const OpInfo& oi = info(instruction);
                if ((oi.kind != OpInfo::Store && oi.kind != OpInfo::StoreImm) || !oi.width || instruction.getNumOperands() < 3 ||
                    !instruction.getOperand(1).isReg() || !instruction.getOperand(2).isImm() || ridx(instruction.getOperand(1)) != 10) {
                    continue;
                }
                int64_t writeOffset = instruction.getOperand(2).getImm();
                if (writeOffset < offset64 + 8 && offset64 < writeOffset + oi.width) {
                    reaching = &instruction;
                }
            }

            if (!reaching) {
                for (MachineBasicBlock* predecessor : point.Block->predecessors()) {
                    if (reachable.count(predecessor)) {
                        work.push_back({predecessor, nullptr});
                    }
                }
                continue;
            }

            const OpInfo& oi = info(*reaching);
            if (oi.kind != OpInfo::Store || oi.width != 8 || reaching->getOperand(2).getImm() != offset64 || !reaching->getOperand(0).isReg()) {
                continue; // a scalar or narrow overwrite ends this path
            }
            int source = ridx(reaching->getOperand(0));
            const ArenaFacts& before = factsBefore[reaching];
            if (source >= 0 && before.Must.test(source)) {
                pointerStores.push_back(reaching);
            } else if (source >= 0 && before.May.test(source)) {
                errs() << "bpf-arena-arith: nested mixed stack origin in " << MF.getName() << ": ";
                reaching->print(errs());
                report_fatal_error(Twine("bpf-arena-arith: cannot normalize nested mixed stack origin in ") + MF.getName());
            }
        }

        for (MachineInstr* store : pointerStores) {
            Register source = store->getOperand(0).getReg();
            BuildMI(*store->getParent(), store->getIterator(), store->getDebugLoc(), TII->get(castOp), source).addReg(source).addImm(1).addImm(0);
        }
        return !pointerStores.empty();
    };

    unsigned normalizedEdges = 0;
    for (unsigned round = 0;; round++) {
        if (round == 128) {
            report_fatal_error("bpf-arena-arith: edge normalization did not converge");
        }
        analyzeFacts();
        bool changed = false;

        for (MachineBasicBlock& block : MF) {
            if (!reachable.count(&block)) {
                continue;
            }
            ArenaFacts state = incoming[&block];
            int origin[11];
            MachineInstr* stackOrigin[11] = {};
            for (int reg = 0; reg <= 10; reg++) {
                origin[reg] = state.May.test(reg) && !state.Must.test(reg) ? reg : -1;
            }

            for (MachineInstr& MI : block) {
                const OpInfo& oi = info(MI);
                ArenaFacts before = state;

                if (oi.kind == OpInfo::Alu && oi.alu == OpInfo::Sub && !oi.immSrc && !oi.is32 && MI.getNumOperands() >= 3 && MI.getOperand(1).isReg() &&
                    MI.getOperand(2).isReg()) {
                    int lhs = ridx(MI.getOperand(1));
                    int rhs = ridx(MI.getOperand(2));
                    bool lhsMixed = lhs >= 0 && before.May.test(lhs) && !before.Must.test(lhs);
                    bool rhsMixed = rhs >= 0 && before.May.test(rhs) && !before.Must.test(rhs);
                    if (lhs >= 0 && rhs >= 0 && before.May.test(rhs) && (lhsMixed || rhsMixed)) {
                        // A suspended path reloads saved program pointers as
                        // scalars, while the uninterrupted path can reach the
                        // same SUB with PTR_TO_ARENA registers.  Normalize
                        // every mixed operand on the incoming pointer edges.
                        // A simultaneously definite pointer operand is cast
                        // here, so the SUB is scalar on every path even when
                        // the mixed operand was the RHS.
                        SmallVector<int, 2> roots;
                        SmallVector<int, 2> definite;
                        SmallVector<MachineInstr*, 2> stackRoots;
                        for (int reg : {lhs, rhs}) {
                            if (before.Must.test(reg)) {
                                if (!llvm::is_contained(definite, reg)) {
                                    definite.push_back(reg);
                                }
                            } else if (before.May.test(reg)) {
                                if (origin[reg] < 0 && !stackOrigin[reg]) {
                                    errs() << "bpf-arena-arith: lost mixed-pointer origin in " << MF.getName() << " block " << block.getNumber() << " for r"
                                           << reg << " (may=" << before.May.to_ulong() << ", must=" << before.Must.to_ulong() << "): ";
                                    MI.print(errs());
                                    report_fatal_error(Twine("bpf-arena-arith: mixed pointer has no incoming origin in ") + MF.getName());
                                }
                                if (stackOrigin[reg] && !llvm::is_contained(stackRoots, stackOrigin[reg])) {
                                    stackRoots.push_back(stackOrigin[reg]);
                                } else if (origin[reg] >= 0 && !llvm::is_contained(roots, origin[reg])) {
                                    roots.push_back(origin[reg]);
                                }
                            }
                        }

                        if (!stackRoots.empty()) {
                            bool normalized = false;
                            for (MachineInstr* originLoad : stackRoots) {
                                normalized |= normalizeMixedStackLoad(*originLoad);
                            }
                            if (!normalized) {
                                report_fatal_error(Twine("bpf-arena-arith: mixed stack origin has no pointer store in ") + MF.getName());
                            }
                            normalizedEdges += stackRoots.size();
                            changed = true;
                            break;
                        }

                        for (int reg : definite) {
                            BuildMI(block, MI.getIterator(), MI.getDebugLoc(), TII->get(castOp), regOf[reg]).addReg(regOf[reg]).addImm(1).addImm(0);
                            normalizedEdges++;
                        }

                        for (int root : roots) {
                            bool inserted = false;
                            for (MachineBasicBlock* pred : block.predecessors()) {
                                if (!reachable.count(pred)) {
                                    continue;
                                }
                                const ArenaFacts& edge = outgoing[pred];
                                if (edge.May.test(root) && !edge.Must.test(root)) {
                                    errs() << "bpf-arena-arith: ambiguous incoming edge in " << MF.getName() << " from block " << pred->getNumber() << " to "
                                           << block.getNumber() << " for r" << root << " (may=" << edge.May.to_ulong() << ", must=" << edge.Must.to_ulong()
                                           << ") at: ";
                                    MI.print(errs());
                                    pred->print(errs());
                                    block.print(errs());
                                    report_fatal_error(Twine("bpf-arena-arith: ambiguous incoming edge in ") + MF.getName());
                                }
                                if (!edge.Must.test(root)) {
                                    continue;
                                }

                                // Do not change a physical value needed by
                                // another successor. Such a critical edge
                                // needs an explicit split rather than a
                                // predecessor-wide cast.
                                for (MachineBasicBlock* other : pred->successors()) {
                                    if (other != &block && (other->isLiveIn(regOf[root]) || other->isLiveIn(wregOf[root]))) {
                                        report_fatal_error(Twine("bpf-arena-arith: pointer difference needs a critical-edge split in ") + MF.getName());
                                    }
                                }

                                BuildMI(*pred, pred->getFirstTerminator(), MI.getDebugLoc(), TII->get(castOp), regOf[root])
                                    .addReg(regOf[root])
                                    .addImm(1)
                                    .addImm(0);
                                inserted = true;
                                normalizedEdges++;
                            }
                            if (!inserted) {
                                report_fatal_error(Twine("bpf-arena-arith: no pointer edge to normalize in ") + MF.getName());
                            }
                        }
                        changed = true;
                        break;
                    }
                }

                int result = -1, nextOrigin = -1;
                MachineInstr* nextStackOrigin = nullptr;
                if (oi.kind == OpInfo::Load && oi.width == 8 && MI.getNumOperands() >= 3 && MI.getOperand(0).isReg() && MI.getOperand(1).isReg() &&
                    MI.getOperand(2).isImm() && ridx(MI.getOperand(1)) == 10) {
                    result = ridx(MI.getOperand(0));
                    int64_t offset = MI.getOperand(2).getImm();
                    if (offset >= INT32_MIN && offset <= INT32_MAX && before.StackMay.count(int32_t(offset)) && !before.StackMust.count(int32_t(offset))) {
                        nextStackOrigin = &MI;
                    }
                } else if (oi.kind == OpInfo::Copy && MI.getNumOperands() > 1) {
                    result = ridx(MI.getOperand(0));
                    int source = ridx(MI.getOperand(1));
                    if (source >= 0) {
                        nextOrigin = origin[source];
                        nextStackOrigin = stackOrigin[source];
                    }
                } else if (oi.kind == OpInfo::Alu && MI.getNumOperands() > 1) {
                    result = ridx(MI.getOperand(0));
                    int lhs = ridx(MI.getOperand(1));
                    int rhs = !oi.immSrc && MI.getNumOperands() > 2 ? ridx(MI.getOperand(2)) : -1;
                    if (oi.alu == OpInfo::Mov && !oi.immSrc && lhs >= 0) {
                        nextOrigin = origin[lhs];
                        nextStackOrigin = stackOrigin[lhs];
                    } else if (oi.alu == OpInfo::Add && !oi.is32) {
                        if (lhs >= 0 && (origin[lhs] >= 0 || stackOrigin[lhs]) && (rhs < 0 || !before.May.test(rhs))) {
                            nextOrigin = origin[lhs];
                            nextStackOrigin = stackOrigin[lhs];
                        } else if (rhs >= 0 && (origin[rhs] >= 0 || stackOrigin[rhs]) && (lhs < 0 || !before.May.test(lhs))) {
                            nextOrigin = origin[rhs];
                            nextStackOrigin = stackOrigin[rhs];
                        }
                    } else if (oi.alu == OpInfo::Sub && !oi.is32 && lhs >= 0 && (origin[lhs] >= 0 || stackOrigin[lhs]) && (rhs < 0 || !before.May.test(rhs))) {
                        nextOrigin = origin[lhs];
                        nextStackOrigin = stackOrigin[lhs];
                    }
                }

                step(block, MI, state, false);
                ForEachRegisterDef(MI, [&](MachineOperand& def) {
                    int reg = ridx(def);
                    if (reg >= 0) {
                        origin[reg] = -1;
                        stackOrigin[reg] = nullptr;
                    }
                });
                if (result >= 0 && state.May.test(result) && !state.Must.test(result)) {
                    origin[result] = nextOrigin;
                    stackOrigin[result] = nextStackOrigin;
                }
                if (oi.kind == OpInfo::Call) {
                    for (int reg = 0; reg <= 5; reg++) {
                        origin[reg] = -1;
                        stackOrigin[reg] = nullptr;
                    }
                }
            }
            if (changed) {
                break;
            }
        }
        if (!changed) {
            break;
        }
    }

    // Recompute once after the final edge cast, then perform local repairs.
    analyzeFacts();
    fixed += normalizedEdges;

    for (MachineBasicBlock& block : MF) {
        if (!reachable.count(&block)) {
            continue;
        }
        ArenaFacts state = incoming[&block];
        for (auto it = block.begin(); it != block.end(); ++it) {
            step(block, *it, state, true);
        }
    }

    // The simpler spill-value lattice below deliberately optimizes for scalar
    // range propagation and can lose BPF's pointer provenance at joins. This
    // may/must analysis is the authoritative one for arena pointers. Record
    // every native stack word which can carry one and pin that word: untyped
    // scalar storage cannot preserve PTR_TO_ARENA, and casting a mixed
    // scalar/pointer word on reload would be wrong on one of the paths.
    analyzeFacts();
    for (MachineBasicBlock& block : MF) {
        if (!reachable.count(&block)) {
            continue;
        }
        ArenaFacts state = incoming[&block];
        for (MachineInstr& instruction : block) {
            const OpInfo& oi = info(instruction);
            if ((oi.kind == OpInfo::Store || oi.kind == OpInfo::Load) && oi.width == 8 && instruction.getNumOperands() >= 3 &&
                instruction.getOperand(1).isReg() && instruction.getOperand(2).isImm() && ridx(instruction.getOperand(1)) == 10) {
                int64_t offset = instruction.getOperand(2).getImm();
                if (offset >= INT32_MIN && offset <= INT32_MAX) {
                    bool carriesArena = false;
                    if (oi.kind == OpInfo::Store && instruction.getOperand(0).isReg()) {
                        int source = ridx(instruction.getOperand(0));
                        carriesArena = source >= 0 && state.May.test(source);
                    } else {
                        carriesArena = state.StackMay.count((int32_t)offset);
                    }
                    if (carriesArena) {
                        arenaPointerStackWords.insert((int32_t)offset & ~7);
                    }
                }
            }
            step(block, instruction, state, false);
        }
    }
    return fixed;
}

// One instruction's effect on the dataflow state. Returns false to bail.
// `record` collects stack accesses with their pre-instruction facts.
struct Xfer {
    BPFUnifiedSpillsMIR& P;
    const DataLayout& DL;
    std::string bailWhy;

    bool step(MachineInstr& MI, State& st, std::vector<Access>* record) {
        const OpInfo& oi = P.info(MI);
        auto wr = [&](int r) {
            if (r >= 0) {
                st.initMask |= 1u << r;
            }
        };

        switch (oi.kind) {
            case OpInfo::LdImm64: {
                int d = P.ridx(MI.getOperand(0));
                if (d < 0) {
                    bailWhy = "untracked immediate destination";
                    return false;
                }
                const MachineOperand& src = MI.getOperand(1);
                if (src.isGlobal()) {
                    st.reg[d] = Val::remat(src.getGlobal(), src.getOffset());
                } else {
                    st.reg[d] = Val::scalar();
                }
                wr(d);
                break;
            }
            case OpInfo::AddrSpaceCast: {
                // $dst = ADDR_SPACE_CAST $src, from, to
                int d = P.ridx(MI.getOperand(0));
                if (d < 0) {
                    break;
                }
                // The cast's result depends only on its direction, never on what
                // the operand happened to hold: casting to address space 1 always
                // yields an arena pointer, and casting back always yields its
                // address as a number. Demanding a proven-scalar source made
                // every value that reached a cast opaque, which cascaded.
                int64_t to = MI.getNumOperands() > 3 && MI.getOperand(3).isImm() ? MI.getOperand(3).getImm() : -1;
                st.reg[d] = to == 1 ? Val::arena() : to == 0 ? Val::scalar() : Val::unknown();
                wr(d);
                break;
            }
            case OpInfo::Copy: {
                int d = P.ridx(MI.getOperand(0)), s = P.ridx(MI.getOperand(1));
                if (d < 0) {
                    break;
                }
                if (s < 0) {
                    st.reg[d] = Val::unknown();
                    wr(d);
                    break;
                }
                bool to32 = MI.getOperand(0).getReg() != P.regOf[d]; // W dest
                Val v = st.reg[s];
                if (to32) {
                    st.reg[d] = v.k == Val::Masked ? Val::masked(v.msk & 0xffffffffu) : v.scalarish() ? Val::scalar() : Val::unknown();
                } else {
                    st.reg[d] = v;
                }
                wr(d);
                break;
            }
            case OpInfo::Call:
                for (int r = 0; r <= 5; r++) {
                    st.reg[r] = Val::unknown();
                }
                st.initMask &= ~0b111110u;
                st.initMask |= 1u << 0;
                break;
            case OpInfo::Load: {
                if (MI.getNumOperands() < 3 || !MI.getOperand(0).isReg() || !MI.getOperand(1).isReg() || !MI.getOperand(2).isImm()) {
                    bailWhy = "unexpected load shape";
                    return false;
                }
                int d = P.ridx(MI.getOperand(0)), b = P.ridx(MI.getOperand(1));
                if (d < 0) {
                    bailWhy = "untracked load destination";
                    return false;
                }
                int64_t off = MI.getOperand(2).getImm();
                if (b == 10) {
                    Val v = Val::unknown();
                    if (oi.width == 8 && off % 8 == 0) {
                        auto it = st.stack.find((int32_t)off);
                        if (it != st.stack.end()) {
                            v = it->second;
                        }
                    } else if (oi.width == 4) {
                        v = Val::scalar();
                    }
                    if (record) {
                        Access a{&MI, (int32_t)off, oi.width, false, v, st.initMask};
                        record->push_back(a);
                    }
                    st.reg[d] = (v.k == Val::Remat || v.scalarish()) ? v : Val::unknown();
                } else {
                    st.reg[d] = Val::scalar();
                }
                wr(d);
                break;
            }
            case OpInfo::Store:
            case OpInfo::StoreImm: {
                if (MI.getNumOperands() < 3 || !MI.getOperand(1).isReg() || !MI.getOperand(2).isImm()) {
                    bailWhy = "unexpected store shape";
                    return false;
                }
                bool isImm = oi.kind == OpInfo::StoreImm;
                int s = isImm || !MI.getOperand(0).isReg() ? -1 : P.ridx(MI.getOperand(0));
                if (!isImm && s < 0) {
                    bailWhy = "untracked store source";
                    return false;
                }
                int b = P.ridx(MI.getOperand(1));
                int64_t off = MI.getOperand(2).getImm();
                if (b == 10) {
                    Val v = isImm ? Val::scalar() : st.reg[s];
                    if (record) {
                        Access a{&MI, (int32_t)off, oi.width, true, v, st.initMask};
                        record->push_back(a);
                    }
                    if (oi.width == 8 && off % 8 == 0) {
                        st.stack[(int32_t)off] = v;
                    } else {
                        st.stack[(int32_t)off & ~7] = Val::unknown();
                    }
                }
                break;
            }
            case OpInfo::Atomic: {
                int b = MI.getNumOperands() > 1 && MI.getOperand(1).isReg() ? P.ridx(MI.getOperand(1)) : -1;
                if (b == 10) {
                    bailWhy = "atomic on stack";
                    return false;
                }
                // fetch forms write a register; be blunt: any def becomes scalar
                ForEachRegisterDef(MI, [&](MachineOperand& mo) {
                    int d = P.ridx(mo);
                    if (d >= 0) {
                        st.reg[d] = Val::scalar();
                        wr(d);
                    }
                });
                break;
            }
            case OpInfo::Alu: {
                if (MI.getNumOperands() < 2 || !MI.getOperand(0).isReg()) {
                    break;
                }
                int d = P.ridx(MI.getOperand(0));
                if (d < 0) {
                    break;
                }
                bool has2 = MI.getNumOperands() > 2 && MI.getOperand(2).isReg();
                // BPF's ordinary ALU operations are tied three-operand
                // instructions (`dst = op dst, src`), but MOV_rr is the
                // two-operand exception (`dst = mov src`). Treating the
                // missing operand 2 as an absent source leaves the
                // destination's stale lattice value in place and can turn a
                // scalar copy into a verifier pointer.
                int s = -1;
                if (!oi.immSrc) {
                    if (has2) {
                        s = P.ridx(MI.getOperand(2));
                    } else if (oi.alu == OpInfo::Mov && MI.getOperand(1).isReg()) {
                        s = P.ridx(MI.getOperand(1));
                    }
                }
                bool fromFrame = s == 10 || (MI.getOperand(1).isReg() && P.ridx(MI.getOperand(1)) == 10);
                if (fromFrame) {
                    // analyze() has already accepted only the precise
                    // MOV-from-r10 / ADD-immediate / helper-call shape and
                    // recorded the ADD for rebasing.  It is deliberately opaque
                    // to scalar spill propagation: it is a verifier stack
                    // pointer, not a value eligible for unified spill memory.
                    if (oi.alu != OpInfo::Mov || oi.immSrc) {
                        bailWhy = "unsupported r10 arithmetic";
                        return false;
                    }
                    st.reg[d] = Val::unknown();
                    wr(d);
                    break;
                }
                // MOV_ri is the immediate counterpart of the two-operand
                // MOV_rr exception above: its immediate is operand 1. The
                // ordinary two-address ALU forms keep their immediate in
                // operand 2. Reading every immediate from operand 2 made a
                // spilled positive MOV constant look masked by zero and the
                // rewrite then changed its value to zero after the reload.
                unsigned immediateOperand = oi.alu == OpInfo::Mov ? 1 : 2;
                int64_t imm = oi.immSrc && MI.getNumOperands() > immediateOperand && MI.getOperand(immediateOperand).isImm()
                    ? MI.getOperand(immediateOperand).getImm()
                    : 0;
                Val dPre = st.reg[d];
                Val sPre = s >= 0 ? st.reg[s] : Val::scalar();

                // value transfer
                switch (oi.alu) {
                    case OpInfo::Mov:
                        if (oi.immSrc) {
                            if (imm >= 0) {
                                uint64_t m = (uint64_t)imm;
                                m |= m >> 1;
                                m |= m >> 2;
                                m |= m >> 4;
                                m |= m >> 8;
                                m |= m >> 16;
                                st.reg[d] = Val::masked(m);
                            } else {
                                st.reg[d] = Val::scalar();
                            }
                        } else if (s >= 0) {
                            Val v = st.reg[s];
                            if (oi.is32) {
                                st.reg[d] = v.k == Val::Masked ? Val::masked(v.msk & 0xffffffffu) : v.scalarish() ? Val::scalar() : Val::unknown();
                            } else {
                                st.reg[d] = v;
                            }
                        }
                        break;
                    case OpInfo::And: {
                        uint64_t lim = ~0ull;
                        if (oi.immSrc) {
                            lim = (uint64_t)(int64_t)imm; // sign-extended
                        } else if (s >= 0 && st.reg[s].k == Val::Masked) {
                            lim = st.reg[s].msk;
                        }
                        if (dPre.k == Val::Masked) {
                            lim &= dPre.msk;
                        }
                        if (oi.is32) {
                            lim &= 0xffffffffu;
                        }
                        st.reg[d] = lim != ~0ull ? Val::masked(lim) : (dPre.scalarish() && (oi.immSrc || sPre.scalarish())) ? Val::scalar() : Val::unknown();
                        break;
                    }
                    case OpInfo::Sll:
                    case OpInfo::Srl:
                        if (oi.immSrc) {
                            uint64_t base = dPre.k == Val::Masked ? dPre.msk : oi.is32 ? 0xffffffffull : ~0ull;
                            unsigned shift = imm & (oi.is32 ? 31 : 63);
                            uint64_t m = oi.alu == OpInfo::Sll ? base << shift : base >> shift;
                            if (oi.is32) {
                                m &= 0xffffffffu;
                            }
                            st.reg[d] = Val::masked(m);
                        } else {
                            st.reg[d] = Val::scalar();
                        }
                        break;
                    case OpInfo::Add:
                        // Arena pointer arithmetic stays arena: the result is still
                        // an address in the same mapping, so it spills the same way.
                        if (oi.immSrc) {
                            if (dPre.k == Val::Remat && !oi.is32) {
                                st.reg[d] = Val::remat(dPre.gv, dPre.add + imm);
                            } else if (dPre.k == Val::Arena && !oi.is32) {
                                st.reg[d] = Val::arena();
                            } else if (dPre.scalarish()) {
                                st.reg[d] = Val::scalar();
                            } else {
                                st.reg[d] = Val::unknown();
                            }
                        } else {
                            bool arena =
                                !oi.is32 && ((dPre.k == Val::Arena && (s < 0 || sPre.scalarish())) || (s >= 0 && sPre.k == Val::Arena && dPre.scalarish()));
                            bool ok = dPre.scalarish() && (s < 0 || sPre.scalarish());
                            st.reg[d] = arena ? Val::arena() : ok ? Val::scalar() : Val::unknown();
                        }
                        break;
                    default:
                        st.reg[d] = (dPre.scalarish() || dPre.k == Val::Bot) && (oi.immSrc || s < 0 || sPre.scalarish()) ? Val::scalar() : Val::unknown();
                        break;
                }
                wr(d);
                break;
            }
            case OpInfo::Branch:
            case OpInfo::Ret:
                break;
            case OpInfo::Other:
                // An unclassified definition invalidates the old value. In
                // particular, leaving a full-register INLINEASM output at its
                // previous Scalar/Remat state is optimistic: arbitrary
                // assembly may have produced a verifier pointer. A W output
                // is the one structural fact we do know — ALU32 results are
                // scalar — even when INLINEASM also lists the aliased R
                // register as an implicit def.
                uint16_t defs = 0, scalarDefs = 0;
                ForEachRegisterDef(MI, [&](MachineOperand& operand) {
                    int d = P.ridx(operand);
                    if (d >= 0) {
                        defs |= 1u << d;
                        if (MI.isInlineAsm() && operand.getReg() == P.wregOf[d]) {
                            scalarDefs |= 1u << d;
                        }
                    }
                });
                for (int d = 0; d <= 9; ++d) {
                    if (defs & (1u << d)) {
                        st.reg[d] = scalarDefs & (1u << d) ? Val::scalar() : Val::unknown();
                        wr(d);
                    }
                }
                break;
        }
        return true;
    }
};

bool BPFUnifiedSpillsMIR::analyze(
    MachineFunction& MF, std::vector<Access>& accesses, std::vector<StackAddress>& stackAddresses, int32_t& frameLow, std::string& bailWhy, int physicalLimit) {
    const DataLayout& DL = MF.getFunction().getParent()->getDataLayout();

    // Word ids over all r10-relative accesses.
    std::map<int32_t, size_t> wordId;
    frameLow = 0;
    for (auto& MBB : MF) {
        for (auto& MI : MBB) {
            const OpInfo& oi = info(MI);
            if (oi.kind != OpInfo::Load && oi.kind != OpInfo::Store && oi.kind != OpInfo::StoreImm) {
                continue;
            }
            if (MI.getNumOperands() < 3 || !MI.getOperand(1).isReg() || !MI.getOperand(2).isImm()) {
                continue;
            }
            if (ridx(MI.getOperand(1)) == 10) {
                int32_t off = (int32_t)MI.getOperand(2).getImm();
                wordId.try_emplace(off & ~7, wordId.size());
                frameLow = std::min(frameLow, off);
            }
        }
    }
    // Nothing to relocate: skip the dataflow entirely. Most native/runtime
    // functions and allocation units are under the limit. The units that do
    // need unified spills are still independent here; machine flattening is
    // deliberately later than this analysis and register allocation.
    uint64_t nativeFrameBytes = std::max<uint64_t>(MF.getFrameInfo().getStackSize(), static_cast<uint64_t>(-static_cast<int64_t>(frameLow)));
    if (nativeFrameBytes <= static_cast<uint64_t>(physicalLimit)) {
        return true;
    }

    // Recognize the only safe r10 escape accepted by this pass: a stack
    // address formed with one constant add and consumed by the next helper
    // call.  Keeping this structural and fail-closed matters: silently
    // repacking a frame behind an arbitrary derived stack pointer would
    // miscompile it.  LLVM emits unrelated argument setup between the ADD
    // and JAL, so allow instructions which neither read nor redefine dst.
    for (MachineBasicBlock& block : MF) {
        for (auto it = block.begin(); it != block.end(); ++it) {
            MachineInstr& mov = *it;
            const OpInfo& mi = info(mov);
            if (mi.kind != OpInfo::Alu || mi.alu != OpInfo::Mov || mi.immSrc || mov.getNumOperands() < 2 || !mov.getOperand(0).isReg() ||
                !mov.getOperand(1).isReg() || ridx(mov.getOperand(1)) != 10) {
                continue;
            }

            Register dst = mov.getOperand(0).getReg();
            auto next = std::next(it);
            while (next != block.end() && next->isDebugInstr()) {
                ++next;
            }
            if (next == block.end()) {
                bailWhy = "r10 address crosses a block";
                return false;
            }
            MachineInstr& add = *next;
            const OpInfo& ai = info(add);
            if (ai.kind != OpInfo::Alu || ai.alu != OpInfo::Add || !ai.immSrc || add.getNumOperands() < 3 || !add.getOperand(0).isReg() ||
                !add.getOperand(1).isReg() || !add.getOperand(2).isImm() || add.getOperand(0).getReg() != dst || add.getOperand(1).getReg() != dst) {
                bailWhy = "unsupported r10 address formation";
                return false;
            }
            int64_t off64 = add.getOperand(2).getImm();
            if (off64 >= 0 || off64 < frameLow || off64 < INT32_MIN) {
                bailWhy = "r10 address is outside the frame";
                return false;
            }

            bool consumedByCall = false;
            for (++next; next != block.end(); ++next) {
                MachineInstr& use = *next;
                if (use.isDebugInstr()) {
                    continue;
                }
                if (info(use).kind == OpInfo::Call) {
                    consumedByCall = true;
                    break;
                }
                bool touches = false;
                for (const MachineOperand& operand : use.operands()) {
                    touches |= operand.isReg() && operand.getReg() == dst;
                }
                if (touches) {
                    break;
                }
            }
            if (!consumedByCall) {
                bailWhy = "r10 address does not feed a local helper call";
                return false;
            }
            int32_t off = (int32_t)off64;
            if (!wordId.count(off & ~7)) {
                bailWhy = "r10 address has no direct stack object";
                return false;
            }

            // PEI has eliminated frame indices, but MachineFrameInfo still
            // retains each object's final r10-relative extent. Prefer that
            // exact extent over pinning the entire suffix above the pointer:
            // a helper needs its object to remain native, not unrelated hot
            // spills which happen to lie closer to r10. Fall back to the
            // suffix only if a backend-created address has no frame object.
            int32_t objectLow = off;
            int32_t objectHigh = 0;
            const MachineFrameInfo& frame = MF.getFrameInfo();
            for (int index = frame.getObjectIndexBegin(); index < frame.getObjectIndexEnd(); ++index) {
                if (frame.isDeadObjectIndex(index) || frame.isVariableSizedObjectIndex(index)) {
                    continue;
                }
                int64_t low = frame.getObjectOffset(index);
                int64_t size = frame.getObjectSize(index);
                int64_t high = low + size;
                if (size > 0 && low >= INT32_MIN && high <= 0 && low <= off && off < high) {
                    objectLow = static_cast<int32_t>(low);
                    objectHigh = static_cast<int32_t>(high);
                    break;
                }
            }
            stackAddresses.push_back({&add, off, objectLow, objectHigh});
        }
    }

    Xfer xf{*this, DL};

    std::map<MachineBasicBlock*, State> in;
    State& entry = in.try_emplace(&MF.front()).first->second;
    entry.reachable = true;
    // Registers start at bottom, not Unknown: a register that some path
    // leaves untouched must not poison the join for the paths that do define
    // it. Reading a genuinely undefined register is a verifier error the
    // program could not survive anyway, so bottom costs nothing and keeps
    // merges precise — which is most of what decides how much can be moved.
    for (int r = 0; r < 11; r++) {
        entry.reg[r] = Val();
    }
    entry.reg[10] = Val::unknown();
    // Definitely-initialized at entry = the entry block's live-ins; the
    // machine verifier rejects a use (even a save) of anything else.
    entry.initMask = 1u << 10;
    for (const auto& li : MF.front().liveins()) {
        unsigned reg = li.PhysReg;
        int idx = reg < PhysicalRegisterTableSize ? regIdx[reg] : -1;
        if (idx >= 0) {
            entry.initMask |= 1u << idx;
        }
    }

    // Reverse post-order: a block is visited after the predecessors that can
    // reach it, so values propagate a whole path per sweep instead of one
    // edge. On functions with thousands of blocks this is the difference
    // between converging in a few sweeps and thrashing.
    std::map<MachineBasicBlock*, unsigned> rpoIndex;
    {
        ReversePostOrderTraversal<MachineFunction*> rpo(&MF);
        unsigned i = 0;
        for (MachineBasicBlock* bb : rpo) {
            rpoIndex[bb] = i++;
        }
    }
    auto later = [&](MachineBasicBlock* a, MachineBasicBlock* b) {
        return rpoIndex[a] > rpoIndex[b]; // pop the earliest block first
    };

    // Chaotic iteration always terminates in theory — the lattice only grows —
    // but "eventually" is not a build time. The budget is generous enough that
    // a converging function never notices, and a pathological one is left
    // alone instead of hanging the compiler.
    uint64_t visits = 0;
    const uint64_t visitBudget = 200ull * (rpoIndex.size() + 1);

    std::vector<MachineBasicBlock*> work{&MF.front()};
    std::set<MachineBasicBlock*> inWork{&MF.front()};
    auto enqueue = [&](MachineBasicBlock* bb) {
        if (inWork.insert(bb).second) {
            work.push_back(bb);
            std::push_heap(work.begin(), work.end(), later);
        }
    };
    while (!work.empty()) {
        if (++visits > visitBudget) {
            bailWhy = "dataflow did not converge within budget";
            return false;
        }
        std::pop_heap(work.begin(), work.end(), later);
        MachineBasicBlock* bb = work.back();
        work.pop_back();
        inWork.erase(bb);
        State st = in[bb];
        if (!st.reachable) {
            continue;
        }
        for (auto& MI : *bb) {
            if (!xf.step(MI, st, nullptr)) {
                bailWhy = xf.bailWhy;
                return false;
            }
        }
        for (MachineBasicBlock* s : bb->successors()) {
            if (in[s].merge(st)) {
                enqueue(s);
            }
        }
    }

    // Record pass with converged states.
    for (auto& MBB : MF) {
        auto it = in.find(&MBB);
        if (it == in.end() || !it->second.reachable) {
            continue;
        }
        State st = it->second;
        for (auto& MI : MBB) {
            if (!xf.step(MI, st, &accesses)) {
                bailWhy = xf.bailWhy;
                return false;
            }
        }
    }
    return true;
}

bool BPFUnifiedSpillsMIR::runOnMachineFunction(MachineFunction& MF) {
    TII = MF.getSubtarget().getInstrInfo();
    const TargetRegisterInfo* TRI = MF.getSubtarget().getRegisterInfo();
    const Function& function = MF.getFunction();

    if (UnifiedSpillLimit < 0 || UnifiedSpillLimit > 512 || UnifiedSpillLimit % 8) {
        function.getContext().emitError("bpf-unified-spills: native step-stack cap must be an 8-byte multiple from 0 through 512");
        return false;
    }

    int physicalLimit = 512;
    if (function.getMetadata(bpf::md::AllocationUnit)) {
        physicalLimit = UnifiedSpillLimit;
        if (MDNode* metadata = function.getMetadata(bpf::md::NativeStackBudget)) {
            auto* value = metadata->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(metadata->getOperand(0)) : nullptr;
            if (!value || value->getValue().getActiveBits() > 32 || value->getZExtValue() > 512 || value->getZExtValue() % 8) {
                function.getContext().emitError(Twine("bpf-unified-spills: malformed post-RA native-stack budget on ") + function.getName());
                return false;
            }
            physicalLimit = std::min(physicalLimit, int(value->getZExtValue()));
        }
    }

    // The tables are instance state, so their initialization guard must be as
    // well. LLVM may construct the pass more than once in one process.
    if (!regsDone) {
        for (auto& e : regIdx) {
            e = -1;
        }
        for (unsigned r = 1; r < TRI->getNumRegs() && r < PhysicalRegisterTableSize; r++) {
            StringRef n = TRI->getName(r);
            bool w = n.starts_with("W");
            if ((n.starts_with("R") || w) && n.size() <= 3) {
                int num;
                if (!n.drop_front(1).getAsInteger(10, num) && num >= 0 && num <= 10) {
                    regIdx[r] = num;
                    if (w) {
                        wregOf[num] = r;
                    } else {
                        regOf[num] = r;
                    }
                }
            }
        }
        regsDone = true;
    }

    unsigned arenaArithmeticFixed = fixArenaPointerArithmetic(MF);
    const bool arenaArithmeticChanged = arenaArithmeticFixed != 0;

    int32_t frameLow = 0;
    std::vector<Access> accesses;
    std::vector<StackAddress> stackAddresses;
    std::string bailWhy;
    bool analyzed = analyze(MF, accesses, stackAddresses, frameLow, bailWhy, physicalLimit);
    uint64_t nativeFrameBytes = std::max<uint64_t>(MF.getFrameInfo().getStackSize(), static_cast<uint64_t>(-static_cast<int64_t>(frameLow)));
    if (!function.getMetadata(bpf::md::AllocationUnit) && nativeFrameBytes > 512) {
        function.getContext().emitError(Twine("bpf-unified-spills: native function ") + MF.getName() + " exceeds the 512-byte BPF stack");
        return arenaArithmeticChanged;
    }
    if (!analyzed) {
        // llc's ordinary BPF stack diagnostic is deliberately raised to the
        // unified fiber-stack limit so this pass can see large physical
        // frames. Never let an analysis bail turn that into an unloadable
        // object beyond its actual call-chain budget. Ordinary native
        // functions do not own a leased fiber and therefore retain the
        // kernel's absolute per-function limit instead.
        uint64_t safeLimit = static_cast<uint64_t>(physicalLimit);
        if (nativeFrameBytes > safeLimit) {
            function.getContext().emitError(Twine("bpf-unified-spills: cannot safely relocate ") + MF.getName() + "'s " + Twine(nativeFrameBytes) +
                "-byte native frame into its " + Twine(safeLimit) + "-byte budget: " + bailWhy);
        }
        return arenaArithmeticChanged;
    }
    if (nativeFrameBytes <= static_cast<uint64_t>(physicalLimit)) {
        // Access analysis can prove that all touched offsets fit the hot
        // budget while MachineFrameInfo still contains an opaque or otherwise
        // unobserved object. Never let that residual frame escape above the
        // kernel's absolute stack limit.
        if (nativeFrameBytes > 512) {
            function.getContext().emitError(
                Twine("bpf-unified-spills: physical function ") + MF.getName() + " retains a native frame exceeding the 512-byte BPF stack");
        }
        return arenaArithmeticChanged;
    }

    // Unified transient spill memory is owned by a leased fiber. Ordinary
    // native entry/runtime functions run before a lease exists (fiber
    // acquisition is the important example), so there is no correct fiber stack they
    // could use. Their frames remain native even when an experimental
    // Capsule-step budget is smaller. Reject a genuinely oversized native
    // frame explicitly once the backend's preliminary limit is raised to let
    // this post-RA pass inspect large Capsule frames.
    if (!function.getMetadata(bpf::md::AllocationUnit)) {
        return arenaArithmeticChanged;
    }

    struct StackAnchor {
        MachineInstr* instruction = nullptr;
        Register base;
    } anchor;
    for (MachineBasicBlock& block : MF) {
        for (MachineInstr& instruction : block) {
            if (!instruction.isInlineAsm() || instruction.getNumOperands() < 2 || !instruction.getOperand(0).isSymbol() ||
                !StringRef(instruction.getOperand(0).getSymbolName()).contains(bpf::sym::StackAnchor)) {
                continue;
            }
            if (anchor.instruction) {
                function.getContext().emitError(Twine("bpf-unified-spills: multiple unified-stack anchors in ") + MF.getName());
                return arenaArithmeticChanged;
            }
            SmallVector<Register, 1> uses;
            for (const MachineOperand& operand : instruction.operands()) {
                if (operand.isReg() && operand.isUse() && operand.getReg()) {
                    uses.push_back(operand.getReg());
                }
            }
            if (uses.size() != 1) {
                function.getContext().emitError(Twine("bpf-unified-spills: malformed unified-stack anchor in ") + MF.getName());
                return arenaArithmeticChanged;
            }
            anchor = {&instruction, uses[0]};
        }
    }
    if (!anchor.instruction) {
        function.getContext().emitError(Twine("bpf-unified-spills: physical function ") + MF.getName() + " needs relocation but has no unified-stack anchor");
        return arenaArithmeticChanged;
    }
    auto* stackSizeMD = function.getMetadata(bpf::md::StackSize);
    auto* stackSizeValue = stackSizeMD && stackSizeMD->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(stackSizeMD->getOperand(0)) : nullptr;
    if (!stackSizeValue || !stackSizeValue->getZExtValue() || !isPowerOf2_64(stackSizeValue->getZExtValue()) ||
        stackSizeValue->getZExtValue() > bpf::MaxFiberStackBytes) {
        function.getContext().emitError(Twine("bpf-unified-spills: malformed unified-stack size on ") + MF.getName());
        return arenaArithmeticChanged;
    }
    uint64_t fiberStackSize = stackSizeValue->getZExtValue();

    // Every r10 access must have been visited by the analysis, or the
    // renumbering below silently mixes old and new frame layouts.
    {
        std::set<MachineInstr*> seen;
        for (auto& a : accesses) {
            seen.insert(a.mi);
        }
        for (auto& MBB : MF) {
            for (auto& MI : MBB) {
                const OpInfo& oi = info(MI);
                if (oi.kind != OpInfo::Load && oi.kind != OpInfo::Store && oi.kind != OpInfo::StoreImm) {
                    continue;
                }
                if (MI.getNumOperands() < 3 || !MI.getOperand(1).isReg() || !MI.getOperand(2).isImm() || ridx(MI.getOperand(1)) != 10) {
                    continue;
                }
                if (!seen.count(&MI)) {
                    function.getContext().emitError(Twine("bpf-unified-spills: unvisited r10 access in ") + MF.getName() + ": " + TII->getName(MI.getOpcode()) +
                        " off " + Twine(MI.getOperand(2).getImm()));
                    return arenaArithmeticChanged;
                }
            }
        }
    }

    // ------------------------------------------------------- classification
    struct Group {
        std::vector<Access*> acc;
        bool forcedStack = false;
    };
    std::map<std::pair<int32_t, int>, Group> groups;
    for (auto& a : accesses) {
        groups[{a.off, a.width}].acc.push_back(&a);
    }
    for (auto& [k1, g1] : groups) {
        for (auto& [k2, g2] : groups) {
            if (k1 == k2) {
                continue;
            }
            int32_t a0 = k1.first, a1 = k1.first + k1.second;
            int32_t b0 = k2.first, b1 = k2.first + k2.second;
            if (a0 < b1 && b0 < a1) {
                g1.forcedStack = true;
                g2.forcedStack = true;
            }
        }
    }

    std::map<int32_t, SlotClass> wordCls;
    auto worse = [](SlotClass a, SlotClass b) {
        if (a == SlotClass::Stack || b == SlotClass::Stack) {
            return SlotClass::Stack;
        }
        if (a == b) {
            return a;
        }
        // Mixing an arena pointer with a plain scalar in one word means the
        // reload cannot know which form to restore.
        if (a == SlotClass::UnifiedArena || b == SlotClass::UnifiedArena) {
            return SlotClass::Stack;
        }
        if (a == SlotClass::Unified || b == SlotClass::Unified) {
            return SlotClass::Unified;
        }
        return SlotClass::Remat;
    };
    for (auto& [key, g] : groups) {
        auto [off, width] = key;
        SlotClass c;
        if (g.forcedStack) {
            c = SlotClass::Stack;
        } else if (width < 8 || off % 8 != 0) {
            // A sub-word or unaligned stack reload is STACK_MISC — unbounded —
            // already, so unified memory loses nothing.
            c = SlotClass::Unified;
        } else {
            bool allScalar = true, allRemat = true, allArena = true;
            for (Access* a : g.acc) {
                if (!a->seen.scalarish()) {
                    allScalar = false;
                }
                if (a->seen.k != Val::Remat) {
                    allRemat = false;
                }
                if (a->seen.k != Val::Arena) {
                    allArena = false;
                }
            }
            c = allRemat ? SlotClass::Remat : allScalar ? SlotClass::Unified : allArena ? SlotClass::UnifiedArena : SlotClass::Stack;
        }
        int32_t w = off & ~7;
        auto it = wordCls.find(w);
        wordCls[w] = it == wordCls.end() ? c : worse(it->second, c);
    }
    // Helper-visible addresses must continue to denote real BPF stack. Pin
    // the complete MachineFrameInfo object, including words which no machine
    // instruction accesses directly. For backend-created pointers without a
    // recoverable object, analyze() records the conservative [pointer, r10)
    // suffix instead.
    for (const StackAddress& address : stackAddresses) {
        for (int32_t word = address.objectLow & ~7; word < address.objectHigh; word += 8) {
            wordCls[word] = SlotClass::Stack;
        }
    }
    // A live arena pointer saved while repairing a commuted ADD must retain
    // verifier pointer type. Keep that compiler-owned word on the BPF stack;
    // map-backed spill memory would deliberately erase the provenance.
    for (const Access& access : accesses) {
        if (arenaRepairStackAccesses.count(access.mi)) {
            wordCls[access.off & ~7] = SlotClass::Stack;
        }
    }
    for (int32_t word : arenaPointerStackWords) {
        wordCls[word] = SlotClass::Stack;
    }

    // The resolved backing pointer does not exist until the anchor. Any word
    // touched on a predecessor path, or earlier in the anchor block, must stay
    // on the native BPF stack. Classification is per word, so a value stored
    // before the anchor and reloaded afterward is pinned as well.
    std::set<MachineBasicBlock*> beforeAnchorBlocks;
    std::vector<MachineBasicBlock*> beforeWork(anchor.instruction->getParent()->pred_begin(), anchor.instruction->getParent()->pred_end());
    while (!beforeWork.empty()) {
        MachineBasicBlock* block = beforeWork.back();
        beforeWork.pop_back();
        if (!beforeAnchorBlocks.insert(block).second) {
            continue;
        }
        beforeWork.insert(beforeWork.end(), block->pred_begin(), block->pred_end());
    }
    bool beforeAnchor = true;
    for (MachineInstr& instruction : *anchor.instruction->getParent()) {
        if (&instruction == anchor.instruction) {
            beforeAnchor = false;
            continue;
        }
        if (!beforeAnchor) {
            continue;
        }
        for (const Access& access : accesses) {
            if (access.mi == &instruction) {
                wordCls[access.off & ~7] = SlotClass::Stack;
            }
        }
    }
    for (const Access& access : accesses) {
        if (beforeAnchorBlocks.contains(access.mi->getParent())) {
            wordCls[access.off & ~7] = SlotClass::Stack;
        }
    }

    // Arena stores temporarily save two registers below the unified-base
    // slot. Plain scalar stores save only one. Reserve the third word whenever
    // an arena-pointer spill survived classification.
    bool anyArena = false;
    for (auto& [w, c] : wordCls) {
        anyArena |= c == SlotClass::UnifiedArena;
    }
    const int reservedWords = anyArena ? 3 : 2;

    // Move only what the limit demands. A word on the stack costs nothing at
    // run time; a relocated one costs instructions at every access. So the
    // most-accessed words keep their stack slots up to the limit, and only
    // the overflow — cheapest first — goes to unified memory.
    {
        int capacity = physicalLimit / 8 - reservedWords;
        int stackW = 0;
        for (auto& [w, c] : wordCls) {
            if (c == SlotClass::Stack) {
                stackW++;
            }
        }
        int keepable = capacity - stackW;
        if (keepable > 0) {
            std::map<int32_t, int> weight;
            for (auto& a : accesses) {
                auto it = wordCls.find(a.off & ~7);
                if (it != wordCls.end() && it->second == SlotClass::Unified) {
                    weight[a.off & ~7]++;
                }
            }
            std::vector<std::pair<int, int32_t>> byWeight;
            for (auto& [w, c] : wordCls) {
                if (c == SlotClass::Unified) {
                    byWeight.push_back({weight[w], w});
                }
            }
            std::sort(byWeight.rbegin(), byWeight.rend());
            for (auto& [cnt, w] : byWeight) {
                if (keepable-- <= 0) {
                    break;
                }
                wordCls[w] = SlotClass::Stack;
            }
        }
    }

    bool anyUnified = false;
    for (auto& [w, c] : wordCls) {
        anyUnified |= c == SlotClass::Unified || c == SlotClass::UnifiedArena;
    }

    // New frame layout: stack words packed from -8 down, then unified base and
    // one or two borrowed-register save slots.
    std::map<int32_t, int32_t> wordNewOff;
    int32_t next = 0;
    for (auto it = wordCls.rbegin(); it != wordCls.rend(); ++it) {
        if (it->second == SlotClass::Stack) {
            next -= 8;
            wordNewOff[it->first] = next;
        }
    }
    int32_t baseOff = 0, borrowOff = 0;
    if (anyUnified) {
        baseOff = next - 8;
        borrowOff = next - 16;
        next -= 8 * reservedWords;
    }
    if (next < -physicalLimit) {
        std::string composition;
        {
            llvm::SmallPtrSet<const llvm::DISubprogram*, 8> seen;
            for (const MachineBasicBlock& block : MF) {
                for (const MachineInstr& instruction : block) {
                    const DebugLoc& loc = instruction.getDebugLoc();
                    auto* scope = loc ? dyn_cast_or_null<DILocalScope>(loc.getScope()) : nullptr;
                    auto* sub = scope ? scope->getSubprogram() : nullptr;
                    if (sub && seen.insert(sub).second && seen.size() <= 12) {
                        composition += " ";
                        composition += sub->getName();
                    }
                }
            }
        }
        function.getContext().emitError(Twine("bpf-unified-spills: non-relocatable stack in ") + MF.getName() + " leaves a " + Twine(-next) +
            "-byte native frame, exceeding its " + Twine(physicalLimit) + "-byte budget; sources:" + composition);
        return false;
    }

    // Rebase each accepted `dst = r10 + oldOff` after stack-word packing.
    // Preserve the byte position inside its eight-byte word.
    for (const StackAddress& address : stackAddresses) {
        int32_t oldWord = address.off & ~7;
        auto found = wordNewOff.find(oldWord);
        if (found == wordNewOff.end()) {
            report_fatal_error("bpf-unified-spills: helper stack address was relocated");
        }
        address.add->getOperand(2).setImm(found->second + (address.off - oldWord));
    }

    // Allocation units are dispatcher leaves: a managed call suspends the
    // current unit instead of making another BPF call. They therefore never
    // nest on one fiber, so every unit reuses the low end of that fiber's
    // existing stack instead of summing all functions' worst cases.
    int64_t transientSize = 0;
    std::map<int32_t, int64_t> wordTransientOffset;
    for (auto& [w, c] : wordCls) {
        if (c == SlotClass::Unified || c == SlotClass::UnifiedArena) {
            wordTransientOffset[w] = transientSize;
            transientSize += 8;
        }
    }
    uint64_t transientReserve = bpf::TransientReserveBytes(fiberStackSize);
    if ((uint64_t)transientSize > transientReserve) {
        function.getContext().emitError(Twine("bpf-unified-spills: physical function ") + MF.getName() + " needs " + Twine(transientSize) +
            " bytes of transient spill storage, exceeding its " + Twine(transientReserve) + "-byte fiber-stack partition");
        return false;
    }
    // Opcode lookup by name for the instructions we emit.
    auto opByName = [&](StringRef n) -> unsigned {
        for (unsigned i = 0; i < TII->getNumOpcodes(); i++) {
            if (TII->getName(i) == n) {
                return i;
            }
        }
        report_fatal_error(Twine("bpf-unified-spills: no opcode ") + n);
    };
    if (!emittedOpcodesDone) {
        opSTD = opByName("STD");
        opSTDimm = opByName("STD_imm");
        opSTWimm = opByName("STW_imm");
        opLDD = opByName("LDD");
        opLDimm = opByName("LD_imm64");
        opADDri = opByName("ADD_ri");
        opCast = opByName("ADDR_SPACE_CAST");
        opANDri = opByName("AND_ri");
        opANDri32 = opByName("AND_ri_32");
        opMOVri32 = opByName("MOV_ri_32");
        opJULTri = opByName("JULT_ri");
        opJMP = opByName("JMP");
        opRET = opByName("RET");
        emittedOpcodesDone = true;
    }
    unsigned R10 = regOf[10];
    auto materializeMemoryOffset = [&](MachineBasicBlock& block, MachineBasicBlock::iterator before, const DebugLoc& dl, Register base, int64_t offset) {
        if (isInt<16>(offset)) {
            return offset;
        }
        BuildMI(block, before, dl, TII->get(opADDri), base).addReg(base).addImm(offset);
        return int64_t{0};
    };

    // --------------------------------------------------------------- rewrite
    // Save the anchor's backing pointer in the packed native frame. The
    // anchor register holds the raw full-address stack base — a scalar to
    // the verifier — while the rewritten accesses below dereference the
    // reloaded slot directly, so the SAVED value must carry the arena
    // permission: license a copy in place (the cast truncates, so the
    // original register is preserved around it), store it, and restore.
    // Spill slots keep a pointer's verifier type, so every reload below is
    // licensed for free. No bound check is emitted here: every descent is
    // bounded at its source (entry prologues and carve sites, against the
    // reserve this transient extent was validated to fit), so the extent
    // can never meet the downward-growing stack.
    if (anyUnified) {
        DebugLoc dl = anchor.instruction->getDebugLoc();
        MachineBasicBlock& block = *anchor.instruction->getParent();
        MachineBasicBlock::iterator at = anchor.instruction->getIterator();
        // Licensing applies to the arena backing only: on the fixed tier the
        // anchor is a map-value pointer whose permission is native, and the
        // cast instruction does not exist on those kernels.
        const bool arenaBacked = function.getParent()->getGlobalVariable(bpf::sym::ArenaMap, /*AllowInternal=*/true) != nullptr;
        if (arenaBacked) {
            BuildMI(block, at, dl, TII->get(opSTD)).addReg(anchor.base).addReg(R10).addImm(borrowOff);
            BuildMI(block, at, dl, TII->get(opCast), anchor.base).addReg(anchor.base).addImm(0).addImm(1);
        }
        BuildMI(block, at, dl, TII->get(opSTD)).addReg(anchor.base).addReg(R10).addImm(baseOff);
        if (arenaBacked) {
            BuildMI(block, at, dl, TII->get(opLDD), anchor.base).addReg(R10).addImm(borrowOff);
        }
    }

    int unifiedW = 0, stackW = 0, rematW = 0;
    for (auto& [w, c] : wordCls) {
        (c == SlotClass::Unified || c == SlotClass::UnifiedArena ? unifiedW : c == SlotClass::Stack ? stackW : rematW)++;
    }

    // Registers dead just before each rewritten store are free scratch — no
    // save/restore needed. Live ones can still be borrowed (save/restore
    // makes the clobber invisible), and live implies initialized for the
    // kernel verifier too.
    std::map<MachineInstr*, uint16_t> deadBefore;
    {
        std::set<MachineBasicBlock*> blocks;
        for (auto& a : accesses) {
            if (a.isStore) {
                blocks.insert(a.mi->getParent());
            }
        }
        std::set<MachineInstr*> wanted;
        for (auto& a : accesses) {
            if (a.isStore) {
                wanted.insert(a.mi);
            }
        }
        const MachineRegisterInfo& MRI = MF.getRegInfo();
        for (MachineBasicBlock* bb : blocks) {
            LivePhysRegs LPR(*TRI);
            LPR.addLiveOuts(*bb);
            for (auto it = bb->rbegin(); it != bb->rend(); ++it) {
                MachineInstr& MI = *it;
                LPR.stepBackward(MI);
                if (wanted.count(&MI)) {
                    uint16_t dead = 0;
                    for (int r = 0; r <= 9; r++) {
                        if (LPR.available(MRI, regOf[r])) {
                            dead |= 1u << r;
                        }
                    }
                    deadBefore[&MI] = dead;
                }
            }
        }
    }

    for (auto& a : accesses) {
        MachineInstr* MI = a.mi;
        MachineBasicBlock* MBB = MI->getParent();
        DebugLoc dl = MI->getDebugLoc();
        int32_t w = a.off & ~7;
        SlotClass c = wordCls[w];
        if (c == SlotClass::Stack) {
            MI->getOperand(2).setImm(wordNewOff[w] + (a.off - w));
        } else if (c == SlotClass::UnifiedArena) {
            // An arena pointer travels as its address: cast down before the
            // store, cast back after the load. Map memory cannot hold the
            // pointer type, but the address is all the type carries here —
            // the arena mapping is what bounds the access.
            int64_t k = wordTransientOffset[w] + (a.off - w);
            if (!a.isStore) {
                int d = ridx(MI->getOperand(0));
                Register dstFull = regOf[d];
                Register base = dstFull;
                BuildMI(*MBB, MI, dl, TII->get(opLDD), dstFull).addReg(R10).addImm(baseOff);
                int64_t memoryOffset = materializeMemoryOffset(*MBB, MI->getIterator(), dl, base, k);
                BuildMI(*MBB, MI, dl, TII->get(opLDD), dstFull).addReg(base).addImm(memoryOffset);
                BuildMI(*MBB, MI, dl, TII->get(opCast), dstFull).addReg(dstFull).addImm(0).addImm(1);
                MI->eraseFromParent();
            } else {
                int src = ridx(MI->getOperand(0));
                uint16_t dead = deadBefore.count(MI) ? deadBefore[MI] : 0;
                // Two scratch registers: one holds the scratch base, the
                // other the cast-down address, and neither may be the value
                // being spilled.
                int rb = -1, rc = -1;
                for (int cand = 1; cand <= 9; cand++) {
                    if (cand == src) {
                        continue;
                    }
                    if (rb < 0) {
                        rb = cand;
                    } else if (rc < 0) {
                        rc = cand;
                        break;
                    }
                }
                if (rb < 0 || rc < 0) {
                    report_fatal_error("bpf-unified-spills: no borrow pair");
                }
                bool saveB = !((dead >> rb) & 1), saveC = !((dead >> rc) & 1);
                unsigned RB = regOf[rb], RC = regOf[rc];
                if (saveB) {
                    BuildMI(*MBB, MI, dl, TII->get(opSTD)).addReg(RB).addReg(R10).addImm(borrowOff);
                }
                if (saveC) {
                    BuildMI(*MBB, MI, dl, TII->get(opSTD)).addReg(RC).addReg(R10).addImm(borrowOff - 8);
                }
                BuildMI(*MBB, MI, dl, TII->get(opCast), RC).addReg(MI->getOperand(0).getReg()).addImm(1).addImm(0);
                BuildMI(*MBB, MI, dl, TII->get(opLDD), RB).addReg(R10).addImm(baseOff);
                int64_t memoryOffset = materializeMemoryOffset(*MBB, MI->getIterator(), dl, RB, k);
                BuildMI(*MBB, MI, dl, TII->get(opSTD)).addReg(RC).addReg(RB).addImm(memoryOffset);
                if (saveC) {
                    BuildMI(*MBB, MI, dl, TII->get(opLDD), RC).addReg(R10).addImm(borrowOff - 8);
                }
                if (saveB) {
                    BuildMI(*MBB, MI, dl, TII->get(opLDD), RB).addReg(R10).addImm(borrowOff);
                }
                MI->eraseFromParent();
            }
        } else if (c == SlotClass::Unified) {
            int64_t k = wordTransientOffset[w] + (a.off - w);
            if (!a.isStore) {
                // dst is its own scratch: base, then value (via the original
                // opcode, keeping width and register class), then the mask —
                // identity on the value, umin/umax back for the verifier.
                int d = ridx(MI->getOperand(0));
                Register dstFull = regOf[d];
                Register base = dstFull;
                BuildMI(*MBB, MI, dl, TII->get(opLDD), dstFull).addReg(R10).addImm(baseOff);
                int64_t memoryOffset = materializeMemoryOffset(*MBB, MI->getIterator(), dl, base, k);
                BuildMI(*MBB, MI, dl, TII->get(MI->getOpcode()), MI->getOperand(0).getReg()).addReg(base).addImm(memoryOffset);
                if (a.width == 8 && a.seen.k == Val::Masked) {
                    if (a.seen.msk <= 0xffffffffull) {
                        BuildMI(*MBB, MI, dl, TII->get(opANDri32), wregOf[d]).addReg(wregOf[d]).addImm((int32_t)(uint32_t)a.seen.msk);
                    } else {
                        BuildMI(*MBB, MI, dl, TII->get(opANDri), dstFull).addReg(dstFull).addImm((int32_t)(uint32_t)a.seen.msk);
                    }
                }
                MI->eraseFromParent();
            } else {
                int src = info(*MI).kind == OpInfo::StoreImm ? -1 : ridx(MI->getOperand(0));
                uint16_t dead = deadBefore.count(MI) ? deadBefore[MI] : 0;
                int rb = -1;
                bool save = true;
                for (int cand = 1; cand <= 9 && rb < 0; cand++) {
                    if (((dead >> cand) & 1) && cand != src) {
                        rb = cand;
                        save = false;
                    }
                }
                for (int cand = 1; cand <= 9 && rb < 0; cand++) {
                    if (((a.initMask >> cand) & 1) && !((dead >> cand) & 1) && cand != src) {
                        rb = cand;
                    }
                }
                if (rb < 0) {
                    report_fatal_error("bpf-unified-spills: no borrow register");
                }
                unsigned RB = regOf[rb];
                if (save) {
                    BuildMI(*MBB, MI, dl, TII->get(opSTD)).addReg(RB).addReg(R10).addImm(borrowOff);
                }
                BuildMI(*MBB, MI, dl, TII->get(opLDD), RB).addReg(R10).addImm(baseOff);
                int64_t memoryOffset = materializeMemoryOffset(*MBB, MI->getIterator(), dl, RB, k);
                MachineInstrBuilder replacement = BuildMI(*MBB, MI, dl, TII->get(MI->getOpcode()));
                if (info(*MI).kind == OpInfo::StoreImm) {
                    replacement.addImm(MI->getOperand(0).getImm());
                } else {
                    replacement.addReg(MI->getOperand(0).getReg());
                }
                replacement.addReg(RB).addImm(memoryOffset);
                if (save) {
                    BuildMI(*MBB, MI, dl, TII->get(opLDD), RB).addReg(R10).addImm(borrowOff);
                }
                MI->eraseFromParent();
            }
        } else { // Remat
            if (a.isStore) {
                MI->eraseFromParent();
            } else {
                if (a.seen.k != Val::Remat) {
                    report_fatal_error("bpf-unified-spills: remat load without remat state");
                }
                BuildMI(*MBB, MI, dl, TII->get(opLDimm), MI->getOperand(0).getReg()).addGlobalAddress(a.seen.gv, a.seen.add);
                MI->eraseFromParent();
            }
        }
    }

    bpf::stats() << "bpf-unified-spills: " << MF.getName() << ", " << unifiedW << " unified words, " << stackW << " native words, " << rematW
                 << " rematerialized words\n";
    return true;
}

} // namespace

static RegisterPass<BPFUnifiedSpillsMIR> RegisterUnifiedSpills("bpf-unified-spills", "BPF spill slots to unified fiber stack", false, false);

// `-run-pass` accepts MIR only, which used to force every large program
// through a stop/serialize/reparse/start sandwich. Registering directly in
// the normal llc pipeline keeps all MachineFunctions in memory and preserves
// stock instruction selection, register allocation, block placement, branch
// relaxation, relocation and BTF emission.
static RegisterTargetPassConfigCallback RegisterUnifiedSpillPipeline([](TargetMachine& TM, PassManagerBase&, TargetPassConfig* config) {
    if (UnifiedSpillPipeline && TM.getTargetTriple().isBPF()) {
        // Relocate each independently allocated unit after PEI and the late
        // machine optimizers. Let standard block placement finish each unit
        // independently, then join their final layouts and repair branches.
        // Running placement on the joined CFG tail-merges independent exits
        // and scatters dispatch trees through application bodies.
        config->insertPass(&GCMachineCodeAnalysisID, bpf::MachineStackBudgetPassID());
        config->insertPass(bpf::MachineStackBudgetPassID(), &BPFUnifiedSpillsMIR::ID);
        bpf::AddMachineFlattenPasses(*config, &MachineBlockPlacementID, &MachineBlockPlacementID);
    }
});
