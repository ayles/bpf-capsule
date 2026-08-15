// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "stackify.h"

#include "common.h"
#include "target.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/ADT/SetVector.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/StackLifetime.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

using namespace llvm;

static cl::opt<unsigned> StopAfterPhase("bpf-stackify-phase", cl::desc("Debugging: stop the stackify transform after phase N"), cl::init(0));

static cl::opt<bool> StepHistogram("bpf-step-histogram", cl::desc("Count dispatches per managed function id (expensive to verify)"), cl::init(false));

static cl::opt<bool> DumpIds("bpf-dump-ids", cl::desc("Print the managed function id table, to name a stuck frame"), cl::init(false));

// Folding a function into its callers costs stack: its spills join the
// caller's frame, and every frame is capped at 512 bytes.
// The verifier rejects any loop it cannot bound and simulates every iteration
// of the ones it can. Turning each hostile backedge into explicit state leaves
// the step functions acyclic; bounded chunks are driven by a helper callback.

// Register spills land in the 512-byte BPF frame and cannot be redirected, so
// a function whose live values exceed it has to be cut into shorter pieces.
static cl::opt<unsigned> SplitLargerThan(
    "bpf-split-larger-than",
    cl::desc(
        "Debugging: maximum post-demotion IR instructions per planned "
        "continuation partition (zero selects the target default)"
    ),
    cl::init(0)
);

namespace {

// A frame carries one flat continuation PC.  Function addresses are entry
// PCs, and every suspension replaces the PC with its resume target.  Keeping
// physical step-group selection out of the frame lets regions of one source
// function live in different BPF subprograms.
constexpr uint64_t PcOffset = 0;
constexpr uint64_t FixedFrameHeaderSize = 8;

static cl::opt<unsigned>
    FiberStackBytes("bpf-fiber-stack-size", cl::init(256u * 1024u), cl::desc("Bytes of unified program memory reserved for each Capsule fiber stack"));

// Every non-yield transition immediately re-enters the managed dispatcher.
// Call, return, and an intra-frame continuation need no distinct outer action.
constexpr int ActionContinue = 0;
// Same frame, but return to the native caller before dispatching it again.
constexpr int ActionYield = 2;

// Separately verified scalar subprograms are the fastest representation of a
// compact, pointer-free call island. The per-function proof is independent of
// module size; a fixed target-budgeted selection prevents large ports from
// consuming the old kernel's 256-subprogram limit.
constexpr uint64_t NativeScalarFunctionIrLimit = 1024;
constexpr uint64_t NativeScalarExpandedLoopLimit = 4096;
constexpr uint64_t NativeScalarAllocaLimit = 256;
constexpr unsigned NativeScalarLoopTripLimit = 64;
constexpr unsigned NativeScalarFunctionLimit = 32;
// The one-invocation driver reaches managed code through entry -> trampoline
// -> level-one driver -> router -> step.  On old kernels that leaves two
// reliably usable BPF subprogram frames for a native scalar island.  Prove
// the complete island (including unmanaged soft-float callees) against that
// budget instead of accepting locally safe functions whose composed call
// chain the 5.15 verifier rejects.
constexpr unsigned NativeScalarCallDepthLimit = 2;
// Even a single-use helper can make the verifier's path exploration explode
// when folded into an already substantial managed region. Keep automatic
// inlining a compact-call optimization; larger callers retain an ordinary
// managed call and its independently verified physical region.
constexpr unsigned InlineResultInstructionLimit = 256;

bool IsEntryProgram(Function& func) {
    return func.hasSection() && func.getSection() != ".ksyms";
}

bool IsLateMemoryIntrinsic(const Function& func) {
    return func.getName() == "__bpf_capsule_heap_start" || func.getName() == "__bpf_capsule_heap_size";
}

bool IsStackifiable(Function& func) {
    if (func.isDeclaration() || func.getName().starts_with("llvm.")) {
        return false;
    }
    // The driver and its callback are the machinery that runs managed code;
    // they cannot themselves be managed.
    if (func.getName().starts_with("__bpf_capsule_trampoline") || func.getName().starts_with("bpf_heap_")) {
        return false;
    }
    // Target runtime routines have their own verifier-aware native policy.
    // Each selected routine remains a global subprogram checked once against
    // unknown scalar arguments, avoiding a managed suspend/dispatch/resume at
    // every primitive operation. Branch-heavy routines that do not satisfy
    // that policy remain stackifiable and use the universal fallback.
    if (bpf::IsUnmanagedRuntime(func.getName())) {
        return false;
    }
    return bpf::IsCapsuleFunction(func) && !IsEntryProgram(func);
}

// A value crossing a managed call must live in memory: after the transform the
// code before and after the call runs in two separate invocations.
class LivenessAnalysis {
public:
    explicit LivenessAnalysis(Function& func) {
        // Standard iterative backward liveness over basic blocks.
        DenseMap<BasicBlock*, SmallPtrSet<Value*, 16>> use;
        DenseMap<BasicBlock*, SmallPtrSet<Value*, 16>> def;

        for (auto&& block : func) {
            auto& blockUse = use[&block];
            auto& blockDef = def[&block];
            for (auto&& inst : block) {
                if (auto* phi = dyn_cast<PHINode>(&inst)) {
                    // PHI operands are live out of the predecessor, not here.
                    blockDef.insert(phi);
                    continue;
                }
                for (auto&& op : inst.operands()) {
                    auto* v = op.get();
                    if ((isa<Instruction>(v) || isa<Argument>(v)) && !blockDef.contains(v)) {
                        blockUse.insert(v);
                    }
                }
                blockDef.insert(&inst);
            }
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (auto&& block : reverse(func)) {
                SmallPtrSet<Value*, 16> out;
                for (auto* succ : successors(&block)) {
                    for (auto* v : LiveIn_[succ]) {
                        out.insert(v);
                    }
                    // PHIs in the successor make their incoming value live here.
                    for (auto&& phi : succ->phis()) {
                        auto* v = phi.getIncomingValueForBlock(&block);
                        if (isa<Instruction>(v) || isa<Argument>(v)) {
                            out.insert(v);
                        }
                    }
                }

                auto in = use[&block];
                for (auto* v : out) {
                    if (!def[&block].contains(v)) {
                        in.insert(v);
                    }
                }

                auto& oldIn = LiveIn_[&block];
                bool different = in.size() != oldIn.size();
                if (!different) {
                    for (Value* value : in) {
                        if (!oldIn.contains(value)) {
                            different = true;
                            break;
                        }
                    }
                }
                if (different) {
                    changed = true;
                }
                LiveIn_[&block] = std::move(in);
                LiveOut_[&block] = std::move(out);
            }
        }
    }

    // Values live immediately AFTER `inst` — i.e. that must survive a
    // suspension placed there.
    SmallPtrSet<Value*, 16> liveAfter(Instruction* inst) const {
        BasicBlock* block = inst->getParent();
        SmallPtrSet<Value*, 16> live = LiveOut_.lookup(block);
        for (auto& i : reverse(*block)) {
            if (&i == inst) {
                break;
            }
            live.erase(&i);
            if (isa<PHINode>(&i)) {
                continue;
            }
            for (auto&& op : i.operands()) {
                auto* v = op.get();
                if (isa<Instruction>(v) || isa<Argument>(v)) {
                    live.insert(v);
                }
            }
        }
        return live;
    }

    // Values that specifically cross `from -> to`.  Block live-out is the
    // union of every successor and badly over-approximates switch edges;
    // PHI operands, conversely, belong only to their incoming edge.
    SmallPtrSet<Value*, 16> liveAcross(BasicBlock* from, BasicBlock* to) const {
        SmallPtrSet<Value*, 16> live = LiveIn_.lookup(to);
        for (auto&& phi : to->phis()) {
            Value* value = phi.getIncomingValueForBlock(from);
            if (isa<Instruction>(value) || isa<Argument>(value)) {
                live.insert(value);
            }
        }
        return live;
    }

private:
    DenseMap<BasicBlock*, SmallPtrSet<Value*, 16>> LiveIn_;
    DenseMap<BasicBlock*, SmallPtrSet<Value*, 16>> LiveOut_;
};

// Pointer sets are appropriate for liveness membership, but their iteration
// order depends on allocation addresses.  Consuming that order while creating
// spill slots made otherwise identical builds acquire different frame layouts
// when source/debug paths changed.  Always cross from set semantics back to IR
// in the function's stable argument/instruction order.
SmallVector<Value*, 16> ValuesInProgramOrder(Function& function, const SmallPtrSetImpl<Value*>& values) {
    SmallVector<Value*, 16> ordered;
    for (Argument& argument : function.args()) {
        if (values.contains(&argument)) {
            ordered.push_back(&argument);
        }
    }
    for (Instruction& instruction : instructions(function)) {
        if (values.contains(&instruction)) {
            ordered.push_back(&instruction);
        }
    }
    return ordered;
}

struct ManagedFunction {
    Function* Original = nullptr;
    Function* Stage = nullptr;   // temporary owner until regions are packed
    BasicBlock* Entry = nullptr; // temporary frame setup block
    Value* Sp = nullptr;
    Value* Frame = nullptr;
    uint32_t EntryPc = 0;
    struct State {
        uint32_t Pc = 0;
        BasicBlock* Root = nullptr;
    };
    SmallVector<State> States;
    SmallVector<uint64_t> ArgOffsets; // byte offset of each argument in the frame
    DenseMap<AllocaInst*, uint64_t> AllocaOffsets;
    uint64_t LocalsOffset = 0;
    uint64_t FrameSize = 0;
    uint64_t ReturnSize = 0;
    uint32_t TailClass = 0;
    // CFG edges selected as physical region boundaries after initial
    // demotion.  The second demotion round and the transform consume this
    // exact list, so no moving instruction can move the boundary.
    struct CutEdge {
        BasicBlock* From = nullptr;
        BasicBlock* To = nullptr;
    };
    SmallVector<CutEdge> CutEdges;
};

// A maximal connected piece of transformed CFG.  Suspension edges have
// already become returns, so a region can move independently between LLVM
// functions without introducing cross-function control flow.
struct Region {
    ManagedFunction* Owner = nullptr;
    SmallVector<BasicBlock*> Blocks;
    SmallVector<ManagedFunction::State> States;
    uint64_t Size = 0;
    unsigned Group = 0;
    bool BorrowedContext = false;
};

// One generated subprogram serving several continuation regions.
struct StepGroup {
    Function* Func = nullptr;
    DISubprogram* Subprogram = nullptr;
    BasicBlock* Dispatch = nullptr;
    Value* Sp = nullptr;
    Value* Frame = nullptr;
    SmallVector<ManagedFunction::State> States;
    bool BorrowedContext = false;
};

class StackifyImpl {
public:
    explicit StackifyImpl(Module& module)
        : Module_(module)
        , Ctx_(module.getContext())
        , I8_(Type::getInt8Ty(Ctx_))
        , I32_(Type::getInt32Ty(Ctx_))
        , I64_(Type::getInt64Ty(Ctx_)) {
    }

    bool stopAfter(unsigned phase) const {
        return StopAfterPhase != 0 && phase >= StopAfterPhase;
    }

    bool run() {
        FlattenNativeBoundaryCallers();
        if (InputError_) {
            return false;
        }
        ChooseManagedFunctions();
        if (InputError_) {
            return false;
        }
        ValidateYieldCalls();
        if (YieldError_) {
            return false;
        }
        if (Managed_.empty()) {
            bool removedDrivers = RemoveUnusedRuntimeDrivers();
            return removedDrivers || !NativeScalarFunctions_.empty();
        }
        ConfigureFibers();
        ConfigureBorrowedContext();
        if (InputError_) {
            return false;
        }
        ValidateScalarRootsDoNotReachBorrowedContext();
        if (InputError_) {
            return false;
        }
        DiscoverNativeHelperAllocas();
        if (stopAfter(1)) {
            return false;
        }
        ValidateVerifierPointerStorageAndCalls();
        if (VerifierPointerError_) {
            return false;
        }
        ClassifyLoops();
        if (VerifierPointerError_) {
            return false;
        }
        ValidateVerifierPointerBackedges();
        if (VerifierPointerError_) {
            return false;
        }
        // Demote cross-call values first: it creates the allocas whose sizes
        // determine the frame layout.
        for (auto&& [func, info] : Managed_) {
            DemoteAcrossCalls(*func);
            LocalizeReloadsBypassedByChunkResume(*func);
        }
        PlanRegionCuts();
        // The cut graph is chosen from actual post-demotion size.  Demote once
        // more so every value crossing a newly planned physical boundary is
        // represented in the managed frame.
        for (auto&& [func, info] : Managed_) {
            if (!info->CutEdges.empty()) {
                DemoteAcrossRegionCuts(*func);
                LocalizeReloadsBypassedByChunkResume(*func);
            }
        }
        if (stopAfter(2)) {
            return true;
        }
        ComputeFrameLayout();
        if (InputError_) {
            return false;
        }
        EqualizeIndirectTailFrames();
        CreateStackGlobals();
        CreateStages();
        CreateFrameSizeTable();
        if (stopAfter(3)) {
            return true;
        }

        for (auto&& func : Managed_) {
            TransformFunction(*func.second);
        }
        if (YieldMarker_) {
            if (!YieldMarker_->use_empty()) {
                report_fatal_error("stackify: capsule_yield marker survived function transformation");
            }
            YieldMarker_->eraseFromParent();
            YieldMarker_ = nullptr;
        }
        if (TailCallsLowered_) {
            bpf::stats() << "stackify: reused " << TailCallsLowered_ << " continuation frames for tail calls\n";
        }
        FormRegionsAndCreateStepGroups();
        ReplaceFiberUses();
        ReplaceBorrowedContextUses();
        // The resume dispatch jumps into loop bodies, and the fix-irreducible
        // pass that untangles the result can only rewire BranchInst
        // terminators — a switch edge into the irreducible region crashes
        // LLVM's ControlFlowHub. Splitting every critical switch edge leaves
        // the switches (and their speed) alone while guaranteeing the hub
        // only ever has to redirect a branch.
        for (auto&& group : Groups_) {
            SmallVector<std::pair<Instruction*, unsigned>> edges;
            for (auto&& block : *group.Func) {
                auto* sw = dyn_cast_or_null<SwitchInst>(block.getTerminator());
                if (!sw) {
                    continue;
                }
                for (unsigned i = 0; i < sw->getNumSuccessors(); i++) {
                    if (sw->getSuccessor(i)->hasNPredecessorsOrMore(2)) {
                        edges.push_back({sw, i});
                    }
                }
            }
            for (auto&& [sw, idx] : edges) {
                SplitCriticalEdge(sw, idx, CriticalEdgeSplittingOptions().setMergeIdenticalEdges());
            }
        }
        FinishStepGroups();
        if (stopAfter(4)) {
            return true;
        }
        BuildTrampoline();
        if (stopAfter(5)) {
            return true;
        }
        RewriteEntryPrograms();
        RewriteReturnCopies();
        InternalizeOrdinaryFunctions();
        if (stopAfter(6)) {
            return true;
        }

        // Every call to a managed function is now a frame push, so whatever
        // uses remain are address-of uses (dispatch tables, comparisons) and
        // become the function's integer id. RAUW rather than Use::set: some of
        // those uses live inside uniqued constant initializers.
        for (auto&& [func, info] : Managed_) {
            for (auto&& use : func->uses()) {
                if (auto* call = dyn_cast<CallBase>(use.getUser()); call && call->isCallee(&use)) {
                    report_fatal_error(Twine("stackify: leftover call to ") + func->getName());
                }
            }
            if (info->EntryPc >= BPF_CAPSULE_MANAGED_FUNCTION_TOKEN_LIMIT) {
                report_fatal_error("stackify: managed function-token range exhausted");
            }
            func->replaceAllUsesWith(
                ConstantExpr::getIntToPtr(ConstantInt::get(I64_, (uint64_t)BPF_CAPSULE_FUNCTION_TOKEN_BASE + info->EntryPc), func->getType())
            );
            func->eraseFromParent();
        }

        return true;
    }

private:
    // ---------------------------------------------------------------- policy

    // The old verifier's call-depth limit is independent of stack bytes. The
    // generated fixed-map path already needs the full bounded chain from an
    // entry through the trampoline and memory accessors, so a native helper
    // which retains the capsule_call boundary would add an unsafe frame above
    // it. Inline precisely the native boundary-owning chain into its entry.
    // This does not flatten unrelated native helpers or any managed library
    // code, and it preserves capsule_call as a usable expression in a small
    // source-level wrapper.
    void FlattenNativeBoundaryCallers() {
        unsigned inlined = 0;
        for (;;) {
            Function* wrapper = nullptr;
            for (Function& function : Module_) {
                if (function.isDeclaration() || IsEntryProgram(function)) {
                    continue;
                }
                bool ownsBoundary = llvm::any_of(instructions(function), [](Instruction& instruction) {
                    auto* call = dyn_cast<CallBase>(&instruction);
                    return call && call->getOperandBundle("bpf.capsule.call");
                });
                if (ownsBoundary) {
                    wrapper = &function;
                    break;
                }
            }
            if (!wrapper) {
                break;
            }

            SmallVector<CallBase*> sites;
            for (Use& use : wrapper->uses()) {
                auto* call = dyn_cast<CallBase>(use.getUser());
                if (!call || !call->isCallee(&use) || call->getFunction() == wrapper) {
                    wrapper->getContext().emitError(
                        Twine("stackify: native capsule_call wrapper ") + wrapper->getName() + " must be reached only by direct, non-recursive calls"
                    );
                    InputError_ = true;
                    return;
                }
                sites.push_back(call);
            }
            if (sites.empty()) {
                wrapper->getContext().emitError(Twine("stackify: native capsule_call wrapper ") + wrapper->getName() + " is not reachable from a BPF entry");
                InputError_ = true;
                return;
            }

            wrapper->removeFnAttr(Attribute::NoInline);
            for (CallBase* site : sites) {
                InlineFunctionInfo info;
                if (!InlineFunction(*site, info).isSuccess()) {
                    site->getContext().emitError(site, Twine("stackify: cannot flatten native capsule_call wrapper ") + wrapper->getName());
                    InputError_ = true;
                    return;
                }
                inlined++;
            }
            if (!wrapper->use_empty()) {
                wrapper->getContext().emitError(Twine("stackify: native capsule_call wrapper ") + wrapper->getName() + " retained an unsupported reference");
                InputError_ = true;
                return;
            }
            wrapper->eraseFromParent();
        }
        if (inlined) {
            bpf::stats() << "stackify: flattened " << inlined << " native capsule_call wrapper sites into entries\n";
        }
    }

    bool RemoveUnusedRuntimeDrivers() {
        SmallVector<Function*> drivers;
        SmallPtrSet<Function*, 8> driverSet;
        for (Function& func : Module_) {
            if (func.getName().starts_with("__bpf_capsule_trampoline")) {
                drivers.push_back(&func);
                driverSet.insert(&func);
            }
        }
        if (drivers.empty()) {
            return false;
        }

        // Both typed driver variants are retained until Stackify selects the
        // ABI. If there is no Capsule root, neither variant has a step body;
        // leaving their external declarations in a native-only object makes
        // an otherwise valid object unloadable. References among the driver
        // routines are dead as a unit. Any outside call is instead an invalid
        // continuation with no computation to continue.
        removeFromUsedLists(Module_, [&](Constant* value) { return driverSet.contains(dyn_cast<Function>(value->stripPointerCasts())); });
        for (Function* driver : drivers) {
            driver->removeDeadConstantUsers();
            for (User* user : driver->users()) {
                auto* call = dyn_cast<CallBase>(user);
                if (!call || !driverSet.contains(call->getFunction())) {
                    report_fatal_error(Twine("stackify: call to ") + driver->getName() + " without any Capsule root");
                }
            }
        }
        for (Function* driver : drivers) {
            if (!driver->isDeclaration()) {
                driver->dropAllReferences();
            }
        }
        for (Function* driver : drivers) {
            driver->eraseFromParent();
        }
        return true;
    }

    void ConfigureFibers() {
        FiberControls_ = Module_.getGlobalVariable("bpf_capsule_fibers", true);
        FiberControlsType_ = FiberControls_ ? dyn_cast<ArrayType>(FiberControls_->getValueType()) : nullptr;
        FiberControlType_ = FiberControlsType_ ? dyn_cast<StructType>(FiberControlsType_->getElementType()) : nullptr;
        if (!FiberControlType_ || FiberControlType_->getNumElements() != BPF_CAPSULE_FIBER_CONTROL_FIELD_COUNT ||
            !FiberControlType_->getElementType(BPF_CAPSULE_FIBER_CONTROL_EXIT_WORD)->isIntegerTy(64) ||
            !FiberControlType_->getElementType(BPF_CAPSULE_FIBER_CONTROL_STACK_CURSOR)->isIntegerTy(64) ||
            !FiberControlType_->getElementType(BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE)->isIntegerTy(64) ||
            !FiberControlType_->getElementType(BPF_CAPSULE_FIBER_CONTROL_GENERATION)->isIntegerTy(64)) {
            report_fatal_error("stackify: runtime is missing bpf_capsule_fibers control");
        }
        FiberCount_ = FiberControlsType_->getNumElements();
        FiberConfig_ = Module_.getGlobalVariable("bpf_capsule_config", true);
        FiberConfigType_ = FiberConfig_ ? dyn_cast<StructType>(FiberConfig_->getValueType()) : nullptr;
        if (!FiberConfigType_ || FiberConfigType_->getNumElements() != BPF_CAPSULE_OBJECT_CONFIG_FIELD_COUNT ||
            !FiberConfigType_->getElementType(BPF_CAPSULE_OBJECT_CONFIG_FIBER_COUNT)->isIntegerTy(32)) {
            report_fatal_error("stackify: runtime is missing bpf_capsule_config");
        }
        CurrentFiber_ = Module_.getFunction("__bpf_capsule_current_fiber_index");
        ActiveFiberCount_ = Module_.getFunction("__bpf_capsule_active_fiber_count");
        ExitWordAccessor_ = Module_.getFunction("__bpf_capsule_exit_word_ptr");
        if (!CurrentFiber_) {
            CurrentFiber_ = Function::Create(FunctionType::get(I32_, false), GlobalValue::ExternalLinkage, "__bpf_capsule_current_fiber_index", Module_);
        }
        if (!ExitWordAccessor_) {
            ExitWordAccessor_ =
                Function::Create(FunctionType::get(PointerType::get(Ctx_, 0), false), GlobalValue::ExternalLinkage, "__bpf_capsule_exit_word_ptr", Module_);
        }
        if (!ActiveFiberCount_) {
            ActiveFiberCount_ = Function::Create(FunctionType::get(I32_, false), GlobalValue::ExternalLinkage, "__bpf_capsule_active_fiber_count", Module_);
        }
        GetExitSetter();
    }

    Value* CurrentFiberValue(IRBuilder<>& b) {
        if (!CurrentFiber_ || CurrentFiber_->getParent() != &Module_) {
            report_fatal_error("stackify: current fiber requested after accessor lowering");
        }
        return b.CreateCall(CurrentFiber_, {}, "fiber");
    }

    Value* NormalizeFiber(IRBuilder<>& b, Value* fiber) {
        fiber = b.CreateZExtOrTrunc(fiber, I32_);
        // Generated global subprograms are verified with arbitrary scalar
        // arguments. A select after `fiber < count` looks bounded in IR, but
        // the BPF backend may copy the value before the branch; the verifier
        // then constrains the source register while the copied register used
        // by the map-value GEP remains unbounded. Normalize arithmetically so
        // the exact register used for pointer arithmetic carries the bound.
        // Real callers have already validated the ID, so this is identity on
        // every reachable execution. Power-of-two pools (including the common
        // 2/8/512 cases) cost one ALU32 AND; unusual capacities use UREM.
        if (isPowerOf2_64(FiberCount_)) {
            return b.CreateAnd(fiber, ConstantInt::get(I32_, FiberCount_ - 1), "fiber.index");
        }
        return b.CreateURem(fiber, ConstantInt::get(I32_, FiberCount_), "fiber.index");
    }

    Value* FiberControlPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        if (auto found = NativeFiberControls_.find(b.GetInsertBlock()->getParent()); found != NativeFiberControls_.end()) {
            return found->second;
        }
        if (!fiber) {
            fiber = CurrentFiberValue(b);
        }
        fiber = NormalizeFiber(b, fiber);
        Value* control = b.CreateInBoundsGEP(FiberControlsType_, FiberControls_, {ConstantInt::get(I32_, 0), fiber}, "fiber.control");
        // NormalizeFiber is an arithmetic proof on the exact SSA value used
        // by this GEP. The fixed-memory pass can therefore keep this native
        // control pointer instead of rebuilding a compare/select proof at
        // every field access in the physical step.
        if (auto* gep = dyn_cast<GetElementPtrInst>(control)) {
            gep->setMetadata("bpf.capsule.sectioned.bounded", MDNode::get(Ctx_, {}));
        }
        return control;
    }

    Value* ExitWordPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_EXIT_WORD, "fiber.exit.word");
    }

    Value* StackCursorPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_STACK_CURSOR, "fiber.cursor");
    }

    Value* ReturnSizePtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE, "fiber.return.size");
    }

    Function* GetExitSetter() {
        if (ExitSetter_) {
            return ExitSetter_;
        }
        ExitSetter_ = Function::Create(FunctionType::get(I32_, {I32_, I64_}, false), GlobalValue::ExternalLinkage, "bpf_capsule_set_exit", Module_);
        ExitSetter_->setCallingConv(CallingConv::C);
        ExitSetter_->addFnAttr(Attribute::NoInline);
        ExitSetter_->setMetadata("bpf.native.scalar", MDNode::get(Ctx_, {}));
        ExitSetter_->getArg(0)->setName("fiber");
        ExitSetter_->getArg(1)->setName("code");

        BasicBlock* entry = BasicBlock::Create(Ctx_, "entry", ExitSetter_);
        IRBuilder<> b(entry);
        StoreInst* store = b.CreateStore(ExitSetter_->getArg(1), ExitWordPtr(b, ExitSetter_->getArg(0)));
        // This function is also a backend barrier: keeping the sectioned-map
        // abort store away from arena-stack store suffixes prevents LLVM's BPF
        // tail merger from producing one instruction with two pointer types.
        store->setVolatile(true);
        b.CreateRet(ConstantInt::get(I32_, 0));

        if (!Module_.debug_compile_units().empty()) {
            DIBuilder db(Module_, false, *Module_.debug_compile_units_begin());
            BtfFunctionAddDebugInfo(db, *ExitSetter_, {BtfGetInt(db, 32, true), BtfGetInt(db, 32, false), BtfGetInt(db, 64, false)});
            db.finalize();
        }
        return ExitSetter_;
    }

    void ConfigureBorrowedContext() {
        for (auto&& [func, info] : Managed_) {
            for (Argument& arg : func->args()) {
                if (!arg.hasAttribute("bpf.capsule.borrowed")) {
                    continue;
                }
                if (!arg.getType()->isPointerTy()) {
                    func->getContext().emitError(Twine("stackify: borrowed argument in ") + func->getName() + " is not a pointer");
                    InputError_ = true;
                    return;
                }
                if (BorrowedContext_) {
                    func->getContext().emitError(
                        "stackify: one borrowed verifier context is supported "
                        "per Capsule object"
                    );
                    InputError_ = true;
                    return;
                }
                BorrowedContext_ = true;
                BorrowedFunction_ = func;
                BorrowedArgument_ = arg.getArgNo();

                DISubprogram* subprogram = func->getSubprogram();
                if (!subprogram || !subprogram->getType() || subprogram->getType()->getTypeArray().size() <= BorrowedArgument_ + 1) {
                    func->getContext().emitError(Twine("stackify: borrowed context in ") + func->getName() + " needs debug/BTF type information");
                    InputError_ = true;
                    return;
                }
                BorrowedDebugType_ = subprogram->getType()->getTypeArray()[BorrowedArgument_ + 1];
                if (!BorrowedDebugType_) {
                    func->getContext().emitError(Twine("stackify: borrowed context in ") + func->getName() + " has no BTF pointer type");
                    InputError_ = true;
                    return;
                }
            }
        }
        if (BorrowedContext_) {
            BorrowedCurrent_ =
                cast<Function>(Module_.getOrInsertFunction("__bpf_capsule_current_ctx", FunctionType::get(PointerType::get(Ctx_, 0), false)).getCallee());
        }
    }

    // A verifier context exists only while executing the native entry that
    // supplied it. Reject every statically visible scalar-to-context path;
    // optimizers remain free to prove and delete an unreachable context branch
    // first. Computed managed calls are checked dynamically by the scalar
    // step's deliberately incomplete group switch: a context PC cannot be
    // dispatched without the typed driver and becomes INVALID_DISPATCH.
    void ValidateScalarRootsDoNotReachBorrowedContext() {
        if (!BorrowedContext_) {
            return;
        }

        SmallVector<Function*> scalarRoots;
        for (Function& function : Module_) {
            for (Instruction& instruction : instructions(function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || !call->getOperandBundle("bpf.capsule.call")) {
                    continue;
                }
                Function* root = call->getCalledFunction();
                if (root && root != BorrowedFunction_) {
                    scalarRoots.push_back(root);
                }
            }
        }

        auto directlyUsesBorrowedContext = [&](Function* function) {
            if (function == BorrowedFunction_ && !function->getArg(BorrowedArgument_)->use_empty()) {
                return true;
            }
            return llvm::any_of(instructions(function), [&](Instruction& instruction) {
                auto* call = dyn_cast<CallBase>(&instruction);
                return call && call->getCalledFunction() == BorrowedCurrent_;
            });
        };

        for (Function* root : scalarRoots) {
            SmallPtrSet<Function*, 32> visited;
            SmallVector<Function*> worklist{root};
            while (!worklist.empty()) {
                Function* function = worklist.pop_back_val();
                if (!visited.insert(function).second) {
                    continue;
                }
                if (directlyUsesBorrowedContext(function)) {
                    root->getContext().emitError(
                        Twine("stackify: scalar Capsule root ") + root->getName() + " has a direct call path to context-dependent function " +
                        function->getName()
                    );
                    InputError_ = true;
                    return;
                }

                for (Instruction& instruction : instructions(function)) {
                    auto* call = dyn_cast<CallBase>(&instruction);
                    if (!call || !IsManagedCall(call)) {
                        continue;
                    }
                    if (Function* callee = call->getCalledFunction()) {
                        worklist.push_back(callee);
                    }
                }
            }
        }
    }

    // Helper and kfunc memory operands must remain verifier-visible. Keep only
    // local objects whose address reaches such a call on the native BPF stack;
    // every other addressable local belongs to the unified Capsule stack.
    void DiscoverNativeHelperAllocas() {
        for (auto&& [function, info] : Managed_) {
            for (Instruction& instruction : instructions(*function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || !bpf::IsVerifierCall(*call)) {
                    continue;
                }
                for (Use& argument : call->args()) {
                    auto* alloca = dyn_cast<AllocaInst>(getUnderlyingObject(argument.get()));
                    if (!alloca) {
                        continue;
                    }
                    alloca->setMetadata("bpf.native.alloca", MDNode::get(Ctx_, {}));
                    if (NativeHelperAllocas_.insert(alloca).second) {
                        NativeHelperAllocaOrder_.push_back(alloca);
                    }
                }
            }
        }
        if (!NativeHelperAllocas_.empty()) {
            bpf::stats() << "stackify: kept " << NativeHelperAllocas_.size() << " helper-visible locals on the native BPF stack\n";
        }
    }

    void FindVerifierNativeValues(Function& function, SmallPtrSetImpl<Value*>& native) const {
        for (AllocaInst* alloca : NativeHelperAllocaOrder_) {
            if (alloca->getFunction() == &function) {
                native.insert(alloca);
            }
        }
        bpf::FindVerifierNativeValues(function, native);
    }

    bool IsRematerializableVerifierRoot(Value* value) const {
        if (NativeHelperAllocas_.contains(dyn_cast<AllocaInst>(value))) {
            return true;
        }
        auto* argument = dyn_cast<Argument>(value);
        return argument && argument->hasAttribute("bpf.capsule.borrowed");
    }

    SmallVector<const AllocaInst*, 8> NativeHelperAllocas(Function& function) const {
        SmallVector<const AllocaInst*, 8> allocas;
        for (AllocaInst* alloca : NativeHelperAllocaOrder_) {
            if (alloca->getFunction() == &function) {
                allocas.push_back(alloca);
            }
        }
        return allocas;
    }

    bool RejectLiveNativeHelperAllocas(Function& function, StackLifetime& lifetime, Instruction* boundary, const Twine& reason) {
        for (const AllocaInst* alloca : NativeHelperAllocas(function)) {
            if (lifetime.isAliveAfter(alloca, boundary)) {
                RejectVerifierPointer(const_cast<AllocaInst*>(alloca), function, reason);
                return true;
            }
        }
        return false;
    }

    void RejectVerifierPointer(Value* value, Function& function, const Twine& reason) {
        std::string source;
        raw_string_ostream stream(source);
        if (auto* call = dyn_cast<CallBase>(value); call && bpf::IsVerifierPointerSource(*call)) {
            if (Function* callee = call->getCalledFunction()) {
                stream << "pointer returned by " << callee->getName();
            } else {
                stream << "pointer returned by a BPF helper";
            }
        } else if (auto* argument = dyn_cast<Argument>(value); argument && argument->hasAttribute("bpf.capsule.borrowed")) {
            stream << "borrowed verifier argument " << argument->getName();
        } else {
            stream << "value ";
            value->printAsOperand(stream, false);
            stream << " derived from a verifier pointer";
        }
        stream.flush();
        function.getContext().emitError(Twine("stackify: ") + source + " in " + function.getName() + " " + reason);
        VerifierPointerError_ = true;
    }

    bool RejectNativeValues(Function& function, const SmallPtrSetImpl<Value*>& native, const SmallPtrSetImpl<Value*>& values, const Twine& reason) {
        for (Value* value : ValuesInProgramOrder(function, values)) {
            if (native.contains(value) && !IsRematerializableVerifierRoot(value)) {
                RejectVerifierPointer(value, function, reason);
                return true;
            }
        }
        return false;
    }

    // Verifier-owned pointers are capabilities for one physical BPF region.
    // They may use registers or native BPF stack spills, but cannot enter the
    // software frame which survives a return to the trampoline. The borrowed
    // entry context is the sole exception: every physical step receives that
    // root again and ReplaceArgumentUses rematerializes it at each use.
    void ValidateVerifierPointerStorageAndCalls() {
        for (auto&& [function, info] : Managed_) {
            SmallPtrSet<Value*, 32> native;
            FindVerifierNativeValues(*function, native);
            SmallVector<const AllocaInst*, 8> nativeAllocas = NativeHelperAllocas(*function);
            StackLifetime stackLifetime(*function, nativeAllocas, StackLifetime::LivenessType::May);
            stackLifetime.run();

            for (Instruction& instruction : instructions(*function)) {
                if (auto* store = dyn_cast<StoreInst>(&instruction); store && native.contains(store->getValueOperand())) {
                    RejectVerifierPointer(store->getValueOperand(), *function, "is stored outside native BPF registers/stack");
                    return;
                }
                if (auto* ret = dyn_cast<ReturnInst>(&instruction); ret && ret->getReturnValue() && native.contains(ret->getReturnValue())) {
                    RejectVerifierPointer(ret->getReturnValue(), *function, "escapes through a Capsule return value");
                    return;
                }
            }

            LivenessAnalysis liveness(*function);
            for (CallBase* call : SuspensionCalls(*function)) {
                for (Use& argument : call->args()) {
                    auto* borrowed = dyn_cast<Argument>(argument.get());
                    if (native.contains(argument.get()) && !(borrowed && borrowed->hasAttribute("bpf.capsule.borrowed"))) {
                        RejectVerifierPointer(argument.get(), *function, "is passed through a Capsule suspension point");
                        return;
                    }
                }
                if (RejectLiveNativeHelperAllocas(*function, stackLifetime, call, "is live across a Capsule suspension point")) {
                    return;
                }
                SmallPtrSet<Value*, 16> crossing = liveness.liveAfter(call);
                if (RejectNativeValues(*function, native, crossing, "is live across a Capsule suspension point")) {
                    return;
                }
            }
        }
    }

    void ValidateVerifierPointerBackedges() {
        for (auto&& [function, info] : Managed_) {
            SmallPtrSet<Value*, 32> native;
            FindVerifierNativeValues(*function, native);
            if (native.empty()) {
                continue;
            }
            SmallVector<const AllocaInst*, 8> nativeAllocas = NativeHelperAllocas(*function);
            StackLifetime stackLifetime(*function, nativeAllocas, StackLifetime::LivenessType::May);
            stackLifetime.run();
            LivenessAnalysis liveness(*function);
            for (const Backedge& edge : Backedges(*function)) {
                BasicBlock* resume = edge.ChunkTrips ? ChunkResumes_.lookup(edge.Header) : edge.Header;
                if (!resume) {
                    report_fatal_error("stackify: chunked loop is missing its resume edge");
                }
                if (RejectLiveNativeHelperAllocas(*function, stackLifetime, edge.Latch->getTerminator(), "is live across a suspendable loop boundary")) {
                    return;
                }
                SmallPtrSet<Value*, 16> crossing = liveness.liveAcross(edge.Latch, resume);
                if (RejectNativeValues(*function, native, crossing, "is live across a suspendable loop boundary")) {
                    return;
                }
            }
        }
    }

    bool HasScalarBpfAbi(Function& func) const {
        auto scalar = [](Type* type) { return type->isIntegerTy() && type->getIntegerBitWidth() <= 64; };
        // Linux 5.15 rejects a global BPF subprogram whose return type is
        // void, even when every argument is scalar.
        if (func.isVarArg() || !scalar(func.getReturnType())) {
            return false;
        }
        return llvm::all_of(func.args(), [&](Argument& arg) { return scalar(arg.getType()); });
    }

    bool HasOnlyDirectCallUses(Function& func) const {
        for (Use& use : func.uses()) {
            auto* call = dyn_cast<CallBase>(use.getUser());
            if (!call || !call->isCallee(&use)) {
                return false;
            }
        }
        return true;
    }

    bool FitsNativeScalarBody(Function& func) const {
        if (func.getInstructionCount() > NativeScalarFunctionIrLimit) {
            return false;
        }

        const DataLayout& dl = Module_.getDataLayout();
        uint64_t stack = 0;
        for (Instruction& inst : instructions(func)) {
            auto* alloca = dyn_cast<AllocaInst>(&inst);
            if (!alloca) {
                continue;
            }
            auto* count = dyn_cast<ConstantInt>(alloca->getArraySize());
            if (!alloca->isStaticAlloca() || !count) {
                return false;
            }
            stack = alignTo(stack, alloca->getAlign());
            stack += dl.getTypeAllocSize(alloca->getAllocatedType()) * count->getZExtValue();
            if (stack > NativeScalarAllocaLimit) {
                return false;
            }
        }

        TargetLibraryInfoImpl tliImpl(Triple(Module_.getTargetTriple()));
        TargetLibraryInfo tli(tliImpl);
        AssumptionCache ac(func);
        DominatorTree dt(func);
        LoopInfo li(dt);
        ScalarEvolution se(func, tli, ac, dt, li);
        uint64_t expanded = 0;
        for (Loop* loop : li.getLoopsInPreorder()) {
            unsigned trips = se.getSmallConstantTripCount(loop);
            if (!trips) {
                trips = se.getSmallConstantMaxTripCount(loop);
            }
            if (!trips || trips > NativeScalarLoopTripLimit) {
                return false;
            }
            uint64_t bodyIr = 0;
            for (BasicBlock* block : loop->blocks()) {
                bodyIr += EstimatedBlockSize(*block);
            }
            expanded += uint64_t(trips - 1) * bodyIr;
            if (expanded > NativeScalarExpandedLoopLimit) {
                return false;
            }
        }
        return true;
    }

    bool IsAlwaysNativeCallee(Function& func) const {
        return bpf::IsUnmanagedRuntime(func.getName()) || IsLateMemoryIntrinsic(func) || func.getName().starts_with("bpf_heap_") ||
            func.getName().starts_with("__bpf_capsule_trampoline");
    }

    bool IsCapsuleRoot(Function& func) const {
        for (Use& use : func.uses()) {
            auto* call = dyn_cast<CallBase>(use.getUser());
            if (call && call->isCallee(&use) && call->getOperandBundle("bpf.capsule.call")) {
                return true;
            }
        }
        return false;
    }

    unsigned NativeScalarCallDepth(
        Function* func, const SmallPtrSetImpl<Function*>& candidates, DenseMap<Function*, unsigned>& memo, SmallPtrSetImpl<Function*>& active
    ) const {
        auto cached = memo.find(func);
        if (cached != memo.end()) {
            return cached->second;
        }
        // Candidate recursion was removed with the SCC pass.  Keep this guard
        // for runtime routines too, so a newly added recursive primitive is
        // conservatively managed rather than defeating the depth proof.
        if (!active.insert(func).second) {
            return NativeScalarCallDepthLimit + 1;
        }

        unsigned depth = 1;
        if (!func->isDeclaration()) {
            for (Instruction& inst : instructions(*func)) {
                auto* call = dyn_cast<CallBase>(&inst);
                if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                    continue;
                }
                Function* callee = call->getCalledFunction();
                if (!callee || (!candidates.contains(callee) && !IsAlwaysNativeCallee(*callee))) {
                    continue;
                }
                unsigned child = NativeScalarCallDepth(callee, candidates, memo, active);
                depth = std::max(depth, 1 + child);
                if (depth > NativeScalarCallDepthLimit) {
                    break;
                }
            }
        }
        active.erase(func);
        memo[func] = depth;
        return depth;
    }

    // A global BPF subprogram with a scalar-only ABI is verified once against
    // unknown scalar arguments. For a compact, acyclic and statically bounded
    // call island this is both cheaper and faster than suspend/dispatch/resume
    // around every call. Pointer-bearing APIs and anything whose proof is not
    // local remain managed, preserving the universal fallback.
    void ChooseNativeScalarIslands() {
        SmallPtrSet<Function*, 32> candidates;
        for (Function& func : Module_) {
            // A capsule_call root owns frame construction, suspension status
            // and typed return copying even when its body happens to satisfy
            // the native scalar-island proof. Promoting it would strand the
            // boundary operand bundle in native IR and, more importantly,
            // silently remove the fiber ABI.
            if (IsCapsuleRoot(func) || !IsStackifiable(func) || func.use_empty() || !HasScalarBpfAbi(func) || !HasOnlyDirectCallUses(func) ||
                !FitsNativeScalarBody(func)) {
                continue;
            }
            candidates.insert(&func);
        }

        // Recursion needs the managed software stack even when its public ABI
        // happens to be scalar.
        CallGraph cg(Module_);
        for (auto it = scc_begin(&cg); !it.isAtEnd(); ++it) {
            const std::vector<CallGraphNode*>& scc = *it;
            bool recursive = scc.size() > 1;
            if (scc.size() == 1) {
                Function* func = scc[0]->getFunction();
                for (auto&& edge : *scc[0]) {
                    recursive |= func && edge.second->getFunction() == func;
                }
            }
            if (recursive) {
                for (CallGraphNode* node : scc) {
                    if (Function* func = node->getFunction()) {
                        candidates.erase(func);
                    }
                }
            }
        }

        auto pruneInvalidDependencies = [&]() {
            bool changed;
            do {
                changed = false;
                SmallVector<Function*> remove;
                for (Function* func : candidates) {
                    bool valid = true;
                    for (Instruction& inst : instructions(*func)) {
                        auto* call = dyn_cast<CallBase>(&inst);
                        if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                            continue;
                        }
                        Function* callee = call->getCalledFunction();
                        if (!callee) {
                            // Numbered BPF helpers are constant callees;
                            // computed indirect calls require the managed
                            // dispatcher.
                            valid &= isa<Constant>(call->getCalledOperand());
                        } else {
                            valid &= candidates.contains(callee) || IsAlwaysNativeCallee(*callee);
                        }
                        if (!valid) {
                            break;
                        }
                    }
                    if (!valid) {
                        remove.push_back(func);
                    }
                }
                for (Function* func : remove) {
                    changed |= candidates.erase(func);
                }
            } while (changed);
        };
        pruneInvalidDependencies();

        DenseMap<Function*, unsigned> depths;
        SmallPtrSet<Function*, 32> active;
        SmallVector<Function*> tooDeep;
        for (Function* func : candidates) {
            if (NativeScalarCallDepth(func, candidates, depths, active) > NativeScalarCallDepthLimit) {
                tooDeep.push_back(func);
            }
        }
        for (Function* func : tooDeep) {
            candidates.erase(func);
        }
        // Removing a deep callee also removes callers that depended on it;
        // silently converting only the callee would leave an ordinary BPF
        // call from a native island into managed CPS code.
        pruneInvalidDependencies();

        // A large library can contain hundreds of individually safe scalar
        // leaves. Keeping none of them merely because the module is large
        // throws the hottest calls back through the managed dispatcher. Rank
        // by static call frequency, weighting calls inside source loops, and
        // retain dependency-closed islands up to the reserved subprogram
        // budget. This is profile-free and deterministic; it is not a user
        // tuning knob.
        if (candidates.size() > NativeScalarFunctionLimit) {
            DenseMap<Function*, uint64_t> scores;
            for (Function& caller : Module_) {
                if (caller.isDeclaration()) {
                    continue;
                }
                DominatorTree dt(caller);
                LoopInfo li(dt);
                for (Instruction& inst : instructions(caller)) {
                    auto* call = dyn_cast<CallBase>(&inst);
                    Function* callee = call ? call->getCalledFunction() : nullptr;
                    if (!callee || !candidates.contains(callee)) {
                        continue;
                    }
                    unsigned depth = li.getLoopDepth(inst.getParent());
                    scores[callee] += uint64_t(1) << std::min(depth, 12u);
                }
            }

            SmallVector<Function*> ranked(candidates.begin(), candidates.end());
            llvm::sort(ranked, [&](Function* a, Function* b) {
                if (scores.lookup(a) != scores.lookup(b)) {
                    return scores.lookup(a) > scores.lookup(b);
                }
                if (a->getInstructionCount() != b->getInstructionCount()) {
                    return a->getInstructionCount() > b->getInstructionCount();
                }
                return a->getName() < b->getName();
            });

            SmallPtrSet<Function*, 32> selected;
            for (Function* root : ranked) {
                if (!scores.lookup(root) || selected.contains(root)) {
                    continue;
                }
                SmallPtrSet<Function*, 32> closure;
                SmallVector<Function*> work{root};
                while (!work.empty()) {
                    Function* func = work.pop_back_val();
                    if (selected.contains(func) || !closure.insert(func).second) {
                        continue;
                    }
                    for (Instruction& inst : instructions(*func)) {
                        auto* call = dyn_cast<CallBase>(&inst);
                        Function* callee = call ? call->getCalledFunction() : nullptr;
                        if (callee && candidates.contains(callee) && !selected.contains(callee)) {
                            work.push_back(callee);
                        }
                    }
                }
                if (selected.size() + closure.size() > NativeScalarFunctionLimit) {
                    continue;
                }
                for (Function* func : closure) {
                    selected.insert(func);
                }
            }
            unsigned proven = candidates.size();
            candidates.clear();
            for (Function* func : selected) {
                candidates.insert(func);
            }
            bpf::stats() << "stackify: selected " << candidates.size() << " of " << proven << " proven scalar functions by static hotness\n";
        }
        for (Function* func : candidates) {
            func->setLinkage(GlobalValue::ExternalLinkage);
            func->removeFnAttr(Attribute::AlwaysInline);
            func->addFnAttr(Attribute::NoInline);
            func->setMetadata("bpf.native.scalar", MDNode::get(Ctx_, {}));
            // This function's complete static alloca footprint was just
            // proven small. Preserve those objects on the real BPF stack when
            // MemoryPass runs later; otherwise an address-obscuring frontend
            // operation (Rust's black_box is the common example) makes the
            // arena escape analysis virtualize even a few scalar temporaries.
            // Late register spills remain independently bounded by the MIR
            // spill relocator, so this does not weaken the 512-byte guarantee.
            for (Instruction& inst : instructions(*func)) {
                if (auto* alloca = dyn_cast<AllocaInst>(&inst)) {
                    alloca->setMetadata("bpf.native.alloca", MDNode::get(Ctx_, {}));
                }
            }
            NativeScalarFunctions_.insert(func);
        }
        if (!NativeScalarFunctions_.empty()) {
            bpf::stats() << "stackify: kept " << NativeScalarFunctions_.size() << " bounded scalar functions as native BPF islands\n";
        }
    }

    // Everything that survives inlining becomes managed. Leaving no ordinary
    // subprograms behind keeps the BPF call graph at a fixed depth of three
    // (entry -> trampoline -> step) and means the only functions the kernel
    // sees are the ones we generate, all with scalar signatures.
    void ChooseManagedFunctions() {
        PrepareNoSuspendFunctions();
        InlineSmallFunctions();
        ChooseNativeScalarIslands();

        for (auto&& func : Module_) {
            if (!IsStackifiable(func) || NativeScalarFunctions_.contains(&func)) {
                continue;
            }
            // Entry PCs are handed out after the managed set is fixed.  The
            // physical step group is deliberately not encoded in them.
            CheckSignature(func);
            auto info = std::make_unique<ManagedFunction>();
            info->Original = &func;
            Managed_.emplace_back(&func, std::move(info));
        }
        // llvm-link preserves input-module order, and archive member order is
        // not a semantic property of the whole program.  PCs and physical
        // packing must not depend on that incidental order.
        llvm::stable_sort(Managed_, [](const auto& left, const auto& right) { return left.first->getName() < right.first->getName(); });
        for (auto&& [func, info] : Managed_) {
            ManagedByFunction_[func] = info.get();
        }
        LayOutArguments();

        bpf::stats() << "stackify: " << Managed_.size() << " managed functions\n";
    }

    // Compiler/runtime critical operations use one ordinary BPF subprogram
    // call as their atomicity boundary. Flatten the complete C call tree into
    // that one function, then prove that no possible continuation edge is
    // left: scalar ABI, direct calls only, fixed stack, and statically bounded
    // loops. A miss on the external map lease returns to managed code before
    // any shared allocator mutation, so only that retry loop may suspend.
    void PrepareNoSuspendFunctions() {
        SmallVector<Function*> roots;
        SmallPtrSet<Function*, 32> flattened;
        for (Function& function : Module_) {
            if (!function.isDeclaration() && function.getName().starts_with("__bpf_capsule_nosuspend_")) {
                roots.push_back(&function);
            }
        }

        for (Function* root : roots) {
            for (;;) {
                CallBase* site = nullptr;
                for (Instruction& instruction : instructions(*root)) {
                    auto* call = dyn_cast<CallBase>(&instruction);
                    if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                        continue;
                    }
                    Function* callee = call->getCalledFunction();
                    if (!callee) {
                        if (!isa<Constant>(call->getCalledOperand())) {
                            report_fatal_error(Twine("stackify: nosuspend function ") + root->getName() + " has an indirect call");
                        }
                        continue; // numbered BPF helper
                    }
                    if (callee->isDeclaration()) {
                        // The memory layout is not known until after stackify.
                        // These reserved calls are lowered by that later pass
                        // and cannot suspend or transfer verifier pointers.
                        if (IsLateMemoryIntrinsic(*callee)) {
                            continue;
                        }
                        report_fatal_error(Twine("stackify: nosuspend function ") + root->getName() + " calls unresolved " + callee->getName());
                    }
                    if (callee == root) {
                        report_fatal_error(Twine("stackify: nosuspend function ") + root->getName() + " is recursive");
                    }
                    flattened.insert(callee);
                    site = call;
                    break;
                }
                if (!site) {
                    break;
                }
                InlineFunctionInfo info;
                if (!InlineFunction(*site, info).isSuccess()) {
                    report_fatal_error(Twine("stackify: cannot flatten nosuspend call in ") + root->getName());
                }
            }

            if (!HasScalarBpfAbi(*root) || !HasOnlyDirectCallUses(*root) || !FitsNativeScalarBody(*root)) {
                report_fatal_error(
                    Twine(
                        "stackify: nosuspend function is not a bounded "
                        "scalar BPF operation: "
                    ) +
                    root->getName()
                );
            }
            root->setLinkage(GlobalValue::ExternalLinkage);
            root->removeFnAttr(Attribute::AlwaysInline);
            root->addFnAttr(Attribute::NoInline);
            root->setMetadata("bpf.native.scalar", MDNode::get(Ctx_, {}));
            for (Instruction& instruction : instructions(*root)) {
                if (auto* alloca = dyn_cast<AllocaInst>(&instruction)) {
                    alloca->setMetadata("bpf.native.alloca", MDNode::get(Ctx_, {}));
                }
            }
        }

        // InlineFunction leaves the original callee in the module. Public
        // library APIs (TLSF is the important case) also retain external
        // linkage after the whole-program link, so ordinary GlobalDCE cannot
        // remove those now-dead copies. If they survive, RewriteEntryPrograms
        // correctly diagnoses them as native functions calling managed
        // helpers even though no entry can reach them. Retire only functions
        // that were actually flattened and have no remaining use; repeat so
        // deleting an outer TLSF API exposes its private helper tree as dead.
        bool removed;
        do {
            removed = false;
            SmallVector<Function*> dead;
            for (Function* function : flattened) {
                if (!function->getParent() || !function->use_empty() || llvm::is_contained(roots, function) || IsEntryProgram(*function)) {
                    continue;
                }
                dead.push_back(function);
            }
            for (Function* function : dead) {
                flattened.erase(function);
                function->eraseFromParent();
                removed = true;
            }
        } while (removed);

        if (!roots.empty()) {
            bpf::stats() << "stackify: proved " << roots.size() << " non-suspendable runtime operations\n";
        }
    }

    // Fold small non-recursive helpers into their callers: a trampoline round
    // trip per call is expensive, and each surviving function costs a slot in
    // the kernel's 256-subprogram budget.
    void InlineSmallFunctions() {
        CallGraph cg(Module_);

        SmallVector<Function*> order;
        for (auto it = scc_begin(&cg); !it.isAtEnd(); ++it) {
            const std::vector<CallGraphNode*>& scc = *it;
            if (scc.size() > 1) {
                continue; // recursive: inlining would not terminate
            }
            Function* func = scc[0]->getFunction();
            if (!func || !IsStackifiable(*func)) {
                continue;
            }
            bool selfRecursive = false;
            for (auto&& edge : *scc[0]) {
                selfRecursive |= edge.second->getFunction() == func;
            }
            if (!selfRecursive) {
                order.push_back(func);
            }
        }

        unsigned inlined = 0;
        for (auto* func : order) {
            if (func->getInstructionCount() > bpf::MaxInlinedInstructions()) {
                continue;
            }
            SmallVector<CallBase*> sites;
            bool addressTaken = false;
            bool intoEntry = false;
            for (auto&& use : func->uses()) {
                auto* call = dyn_cast<CallBase>(use.getUser());
                if (call && call->isCallee(&use)) {
                    // Entry programs are not stackified, so anything folded
                    // into one keeps verifier-hostile loops outside the
                    // managed driver.
                    intoEntry |= IsEntryProgram(*call->getFunction()) || call->getOperandBundle("bpf.capsule.call").has_value();
                    sites.push_back(call);
                } else {
                    addressTaken = true;
                }
            }
            if (addressTaken || intoEntry) {
                continue; // the id-dispatch tables still need it
            }
            // Automatic inlining must not duplicate source IR: doing this at
            // every call site made QuickJS 48% larger and pushed a previously
            // valid arena program over the verifier limit. A single-use
            // helper is a pure move into its caller, so it removes a managed
            // call/return and one function without spending graph budget.
            if (sites.empty()) {
                if (func->use_empty()) {
                    func->eraseFromParent();
                    inlined++;
                }
                continue;
            }
            if (sites.size() != 1) {
                continue;
            }
            if (bpf::HasCpuV4() && sites.front()->getFunction()->getInstructionCount() + func->getInstructionCount() > InlineResultInstructionLimit) {
                continue;
            }
            for (auto* call : sites) {
                InlineFunctionInfo ifi;
                if (!InlineFunction(*call, ifi).isSuccess()) {
                    report_fatal_error(Twine("stackify: cannot inline ") + func->getName());
                }
            }
            if (func->use_empty()) {
                func->eraseFromParent();
                inlined++;
            }
        }
        bpf::stats() << "stackify: inlined away " << inlined << " small functions\n";
    }

    void CheckSignature(Function& func) {
        if (func.isVarArg()) {
            func.getContext().emitError(Twine("stackify: variadic function survived ABI expansion: ") + func.getName());
            InputError_ = true;
            return;
        }
        // An sret destination is an ordinary pointer into the caller's frame.
        // The caller remains live while a managed callee runs, and both frames
        // use unified memory, so preserving that pointer has the same semantics
        // as any other pointer argument. ByVal and InAlloca still require ABI
        // copies which StoreCallArguments does not implement.
        for (auto&& attr : {Attribute::ByVal, Attribute::InAlloca}) {
            for (unsigned i = 0; i < func.arg_size(); i++) {
                if (func.getArg(i)->hasAttribute(attr)) {
                    func.getContext().emitError(Twine("stackify: byval/inalloca argument is unsupported in ") + func.getName());
                    InputError_ = true;
                    return;
                }
            }
        }
    }

    // Arguments and return values live in the frame with their natural LLVM
    // types, so aggregates passed by value need no special handling. Argument
    // slots retain one module-wide stride so an indirect call needs only its
    // statically known function type; unlike the former uniform frames, each
    // function reserves only the number of slots it actually accepts.
    void LayOutArguments() {
        const DataLayout& dl = Module_.getDataLayout();

        uint64_t slot = 8;
        uint64_t slotAlignment = 8;
        for (auto&& [func, info] : Managed_) {
            for (auto&& arg : func->args()) {
                slot = std::max(slot, dl.getTypeAllocSize(arg.getType()).getFixedValue());
                slotAlignment = std::max(slotAlignment, dl.getABITypeAlign(arg.getType()).value());
            }
            Type* ret = func->getReturnType();
            if (!ret->isVoidTy()) {
                info->ReturnSize = dl.getTypeAllocSize(ret).getFixedValue();
            }
        }
        ArgSlotSize_ = (slot + slotAlignment - 1) & ~(slotAlignment - 1);
        // Only the continuation PC is live in a running frame. On return the
        // entire callee is dead, so its result reuses that space — placed at
        // the upper end of the frame (the top `returnSize` bytes; see
        // FrameResultPtr), which is also the caller's frame base.
        ArgsOffset_ = (FixedFrameHeaderSize + slotAlignment - 1) & ~(slotAlignment - 1);

        for (auto&& [func, info] : Managed_) {
            for (unsigned i = 0; i < func->arg_size(); i++) {
                info->ArgOffsets.push_back(ArgsOffset_ + i * ArgSlotSize_);
            }
            info->LocalsOffset = ArgsOffset_ + func->arg_size() * ArgSlotSize_;
        }
    }

    // Indirect calls are managed too: the callee value already carries the
    // function's integer id, so the trampoline can dispatch on it directly.
    bool IsManagedCall(CallBase* call) const {
        if (call->isInlineAsm() || isa<IntrinsicInst>(call)) {
            return false;
        }
        Function* callee = call->getCalledFunction();
        if (!callee) {
            // A constant callee that is not a function is a BPF helper, called
            // by number; only a computed callee is a real indirect call.
            return !isa<Constant>(call->getCalledOperand());
        }
        return ManagedByFunction_.contains(callee);
    }

    bool IsYieldCall(CallBase* call) const {
        return YieldMarker_ && call->getCalledOperand()->stripPointerCasts() == YieldMarker_;
    }

    void ValidateYieldCalls() {
        YieldMarker_ = Module_.getFunction("__bpf_capsule_yield");
        if (!YieldMarker_) {
            return;
        }
        if (!YieldMarker_->isDeclaration() || !YieldMarker_->getReturnType()->isVoidTy() || YieldMarker_->arg_size() != 0) {
            report_fatal_error("stackify: __bpf_capsule_yield is a reserved zero-argument compiler marker");
        }
        if (YieldMarker_->use_empty()) {
            YieldMarker_->eraseFromParent();
            YieldMarker_ = nullptr;
            return;
        }
        for (User* user : YieldMarker_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledOperand()->stripPointerCasts() != YieldMarker_) {
                report_fatal_error("stackify: address of __bpf_capsule_yield escapes");
            }
            if (!ManagedByFunction_.contains(call->getFunction())) {
                call->getFunction()->getContext().emitError(
                    Twine("stackify: capsule_yield may only be called from Capsule code, not ") + call->getFunction()->getName()
                );
                YieldError_ = true;
                return;
            }
        }
    }

    SmallVector<CallBase*> SuspensionCalls(Function& func) const {
        SmallVector<CallBase*> calls;
        for (auto&& inst : instructions(func)) {
            if (auto* call = dyn_cast<CallBase>(&inst); call && (IsManagedCall(call) || IsYieldCall(call))) {
                calls.push_back(call);
            }
        }
        return calls;
    }

    // ---------------------------------------------------------------- groups

    // Each logical function is first transformed in a private staging
    // function.  That keeps temporary SSA simple; the staging functions never
    // reach code generation and therefore do not consume the kernel's global
    // subprogram budget.
    void CreateStages() {
        auto createStage = [&](ManagedFunction* info) {
            info->EntryPc = NextPc_++;
            info->Stage = Function::Create(FunctionType::get(I32_, false), GlobalValue::InternalLinkage, "bpf.stage." + Twine(info->EntryPc), Module_);
            info->Stage->setMetadata("bpf.capsule", MDNode::get(Ctx_, {}));
            if (DumpIds) {
                errs() << "stackify-function " << info->EntryPc << " " << info->Original->getName() << " frame=" << info->FrameSize << "\n";
            }
        };

        // A contiguous PC interval lets an equal-frame tail site validate its
        // computed callee without loading the frame-size table.
        TailClassFirst_.assign(TailClassCount_ + 1, 0);
        TailClassMembers_.assign(TailClassCount_ + 1, 0);
        for (uint32_t tailClass = 1; tailClass <= TailClassCount_; tailClass++) {
            TailClassFirst_[tailClass] = NextPc_;
            for (auto&& [function, info] : Managed_) {
                if (info->TailClass == tailClass) {
                    createStage(info.get());
                    TailClassMembers_[tailClass]++;
                }
            }
        }
        for (auto&& [function, info] : Managed_) {
            if (!info->TailClass) {
                createStage(info.get());
            }
        }
    }

    // A computed function value is its entry PC.  Keep the corresponding
    // exact frame size in data rather than spelling the lookup as one select
    // per managed function: the latter makes verifier work proportional to
    // the whole source program at every indirect call site.  Entry PCs are
    // assigned contiguously before resume PCs, so this table is compact. Keep
    // it in a separately named data section: the BPF backend may emit one ELF
    // section per global despite identical section attributes, and duplicate
    // names then make libbpf generate duplicate skeleton members.
    void CreateFrameSizeTable() {
        SmallVector<uint32_t> sizes(NextPc_, 0);
        for (auto&& [function, info] : Managed_) {
            if (info->FrameSize > UINT32_MAX) {
                report_fatal_error("stackify: frame size exceeds table ABI");
            }
            sizes[info->EntryPc] = uint32_t(info->FrameSize);
        }

        auto* tableType = ArrayType::get(I32_, sizes.size());
        FrameSizeTable_ = new GlobalVariable(Module_, tableType, true, GlobalValue::ExternalLinkage, ConstantDataArray::get(Ctx_, sizes), "bpf_frame_size");
        FrameSizeTable_->setSection(".rodata.bpffs");
        FrameSizeTable_->setAlignment(Align(4));
        FrameSizeTable_->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    }

    void CreatePhysicalGroups(unsigned scalarGroups, unsigned borrowedGroups) {
        unsigned groupCount = scalarGroups + borrowedGroups;
        Groups_.resize(groupCount);
        for (auto&& [idx, group] : enumerate(Groups_)) {
            group.BorrowedContext = idx >= scalarGroups;
            // External linkage plus BTF makes these global subprograms: the
            // verifier checks each once, standalone, instead of walking into
            // them from the trampoline at every dispatch.
            SmallVector<Type*> parameters;
            if (group.BorrowedContext) {
                parameters.push_back(PointerType::get(Ctx_, 0));
            }
            parameters.push_back(I32_);
            parameters.push_back(PointerType::get(Ctx_, 0));
            if (!bpf::UseArena()) {
                parameters.push_back(PointerType::get(Ctx_, 0));
            }
            group.Func = Function::Create(FunctionType::get(I32_, parameters, false), Function::ExternalLinkage, "bpf_step." + Twine(idx), Module_);
            group.Func->setCallingConv(CallingConv::C);
            group.Func->addFnAttr(Attribute::NoInline);
            group.Func->setMetadata("bpf.capsule", MDNode::get(Ctx_, {}));
            group.Func->setMetadata("bpf.capsule.physical", MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I32_, group.BorrowedContext ? 1 : 0))));
            group.Func->setMetadata("bpf.capsule.stack.size", MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I64_, FiberStackSize_))));

            if (!Module_.debug_compile_units().empty()) {
                DIBuilder db(Module_, false, *Module_.debug_compile_units_begin());
                auto* cu = *Module_.debug_compile_units_begin();
                SmallVector<Metadata*> signature{BtfGetInt(db, 32, true)};
                if (group.BorrowedContext) {
                    signature.push_back(BorrowedDebugType_);
                }
                signature.push_back(BtfGetInt(db, 32, false));
                auto* controlByteType = db.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
                uint64_t controlBytes = Module_.getDataLayout().getTypeAllocSize(FiberControlType_);
                auto* controlSubrange = db.getOrCreateSubrange(0, controlBytes);
                auto* controlType = db.createArrayType(controlBytes * 8u, 8, controlByteType, db.getOrCreateArray({controlSubrange}));
                DIType* controlDebugType = db.createPointerType(controlType, 64);
                signature.push_back(controlDebugType);
                DIType* backingDebugType = nullptr;
                if (!bpf::UseArena()) {
                    auto* byteType = db.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
                    auto* subrange = db.getOrCreateSubrange(0, FiberStackSize_);
                    auto* regionType = db.createArrayType(uint64_t(FiberStackSize_) * 8u, 8, byteType, db.getOrCreateArray({subrange}));
                    backingDebugType = db.createPointerType(regionType, 64);
                    signature.push_back(backingDebugType);
                }
                auto* type = db.createSubroutineType(db.getOrCreateTypeArray(signature));
                group.Subprogram = db.createFunction(
                    cu, group.Func->getName(), group.Func->getName(), cu->getFile(), 0, type, 0, DINode::FlagArtificial, DISubprogram::SPFlagDefinition
                );
                group.Func->setSubprogram(group.Subprogram);
                if (group.BorrowedContext) {
                    db.createParameterVariable(group.Subprogram, "ctx", 1, cu->getFile(), 0, cast<DIType>(BorrowedDebugType_), true);
                }
                db.createParameterVariable(group.Subprogram, "fiber", group.BorrowedContext ? 2 : 1, cu->getFile(), 0, BtfGetInt(db, 32, false), true);
                db.createParameterVariable(group.Subprogram, "fiber_control", group.BorrowedContext ? 3 : 2, cu->getFile(), 0, controlDebugType, true);
                if (backingDebugType) {
                    db.createParameterVariable(group.Subprogram, "stack_base", group.BorrowedContext ? 4 : 3, cu->getFile(), 0, backingDebugType, true);
                }
                db.finalize();
            }

            auto* entry = BasicBlock::Create(Ctx_, "group.entry", group.Func);
            group.Dispatch = entry;
            IRBuilder<> b(entry);
            if (group.BorrowedContext) {
                group.Func->getArg(0)->setName("ctx");
                // MemoryPass runs after Stackify. Preserve the fact that this
                // argument is a verifier-owned pointer after the original
                // Capsule root has been dissolved into physical groups; raw
                // ctx and packet accesses must not be rewritten as arena
                // accesses.
                group.Func->addParamAttr(0, Attribute::get(Ctx_, "bpf.capsule.borrowed"));
            }
            group.Func->getArg(FiberArgumentIndex(group.BorrowedContext))->setName("fiber");
            Value* fiberControl = group.Func->getArg(ControlArgumentIndex(group.BorrowedContext));
            fiberControl->setName("fiber_control");
            group.Func->addParamAttr(ControlArgumentIndex(group.BorrowedContext), Attribute::get(Ctx_, "bpf.capsule.control"));
            NativeFiberControls_[group.Func] = fiberControl;
            auto* controlReady = BasicBlock::Create(Ctx_, "group.control.ready", group.Func);
            auto* controlMissing = BasicBlock::Create(Ctx_, "group.control.missing", group.Func);
            b.CreateCondBr(b.CreateICmpNE(fiberControl, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), controlReady, controlMissing);
            IRBuilder<> cmb(controlMissing);
            cmb.CreateRet(ConstantInt::get(I32_, ActionContinue));
            b.SetInsertPoint(controlReady);
            group.Dispatch = controlReady;
            if (!bpf::UseArena()) {
                group.Func->getArg(StackRegionArgumentIndex(group.BorrowedContext))->setName("stack_base");
                group.Func->addParamAttr(StackRegionArgumentIndex(group.BorrowedContext), Attribute::get(Ctx_, "bpf.capsule.stack.backing"));
                group.Dispatch = BasicBlock::Create(Ctx_, "group.dispatch", group.Func);
                auto* missing = BasicBlock::Create(Ctx_, "group.stack.missing", group.Func);
                b.CreateCondBr(
                    b.CreateICmpNE(group.Func->getArg(StackRegionArgumentIndex(group.BorrowedContext)), ConstantPointerNull::get(PointerType::get(Ctx_, 0))),
                    group.Dispatch, missing
                );
                IRBuilder<> mb(missing);
                EmitAbort(mb, CAPSULE_ERROR_MEMORY_FAULT, group.Func->getArg(FiberArgumentIndex(group.BorrowedContext)));
                mb.CreateRet(ConstantInt::get(I32_, ActionContinue));
                b.SetInsertPoint(group.Dispatch);
            }
            LoadTopFrame(b, group.Func->getArg(FiberArgumentIndex(group.BorrowedContext)), group.Sp, group.Frame);

            // Keep the three values needed by the post-RA spill mover visible
            // at one dominance point without emitting an instruction. The
            // fixed tier threads the outer drive's ephemeral map-value pointer
            // here; arena uses its native flat stack pointer. Source-visible
            // addresses remain logical values in either case. If this group
            // has no relocated spills the marker assembles to nothing.
            Value* stackBase = nullptr;
            if (bpf::UseArena()) {
                stackBase = StackPtr(b, ConstantInt::get(I64_, 0), group.Func->getArg(FiberArgumentIndex(group.BorrowedContext)));
            } else {
                stackBase = group.Func->getArg(StackRegionArgumentIndex(group.BorrowedContext));
            }
            Value* abort = ExitWordPtr(b, group.Func->getArg(FiberArgumentIndex(group.BorrowedContext)));
            auto* anchor = InlineAsm::get(
                FunctionType::get(Type::getVoidTy(Ctx_), {stackBase->getType(), I64_, abort->getType()}, false), "# bpf_capsule_stack_anchor", "r,r,r",
                /*hasSideEffects=*/true
            );
            b.CreateCall(anchor, {stackBase, group.Sp, abort});
        }
    }

    unsigned FiberArgumentIndex(bool borrowed) const {
        return borrowed ? 1 : 0;
    }

    unsigned StackRegionArgumentIndex(bool borrowed) const {
        return FiberArgumentIndex(borrowed) + 2;
    }

    unsigned ControlArgumentIndex(bool borrowed) const {
        return FiberArgumentIndex(borrowed) + 1;
    }

    bool FunctionBorrowsContext(const Function* function) const {
        return function && function->arg_size() && function->getArg(0)->hasAttribute("bpf.capsule.borrowed");
    }

    void ReplaceFiberUses() {
        SmallPtrSet<Function*, 32> groupFunctions;
        for (StepGroup& group : Groups_) {
            groupFunctions.insert(group.Func);
        }

        auto fiberFor = [&](CallBase* call) -> Argument* {
            Function* owner = call->getFunction();
            if (!groupFunctions.contains(owner)) {
                report_fatal_error("stackify: fiber accessor escaped its physical step group");
            }
            return owner->getArg(FiberArgumentIndex(FunctionBorrowsContext(owner)));
        };

        SmallVector<CallBase*> currentCalls;
        for (User* user : CurrentFiber_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != CurrentFiber_) {
                report_fatal_error("stackify: current-fiber accessor has a non-call use");
            }
            currentCalls.push_back(call);
        }
        for (CallBase* call : currentCalls) {
            call->replaceAllUsesWith(fiberFor(call));
            call->eraseFromParent();
        }

        SmallVector<CallBase*> countCalls;
        for (User* user : ActiveFiberCount_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != ActiveFiberCount_) {
                report_fatal_error("stackify: active-fiber-count accessor has a non-call use");
            }
            (void)fiberFor(call);
            countCalls.push_back(call);
        }
        for (CallBase* call : countCalls) {
            IRBuilder<> b(call);
            Value* slot = b.CreateStructGEP(FiberConfigType_, FiberConfig_, BPF_CAPSULE_OBJECT_CONFIG_FIBER_COUNT, "fiber.count.slot");
            auto* count = b.CreateLoad(I32_, slot, "fiber.count");
            count->setVolatile(true);
            Value* valid = b.CreateAnd(
                b.CreateICmpUGE(count, ConstantInt::get(I32_, 1)), b.CreateICmpULE(count, ConstantInt::get(I32_, FiberCount_)), "fiber.count.valid"
            );
            call->replaceAllUsesWith(b.CreateSelect(valid, count, ConstantInt::get(I32_, 0), "fiber.count.bounded"));
            call->eraseFromParent();
        }

        SmallVector<CallBase*> abortCalls;
        for (User* user : ExitWordAccessor_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != ExitWordAccessor_) {
                report_fatal_error("stackify: exit-word accessor has a non-call use");
            }
            abortCalls.push_back(call);
        }
        for (CallBase* call : abortCalls) {
            IRBuilder<> b(call);
            Value* fiber = fiberFor(call);
            Value* abort = ExitWordPtr(b, fiber);
            SmallVector<User*> users(call->user_begin(), call->user_end());
            for (User* user : users) {
                if (auto* load = dyn_cast<LoadInst>(user)) {
                    load->setOperand(load->getPointerOperandIndex(), abort);
                    load->setVolatile(true);
                    continue;
                }
                if (auto* store = dyn_cast<StoreInst>(user); store && store->getPointerOperand() == call) {
                    IRBuilder<> sb(store);
                    Value* code = store->getValueOperand();
                    if (code->getType() != I64_) {
                        code = sb.CreateZExtOrTrunc(code, I64_);
                    }
                    sb.CreateCall(GetExitSetter(), {fiber, code});
                    store->eraseFromParent();
                    continue;
                }
                user->replaceUsesOfWith(call, abort);
            }
            call->eraseFromParent();
        }

        SmallVector<StoreInst*> generatedStores;
        for (StepGroup& group : Groups_) {
            for (Instruction& inst : instructions(*group.Func)) {
                auto* store = dyn_cast<StoreInst>(&inst);
                if (store && store->getMetadata("bpf.capsule.exit.store")) {
                    generatedStores.push_back(store);
                }
            }
        }
        for (StoreInst* store : generatedStores) {
            Function* owner = store->getFunction();
            IRBuilder<> b(store);
            Value* code = store->getValueOperand();
            if (code->getType() != I64_) {
                code = b.CreateZExtOrTrunc(code, I64_);
            }
            b.CreateCall(GetExitSetter(), {owner->getArg(FiberArgumentIndex(FunctionBorrowsContext(owner))), code});
            store->eraseFromParent();
        }

        if (!CurrentFiber_->use_empty() || !ActiveFiberCount_->use_empty() || !ExitWordAccessor_->use_empty()) {
            report_fatal_error("stackify: Capsule fiber accessors still have uses");
        }
        CurrentFiber_->eraseFromParent();
        ActiveFiberCount_->eraseFromParent();
        ExitWordAccessor_->eraseFromParent();
        CurrentFiber_ = nullptr;
        ActiveFiberCount_ = nullptr;
        ExitWordAccessor_ = nullptr;
    }

    // Replace the temporary zero-argument accessor after transformed regions
    // have reached their final physical group. Every use then becomes the
    // group's exact typed argument, preserving verifier provenance without
    // putting the pointer in persistent Capsule state.
    void ReplaceBorrowedContextUses() {
        if (!BorrowedContext_) {
            return;
        }
        SmallPtrSet<Function*, 32> groupFunctions;
        for (StepGroup& group : Groups_) {
            groupFunctions.insert(group.Func);
        }
        SmallVector<CallBase*> calls;
        for (User* user : BorrowedCurrent_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != BorrowedCurrent_) {
                report_fatal_error("stackify: borrowed context accessor has a non-call use");
            }
            if (!groupFunctions.contains(call->getFunction())) {
                report_fatal_error("stackify: borrowed context escaped its physical step group");
            }
            calls.push_back(call);
        }
        for (CallBase* call : calls) {
            if (!FunctionBorrowsContext(call->getFunction())) {
                report_fatal_error("stackify: borrowed context use was assigned to a scalar physical group");
            }
            call->replaceAllUsesWith(call->getFunction()->getArg(0));
            call->eraseFromParent();
        }
        if (!BorrowedCurrent_->use_empty()) {
            report_fatal_error("stackify: borrowed context accessor still has uses");
        }
        BorrowedCurrent_->eraseFromParent();
        BorrowedCurrent_ = nullptr;
    }

    // Cut transformed staging CFGs at their suspension returns, then balance
    // the resulting connected regions across the available physical BPF
    // subprograms.  This is the key distinction from function grouping: one
    // source function with thousands of continuations no longer becomes one
    // enormous backend function and one enormous local dispatcher.
    void FormRegionsAndCreateStepGroups() {
        DenseMap<BasicBlock*, Region*> byBlock;

        for (auto&& [func, infoPtr] : Managed_) {
            ManagedFunction& info = *infoPtr;
            SmallPtrSet<BasicBlock*, 32> unvisited;
            for (auto&& block : *info.Stage) {
                if (&block != info.Entry) {
                    unvisited.insert(&block);
                }
            }

            while (!unvisited.empty()) {
                auto region = std::make_unique<Region>();
                region->Owner = &info;
                Region* raw = region.get();
                SmallVector<BasicBlock*> worklist;
                BasicBlock* seed = nullptr;
                for (BasicBlock& block : *info.Stage) {
                    if (unvisited.contains(&block)) {
                        seed = &block;
                        break;
                    }
                }
                if (!seed) {
                    report_fatal_error("stackify: region worklist lost an unvisited block");
                }
                worklist.push_back(seed);
                unvisited.erase(worklist.back());

                while (!worklist.empty()) {
                    BasicBlock* block = worklist.pop_back_val();
                    raw->Blocks.push_back(block);
                    raw->Size += block->size();
                    byBlock[block] = raw;
                    if (BorrowedCurrent_) {
                        for (Instruction& instruction : *block) {
                            auto* call = dyn_cast<CallBase>(&instruction);
                            raw->BorrowedContext |= call && call->getCalledFunction() == BorrowedCurrent_;
                        }
                    }

                    auto visit = [&](BasicBlock* adjacent) {
                        if (adjacent != info.Entry && unvisited.erase(adjacent)) {
                            worklist.push_back(adjacent);
                        }
                    };
                    for (auto* succ : successors(block)) {
                        visit(succ);
                    }
                    for (auto* pred : predecessors(block)) {
                        visit(pred);
                    }
                }
                Regions_.push_back(std::move(region));
            }

            for (auto state : info.States) {
                Region* region = byBlock.lookup(state.Root);
                if (!region) {
                    report_fatal_error(Twine("stackify: state without region in ") + func->getName());
                }
                region->States.push_back(state);
            }
        }

        if (Regions_.empty()) {
            report_fatal_error("stackify: no continuation regions");
        }

        // A register definition may not cross a suspension: after regions
        // move it would become illegal cross-function SSA.  Demotion is meant
        // to guarantee this; diagnose the exact producer if that invariant is
        // ever broken instead of letting LLVM fail much later.
        for (auto&& regionPtr : Regions_) {
            Region& region = *regionPtr;
            for (auto* block : region.Blocks) {
                for (auto&& inst : *block) {
                    for (Value* operand : inst.operands()) {
                        auto* def = dyn_cast<Instruction>(operand);
                        if (!def || def->getParent() == region.Owner->Entry) {
                            continue;
                        }
                        // A native helper alloca is an addressable BPF-stack
                        // object, not state carried between regions. Its
                        // lifetime analysis already proved the contents do
                        // not cross a suspension; after packing, relocate the
                        // allocation itself into the one physical function
                        // containing its uses.
                        if (NativeHelperAllocas_.contains(dyn_cast<AllocaInst>(def))) {
                            continue;
                        }
                        if (Region* owner = byBlock.lookup(def->getParent()); owner && owner != &region) {
                            errs() << "stackify: cross-region definition: ";
                            def->print(errs());
                            errs() << "\nstackify: cross-region use: ";
                            inst.print(errs());
                            errs() << "\nstackify: from block " << def->getParent()->getName() << " to " << block->getName() << "\n";
                            report_fatal_error(Twine("stackify: value crosses regions in ") + region.Owner->Original->getName() + ": " + def->getName());
                        }
                    }
                }
            }
        }

        unsigned statefulRegions = llvm::count_if(Regions_, [](const std::unique_ptr<Region>& region) { return !region->States.empty(); });
        if (!statefulRegions) {
            report_fatal_error("stackify: no dispatchable continuation regions");
        }
        unsigned groupCount = std::min<unsigned>(bpf::MaxStepGroups(), statefulRegions);

        SmallVector<Region*> scalarStateful;
        SmallVector<Region*> scalarStateless;
        SmallVector<Region*> borrowedStateful;
        SmallVector<Region*> borrowedStateless;
        for (auto&& region : Regions_) {
            auto& list = region->BorrowedContext ? (region->States.empty() ? borrowedStateless : borrowedStateful)
                                                 : (region->States.empty() ? scalarStateless : scalarStateful);
            list.push_back(region.get());
        }
        auto largestFirst = [](const Region* a, const Region* b) { return a->Size > b->Size; };
        for (auto* list : {&scalarStateful, &scalarStateless, &borrowedStateful, &borrowedStateless}) {
            llvm::stable_sort(*list, largestFirst);
        }

        unsigned borrowedGroupCount = 0;
        if (!borrowedStateless.empty() && borrowedStateful.empty()) {
            report_fatal_error("stackify: borrowed-context code has no dispatchable continuation region");
        }
        if (!borrowedStateful.empty()) {
            borrowedGroupCount = std::max<unsigned>(1, groupCount * borrowedStateful.size() / statefulRegions);
            borrowedGroupCount = std::min<unsigned>(borrowedGroupCount, borrowedStateful.size());
        }
        unsigned scalarGroupCount = groupCount - borrowedGroupCount;
        if (!scalarStateful.empty() && !scalarGroupCount) {
            scalarGroupCount = 1;
            --borrowedGroupCount;
        }
        if (scalarGroupCount > scalarStateful.size()) {
            unsigned excess = scalarGroupCount - scalarStateful.size();
            scalarGroupCount -= excess;
            borrowedGroupCount += excess;
        }
        CreatePhysicalGroups(scalarGroupCount, borrowedGroupCount);

        SmallVector<uint64_t> load(groupCount, 0);
        auto place = [&](Region* region, unsigned best) {
            region->Group = best;
            load[best] += region->Size;
            Groups_[best].States.append(region->States);
        };

        auto placeClass = [&](ArrayRef<Region*> stateful, ArrayRef<Region*> stateless, unsigned first, unsigned count) {
            for (unsigned group = 0; group < count; ++group) {
                place(stateful[group], first + group);
            }
            SmallVector<Region*> remaining;
            remaining.append(stateful.begin() + count, stateful.end());
            remaining.append(stateless.begin(), stateless.end());
            llvm::stable_sort(remaining, largestFirst);
            for (Region* region : remaining) {
                unsigned best = first;
                for (unsigned group = first + 1; group < first + count; ++group) {
                    if (load[group] < load[best]) {
                        best = group;
                    }
                }
                place(region, best);
            }
        };
        if (scalarGroupCount) {
            placeClass(scalarStateful, scalarStateless, 0, scalarGroupCount);
        }
        if (borrowedGroupCount) {
            placeClass(borrowedStateful, borrowedStateless, scalarGroupCount, borrowedGroupCount);
        }

        // The logical PC space is intentionally stable and sparse with
        // respect to physical packing.  Reconstructing the group by switching
        // over every PC creates thousands of cases in the hottest driver and
        // dominates verifier/JIT load time.  A byte table is smaller than that
        // code and turns outer routing into one bounded load plus a switch over
        // at most 180 physical groups.  The group itself still validates the
        // exact PC before entering a region.
        SmallVector<uint8_t> pcGroups(NextPc_, 0);
        for (auto&& region : Regions_) {
            for (auto state : region->States) {
                pcGroups[state.Pc] = uint8_t(region->Group);
                if (DumpIds) {
                    errs() << "stackify-state " << state.Pc << " " << region->Owner->Original->getName() << ":" << state.Root->getName()
                           << " group=" << region->Group << "\n";
                }
            }
        }
        auto* pcGroupType = ArrayType::get(I8_, pcGroups.size());
        PcGroupTable_ = new GlobalVariable(Module_, pcGroupType, true, GlobalValue::ExternalLinkage, ConstantDataArray::get(Ctx_, pcGroups), "bpf_pc_group");
        PcGroupTable_->setSection(".rodata.bpfpc");
        PcGroupTable_->setAlignment(Align(1));
        PcGroupTable_->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

        // Move complete regions, replace the staging frame base with the one
        // computed by their physical group, then discard the staging owners.
        for (auto&& regionPtr : Regions_) {
            Region& region = *regionPtr;
            Function* destination = Groups_[region.Group].Func;
            for (BasicBlock* block : region.Blocks) {
                destination->splice(destination->end(), region.Owner->Stage, block->getIterator());
            }
        }
        // A helper-visible source alloca has now reached the one physical
        // group containing its complete non-suspendable lifetime. Move its
        // allocation instruction to that BPF function's entry block, as the
        // backend requires, while lifetime markers remain around the actual
        // region uses so stack coloring can reuse the native slot.
        for (AllocaInst* alloca : NativeHelperAllocaOrder_) {
            Function* owner = nullptr;
            for (User* user : alloca->users()) {
                auto* instruction = dyn_cast<Instruction>(user);
                if (!instruction) {
                    continue;
                }
                Function* useOwner = instruction->getFunction();
                if (llvm::none_of(Groups_, [&](const StepGroup& group) { return group.Func == useOwner; })) {
                    report_fatal_error("stackify: helper-visible alloca use did not reach a physical step group");
                }
                if (owner && useOwner != owner) {
                    report_fatal_error("stackify: helper-visible alloca crosses physical step groups");
                }
                owner = useOwner;
            }
            if (!owner) {
                report_fatal_error("stackify: helper-visible alloca has no physical uses");
            }
            alloca->moveBefore(owner->getEntryBlock(), owner->getEntryBlock().getFirstInsertionPt());
        }
        for (auto&& [func, infoPtr] : Managed_) {
            ManagedFunction& info = *infoPtr;
            auto replaceUses = [&](Value* value, auto groupValue, StringRef what) {
                for (Use& use : make_early_inc_range(value->uses())) {
                    auto* user = cast<Instruction>(use.getUser());
                    if (user->getParent() == info.Entry) {
                        continue;
                    }
                    Region* region = byBlock.lookup(user->getParent());
                    if (!region) {
                        report_fatal_error(Twine("stackify: ") + what + " use outside region in " + func->getName());
                    }
                    use.set(groupValue(Groups_[region->Group]));
                }
            };
            replaceUses(info.Sp, [](StepGroup& group) { return group.Sp; }, "SP");
            replaceUses(info.Frame, [](StepGroup& group) { return group.Frame; }, "frame");
            func->setSubprogram(nullptr);
            info.Stage->eraseFromParent();
            info.Stage = nullptr;
            info.Entry = nullptr;
            info.Sp = nullptr;
            info.Frame = nullptr;
        }

        for (auto&& group : Groups_) {
            if (group.Subprogram) {
                RemapDebugLocations(*group.Func, *group.Subprogram);
            }
        }

        uint64_t largest = 0;
        for (uint64_t size : load) {
            largest = std::max(largest, size);
        }
        Region* largestRegion = nullptr;
        for (auto&& region : Regions_) {
            if (!largestRegion || region->Size > largestRegion->Size) {
                largestRegion = region.get();
            }
        }
        bpf::stats() << "stackify: " << Regions_.size() << " regions, " << groupCount << " step subprograms, largest IR load " << largest << ", largest region "
                     << largestRegion->Size << " (" << largestRegion->Owner->Original->getName() << ")\n";
    }

    // Give each physical group a balanced dispatch tree over just the PCs of
    // regions packed into it.  A linear equality chain makes both execution
    // and standalone global-function verification quadratic: every region
    // body inherits all preceding failed comparisons.  Thresholds reduce a
    // typical 42-state group from ~21 tests to six, plus one equality check at
    // the leaf.  The trampoline has already selected the group.
    void FinishStepGroups() {
        for (auto&& group : Groups_) {
            if (group.States.empty()) {
                report_fatal_error("stackify: physical step group has no continuation state");
            }
            BasicBlock* entry = group.Dispatch;
            if (!entry) {
                report_fatal_error("stackify: physical group has no dispatch entry");
            }
            IRBuilder<> b(entry);
            auto* pc = b.CreateLoad(I32_, b.CreateGEP(I8_, group.Frame, {ConstantInt::get(I64_, PcOffset)}), "pc");

            auto* unknown = BasicBlock::Create(Ctx_, "group.unknown", group.Func);
            IRBuilder<> ub(unknown);
            ub.CreateCall(
                GetExitSetter(),
                {group.Func->getArg(FiberArgumentIndex(group.BorrowedContext)), ConstantInt::get(I64_, bpf::ExitWordValue(CAPSULE_ERROR_INVALID_DISPATCH))}
            );
            ub.CreateRet(ConstantInt::get(I32_, ActionContinue));

            llvm::stable_sort(group.States, [](const auto& a, const auto& b) { return a.Pc < b.Pc; });
            struct TestRange {
                BasicBlock* Block;
                unsigned Begin;
                unsigned End;
            };
            SmallVector<TestRange, 32> pending;
            pending.push_back({entry, 0, unsigned(group.States.size())});
            while (!pending.empty()) {
                TestRange range = pending.pop_back_val();
                IRBuilder<> tb(range.Block);
                if (range.End - range.Begin == 1) {
                    auto state = group.States[range.Begin];
                    tb.CreateCondBr(tb.CreateICmpEQ(pc, ConstantInt::get(I32_, state.Pc)), state.Root, unknown);
                    continue;
                }

                unsigned middle = range.Begin + (range.End - range.Begin) / 2;
                auto* left = BasicBlock::Create(Ctx_, "group.test.left", group.Func, unknown);
                auto* right = BasicBlock::Create(Ctx_, "group.test.right", group.Func, unknown);
                tb.CreateCondBr(tb.CreateICmpULT(pc, ConstantInt::get(I32_, group.States[middle].Pc)), left, right);
                pending.push_back({right, middle, range.End});
                pending.push_back({left, range.Begin, middle});
            }

            if (group.Subprogram) {
                for (auto* block : {entry, unknown}) {
                    for (auto&& inst : *block) {
                        inst.setDebugLoc(DILocation::get(Ctx_, 0, 0, group.Subprogram));
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------- demotion

    // Backedges become suspend/resume points, so the function ends up acyclic.
    struct Backedge {
        BasicBlock* Latch = nullptr;
        BasicBlock* Header = nullptr;
        // Zero means suspend on every traversal.  Nonzero means execute this
        // many traversals as a real bounded BPF loop before suspending once.
        unsigned ChunkTrips = 0;
    };

    // Make an LLVM-proven maximum visible to the BPF verifier.  SCEV can use
    // facts (notably `range` metadata) which are valid for optimization but
    // are intentionally erased later because the kernel cannot see them.  A
    // tiny explicit induction guard bridges that gap.  Reaching the guard's
    // failure edge contradicts the IR proof, so abort rather than silently
    // truncating if a compiler bug or memory corruption ever makes it real.
    void GuardNativeLoop(BasicBlock* header, BasicBlock* latch, BasicBlock* preheader, unsigned trips, DenseMap<Function*, BasicBlock*>& bailByFunction) {
        Function* func = header->getParent();
        BasicBlock*& bail = bailByFunction[func];
        DebugLoc debugLoc;
        if (auto* sp = func->getSubprogram()) {
            debugLoc = DILocation::get(Ctx_, 0, 0, sp);
        }
        if (!bail) {
            bail = BasicBlock::Create(Ctx_, "bpf.loop.bound.fail", func);
            IRBuilder<> bb(bail);
            EmitAbort(bb, CAPSULE_ERROR_INTRINSIC_GUARD);
            if (func->getReturnType()->isVoidTy()) {
                bb.CreateRetVoid();
            } else {
                bb.CreateRet(Constant::getNullValue(func->getReturnType()));
            }
            for (Instruction& inst : *bail) {
                inst.setDebugLoc(debugLoc);
            }
        }

        auto* counter = PHINode::Create(I32_, 2, "bpf.loop.iter", header->begin());
        counter->addIncoming(ConstantInt::get(I32_, 0), preheader);
        counter->setDebugLoc(debugLoc);

        // Keep the guard next to the failure block, after the original body.
        // Linux 5.15's separate CFG-layout restriction is handled after final
        // machine block placement, where implicit fallthroughs are knowable.
        auto* guard = BasicBlock::Create(Ctx_, header->getName() + ".bound", func, bail);
        latch->getTerminator()->replaceSuccessorWith(header, guard);
        for (PHINode& phi : header->phis()) {
            if (&phi != counter) {
                phi.replaceIncomingBlockWith(latch, guard);
            }
        }

        IRBuilder<> gb(guard);
        Value* next = gb.CreateAdd(counter, ConstantInt::get(I32_, 1), "bpf.loop.iter.next");
        // The empty tied inline asm emits no BPF instruction.  It only stops
        // the post-stackify LLVM cleanup from proving this check redundant;
        // the kernel still sees the increment and constant comparison.
        auto* barrierType = FunctionType::get(I32_, {I32_}, false);
        auto* barrier = InlineAsm::get(barrierType, "", "=r,0", /*hasSideEffects=*/true);
        Value* visibleNext = gb.CreateCall(barrier, {next}, "bpf.loop.iter.visible");
        gb.CreateCondBr(gb.CreateICmpULT(visibleNext, ConstantInt::get(I32_, trips)), header, bail);
        counter->addIncoming(visibleNext, guard);
        for (Instruction& inst : *guard) {
            inst.setDebugLoc(debugLoc);
        }
    }

    struct ChunkCandidate {
        BasicBlock* Header = nullptr;
        BasicBlock* Latch = nullptr;
        BasicBlock* Preheader = nullptr;
        unsigned Trips = 0;
        unsigned BaseTrips = 0;
        unsigned DesiredTrips = 0;
        uint64_t BaseCost = 0;
        uint64_t DesiredCost = 0;
        uint64_t Hotness = 1;
        bool Canonical = false;
        SmallVector<BasicBlock*, 8> Blocks;
    };

    // Build the bounded native cycle before frame layout.  Loop-carried PHIs
    // remain SSA on the hot edge; only the cold suspension edge serializes
    // their next values.  The temporary boundary->resume edge keeps the CFG
    // analyzable until TransformFunction replaces it by store-PC-and-return.
    void PrepareChunkedLoop(const ChunkCandidate& chunk) {
        Function& func = *chunk.Header->getParent();
        DebugLoc debugLoc;
        if (auto* sp = func.getSubprogram()) {
            debugLoc = DILocation::get(Ctx_, 0, 0, sp);
        }

        // Dispatch may enter at resume without executing definitions above
        // the loop.  Preserve every such live-in in the managed frame.  Values
        // defined in the loop are recomputed; arguments and allocas already
        // acquire frame-relative materializations later.
        LivenessAnalysis liveness(func);
        SmallPtrSet<Value*, 32> verifierNative;
        FindVerifierNativeValues(func, verifierNative);
        SmallPtrSet<Value*, 16> crossing = liveness.liveAcross(chunk.Latch, chunk.Header);
        if (RejectNativeValues(func, verifierNative, crossing, "is live across a suspendable loop chunk")) {
            return;
        }
        SmallPtrSet<BasicBlock*, 16> loopBlocks;
        loopBlocks.insert_range(chunk.Blocks);
        SetVector<Value*> externalLiveIns;
        for (Value* value : ValuesInProgramOrder(func, crossing)) {
            if (isa<Argument>(value) || isa<AllocaInst>(value)) {
                continue;
            }
            auto* inst = dyn_cast<Instruction>(value);
            if (inst && inst->getParent() != chunk.Header && !loopBlocks.contains(inst->getParent())) {
                externalLiveIns.insert(inst);
            }
        }
        if (!externalLiveIns.empty()) {
            DemoteValues(func, externalLiveIns);
        }

        auto* resume = BasicBlock::Create(Ctx_, chunk.Header->getName() + ".chunk.resume", &func);
        auto* guard = BasicBlock::Create(Ctx_, chunk.Latch->getName() + ".chunk.guard", &func);
        auto* keepGoing = BasicBlock::Create(Ctx_, chunk.Latch->getName() + ".chunk.continue", &func);
        auto* boundary = BasicBlock::Create(Ctx_, chunk.Latch->getName() + ".chunk.boundary", &func);

        struct Carried {
            PHINode* Phi;
            Value* Next;
            AllocaInst* Slot;
            LoadInst* Reload;
        };
        SmallVector<Carried> carried;
        IRBuilder<> entryBuilder(&*func.getEntryBlock().getFirstInsertionPt());
        IRBuilder<> resumeBuilder(resume);
        for (PHINode& phi : chunk.Header->phis()) {
            Value* next = phi.getIncomingValueForBlock(chunk.Latch);
            auto* slot = entryBuilder.CreateAlloca(phi.getType(), nullptr, phi.getName() + ".chunk.slot");
            auto* reload = resumeBuilder.CreateLoad(phi.getType(), slot, phi.getName() + ".chunk.reload");
            reload->setDebugLoc(debugLoc);
            carried.push_back({&phi, next, slot, reload});
        }
        resumeBuilder.CreateBr(chunk.Header)->setDebugLoc(debugLoc);

        chunk.Latch->getTerminator()->replaceSuccessorWith(chunk.Header, guard);
        for (auto item : carried) {
            item.Phi->removeIncomingValue(chunk.Latch, false);
            item.Phi->addIncoming(item.Next, keepGoing);
            item.Phi->addIncoming(item.Reload, resume);
        }

        auto* counter = PHINode::Create(I32_, 3, "bpf.loop.chunk", chunk.Header->begin());
        counter->addIncoming(ConstantInt::get(I32_, 0), chunk.Preheader);
        counter->addIncoming(ConstantInt::get(I32_, 0), resume);
        counter->setDebugLoc(debugLoc);

        IRBuilder<> guardBuilder(guard);
        Value* nextCount = guardBuilder.CreateAdd(counter, ConstantInt::get(I32_, 1), "bpf.loop.chunk.next");
        guardBuilder.CreateCondBr(guardBuilder.CreateICmpULT(nextCount, ConstantInt::get(I32_, chunk.Trips)), keepGoing, boundary);

        IRBuilder<> continueBuilder(keepGoing);
        continueBuilder.CreateBr(chunk.Header)->setDebugLoc(debugLoc);
        counter->addIncoming(nextCount, keepGoing);

        IRBuilder<> boundaryBuilder(boundary);
        for (auto item : carried) {
            boundaryBuilder.CreateStore(item.Next, item.Slot)->setDebugLoc(debugLoc);
        }
        boundaryBuilder.CreateBr(resume)->setDebugLoc(debugLoc);

        ChunkBoundaries_[chunk.Header] = boundary;
        ChunkResumes_[chunk.Header] = resume;
        for (BasicBlock* block : {guard, keepGoing, boundary, resume}) {
            for (Instruction& inst : *block) {
                if (!inst.getDebugLoc()) {
                    inst.setDebugLoc(debugLoc);
                }
            }
        }
    }

    // A fully virtualized loop is the universal fallback: it is resumable,
    // places no trip-count burden on the verifier, and works on every target.
    // It is also needlessly expensive for a small loop whose bound is already
    // visible in the optimized IR.  Keep only the conservative, profitable
    // subset below as real BPF loops.  This is deliberately an automatic
    // compiler decision, not a batch-size option for users to tune.
    void ClassifyLoops() {
        constexpr unsigned MaxLinearNativeTrips = 64;
        // Four is a verifier-state limit, not a source-semantic one. Unknown
        // scalar states can multiply at each branching backedge until a loop
        // with only a handful of iterations exhausts the verifier's global
        // analysis budget. Longer branching loops use resumable chunks;
        // straight-line loops retain the much larger fast path below.
        constexpr unsigned MaxBranchingNativeTrips = 4;
        constexpr uint64_t MaxExpandedIr = 256;
        // Bound extra native-loop verifier work in the complete load graph.
        // Chunked dynamic loops use a separate marginal-cost allocator below.
        constexpr uint64_t MaxExtraLinearIr = 1024;
        uint64_t native = 0;
        uint64_t guarded = 0;
        uint64_t chunked = 0;
        uint64_t virtualized = 0;
        uint64_t savedBackedges = 0;
        uint64_t expandedIr = 0;
        uint64_t extraLinearIr = 0;
        uint64_t chunkBackedges = 0;
        uint64_t rejectedShape = 0;
        uint64_t rejectedCalls = 0;
        uint64_t rejectedBound = 0;
        uint64_t rejectedTrips = 0;
        uint64_t rejectedCost = 0;
        struct GuardCandidate {
            BasicBlock* Header;
            BasicBlock* Latch;
            BasicBlock* Preheader;
            unsigned Trips;
        };
        SmallVector<GuardCandidate> guards;
        SmallVector<ChunkCandidate> chunks;

        uint64_t sourceIr = 0;
        for (auto&& [func, info] : Managed_) {
            for (BasicBlock& block : *func) {
                sourceIr += EstimatedBlockSize(block);
            }
        }

        // Static incoming call frequency is a profile-free estimate of which
        // chunk saves the most dispatches.  It is invariant under adding
        // unrelated functions: only this function's call sites and loop
        // nesting affect its score.
        DenseMap<Function*, uint64_t> functionHotness;
        for (auto&& [func, info] : Managed_) {
            functionHotness[func] = 1;
        }
        for (auto&& [caller, info] : Managed_) {
            DominatorTree callerDt(*caller);
            LoopInfo callerLi(callerDt);
            for (Instruction& inst : instructions(*caller)) {
                auto* call = dyn_cast<CallBase>(&inst);
                Function* callee = call ? call->getCalledFunction() : nullptr;
                if (!callee || !ManagedByFunction_.contains(callee)) {
                    continue;
                }
                unsigned depth = callerLi.getLoopDepth(inst.getParent());
                functionHotness[callee] += uint64_t(1) << std::min(depth, 12u);
            }
        }

        // A callback's direct use is its registration, not the computed call
        // which makes it hot at runtime.  Attribute every computed managed
        // call to its type-compatible address-taken targets.  Weight the site
        // by the caller's already-computed incoming frequency as well as its
        // local loop depth: this recovers the ordinary call-chain context
        // which an indirect edge otherwise erases (platform I/O callbacks are
        // the common case).  Exact function-type matching is the same closed
        // target set used by the whole-program partition pass.
        for (auto&& [caller, info] : Managed_) {
            DominatorTree callerDt(*caller);
            LoopInfo callerLi(callerDt);
            for (Instruction& inst : instructions(*caller)) {
                auto* call = dyn_cast<CallBase>(&inst);
                if (!call || call->getCalledFunction() || isa<Constant>(call->getCalledOperand())) {
                    continue;
                }
                unsigned depth = callerLi.getLoopDepth(inst.getParent());
                uint64_t localWeight = uint64_t(1) << std::min(depth, 12u);
                uint64_t callerWeight = functionHotness.lookup(caller);
                uint64_t siteWeight =
                    callerWeight > std::numeric_limits<uint64_t>::max() / localWeight ? std::numeric_limits<uint64_t>::max() : callerWeight * localWeight;
                for (auto&& [target, targetInfo] : Managed_) {
                    if (!target->hasAddressTaken() || target->getFunctionType() != call->getFunctionType()) {
                        continue;
                    }
                    uint64_t& hotness = functionHotness[target];
                    hotness = hotness > std::numeric_limits<uint64_t>::max() - siteWeight ? std::numeric_limits<uint64_t>::max() : hotness + siteWeight;
                }
            }
        }

        TargetLibraryInfoImpl tliImpl(Triple(Module_.getTargetTriple()));
        TargetLibraryInfo tli(tliImpl);
        for (auto&& [func, info] : Managed_) {
            AssumptionCache ac(*func);
            DominatorTree dt(*func);
            LoopInfo li(dt);
            ScalarEvolution se(*func, tli, ac, dt, li);

            for (Loop* loop : li.getLoopsInPreorder()) {
                uint64_t bodyIr = 0;
                unsigned branchFanout = 0;
                bool managedCall = false;
                bool nonScalarExecutableCall = false;
                SmallVector<Function*, 4> blockingCallees;
                bool blockingIndirectCall = false;
                for (BasicBlock* block : loop->blocks()) {
                    bodyIr += EstimatedBlockSize(*block);
                    // A loop with several data-dependent paths is much more
                    // expensive for the verifier than a straight-line loop
                    // of the same IR size: every retained iteration carries
                    // those distinct abstract states around the backedge.
                    // Count excess CFG successors as a small, target-agnostic
                    // proxy for that cost.  The latch itself contributes one,
                    // as it should -- its exit condition also evolves state.
                    branchFanout += block->getTerminator()->getNumSuccessors() > 0 ? block->getTerminator()->getNumSuccessors() - 1 : 0;
                    for (Instruction& inst : *block) {
                        // BPF has no conditional move.  LLVM selects therefore
                        // become control-flow branches after this pass and must
                        // count toward the verifier's path product even though
                        // they are not CFG successors yet.
                        branchFanout += isa<SelectInst>(inst);
                        auto* call = dyn_cast<CallBase>(&inst);
                        managedCall |= call && IsManagedCall(call);
                        // Inline-asm opacity barriers are not runtime calls,
                        // but they mark address expressions the verifier must
                        // rediscover on every iteration.  Treat them as a
                        // chunking boundary: admitting all such heap loops in
                        // QuickJS/SQLite exhausts Linux 5.15's global analysis
                        // budget even though each loop looks small in IR.
                        bool executable = call && !isa<IntrinsicInst>(call);
                        // A selected scalar island has a pointer-free ABI,
                        // bounded local loops, a proven whole-call-chain
                        // depth and its own global-subprogram verifier proof.
                        // It is safe to invoke from a native chunk without
                        // turning the source call into a suspension boundary.
                        // Ordinary calls, helpers and inline asm keep the
                        // conservative one-iteration fallback.
                        Function* callee = executable ? call->getCalledFunction() : nullptr;
                        bool blockingCall = executable && (!callee || !NativeScalarFunctions_.contains(callee));
                        nonScalarExecutableCall |= blockingCall;
                        if (blockingCall && callee) {
                            blockingCallees.push_back(callee);
                        } else if (blockingCall) {
                            blockingIndirectCall = true;
                        }
                    }
                }

                // Innermost, simplified single-latch loops stay self-contained when
                // calls and physical continuation regions are formed.  SCEV's
                // predicate-free maximum is a proof over the actual optimized
                // IR, rather than a source annotation the verifier may not be
                // able to reproduce.  The two caps bound both jump history and
                // the verifier's per-iteration path expansion.
                unsigned exactTrips = se.getSmallConstantTripCount(loop);
                unsigned trips = exactTrips ? exactTrips : se.getSmallConstantMaxTripCount(loop);
                uint64_t expansion = trips ? uint64_t(trips - 1) * bodyIr : std::numeric_limits<uint64_t>::max();
                BasicBlock* latch = loop->getLoopLatch();
                BasicBlock* preheader = loop->getLoopPreheader();
                BasicBlock* predecessor = loop->getLoopPredecessor();
                // A straight-line constant loop creates one verifier state
                // per iteration, not a path product. Give that case a larger
                // but still tiny linear budget. This is the common Rust
                // iterator/hash shape, and stock 5.15 verifies it directly;
                // turning every traversal into a continuation was most of
                // the measured transformed-vs-direct gap.
                uint64_t nativeIrBudget = branchFanout <= 1 ? 1024 : MaxExpandedIr;
                uint64_t linearExtension = expansion > MaxExpandedIr ? expansion - MaxExpandedIr : 0;
                bool nativeShape = loop->isInnermost() && latch && preheader && loop->isLoopSimplifyForm();
                bool nativeCost = expansion <= nativeIrBudget && (!linearExtension || linearExtension <= MaxExtraLinearIr - extraLinearIr);
                // A constant trip count is not by itself a verifier-cost
                // bound. A loop with internal control flow carries several
                // abstract states around every backedge; on arena targets
                // the following memory operations are visible in the same
                // verifier graph, so a tiny 64-trip source loop can exhaust
                // the million-instruction analysis budget. Keep long native
                // loops only when the latch is their sole branch. Branching
                // loops use the resumable chunk path below after eight trips.
                unsigned maxNativeTrips = branchFanout <= 1 ? MaxLinearNativeTrips : MaxBranchingNativeTrips;
                bool keepNative = nativeShape && !managedCall && trips && trips <= maxNativeTrips && nativeCost;
                if (!keepNative) {
                    if (!nativeShape) {
                        rejectedShape++;
                    } else if (managedCall) {
                        rejectedCalls++;
                    } else if (!trips) {
                        rejectedBound++;
                    } else if (trips > maxNativeTrips) {
                        rejectedTrips++;
                    } else {
                        rejectedCost++;
                    }
                    // Dynamic loops are the hot case in interpreters and
                    // codecs.  Running one managed dispatch per traversal is
                    // correct but catastrophically expensive.  A bounded
                    // native chunk retains exact suspension semantics while
                    // amortizing dispatch and PC selection.  Size the chunk
                    // from the optimized body: roughly 1k expanded IR leaves
                    // ample room below the verifier's 8192-jump path limit.
                    // A managed call cannot carry a chunk counter across its
                    // suspension. Ordinary subprograms are also excluded: on
                    // Linux 5.15, nesting a bounded callee loop inside a
                    // 64-trip chunk multiplied verifier exploration past the
                    // one-million-instruction limit in QuickJS. Separately
                    // proven scalar islands are different: the kernel checks
                    // their bounded pointer-free call graph independently, so
                    // a caller chunk does not duplicate their internal CFG.
                    // Map-backed memory is lowered after this pass into
                    // accessor calls and much larger control flow.  Its old
                    // verifier must therefore get a smaller chunk than arena
                    // code even when today's IR bodies look identical.
                    const uint64_t maxChunkExpandedIr = bpf::UseArena() ? 1024 : 128;
                    // Every module gets the same conservative base choice.
                    // Arena-linear loops may request a larger local optimum;
                    // the marginal-cost allocator below spends finite global
                    // verifier headroom on the hottest requests instead of
                    // changing every loop at one arbitrary module-size cliff.
                    const unsigned baseMaxChunkTrips = !bpf::UseArena() ? 8 : branchFanout <= 1 ? 8 : 4;
                    // Linux 7.1 regressed verifier pruning for this shape:
                    // otherwise equivalent 32- and 64-trip Rust chunks reach
                    // the one-million processed-insn limit, while 16 remains
                    // below 100k.  This is a proof-cost ceiling; execution is
                    // still chunked and the measured Rust workload remains
                    // within run-to-run noise of the former 64-trip choice.
                    const unsigned desiredMaxChunkTrips = !bpf::UseArena() ? 8 : branchFanout <= 1 ? 16 : branchFanout == 2 ? 8 : 4;
                    // Compiler-emulated arithmetic is deliberately branchy.
                    // In the map tier, its software-stack accesses become
                    // accessor calls after stackify, so even an eight-trip
                    // native chunk of __bpf_ddiv made 5.15 explore more than
                    // one million instructions.  Keep those runtime loops
                    // resumable on the old tier; ordinary library leaf loops
                    // still get chunks.
                    bool oldRuntime = !bpf::UseArena() && func->getName().starts_with("__bpf_");
                    // Chunking only rewires the unique latch -> header edge;
                    // unlike full LoopSimplify it does not consume or modify
                    // exit blocks. It also only needs one outside predecessor
                    // to seed carried PHIs; that predecessor may own a second
                    // zero-trip exit edge and therefore need not satisfy
                    // LLVM's stricter preheader definition.
                    auto sizeChunk = [&](unsigned maximum) {
                        return bodyIr ? std::min<unsigned>(maximum, std::max<uint64_t>(2, maxChunkExpandedIr / bodyIr)) : 0u;
                    };
                    unsigned baseTrips = sizeChunk(baseMaxChunkTrips);
                    unsigned desiredTrips = sizeChunk(desiredMaxChunkTrips);
                    // A unique outside predecessor is sufficient for the IR
                    // rewrite, but a noncanonical entry also preserves its
                    // zero-trip branch.  Replicating those incoming states can
                    // consume the verifier's one-million-insn analysis budget.
                    // Treat it as a candidate with an explicit cost rather
                    // than accepting/rejecting all such loops by module size.
                    BasicBlock* chunkEntry = preheader ? preheader : predecessor;
                    bool canChunk = loop->isInnermost() && latch && chunkEntry && !nonScalarExecutableCall && !oldRuntime && bodyIr != 0 &&
                        bodyIr <= maxChunkExpandedIr / 2;
                    if (DumpIds) {
                        errs() << "stackify-loop " << func->getName() << ":" << loop->getHeader()->getName() << " inner=" << loop->isInnermost()
                               << " latch=" << bool(latch) << " preheader=" << bool(preheader) << " predecessor=" << bool(predecessor)
                               << " simplify=" << loop->isLoopSimplifyForm() << " body=" << bodyIr << " trips=" << trips
                               << " blocking=" << nonScalarExecutableCall << " chunk=" << canChunk;
                        for (Function* callee : blockingCallees) {
                            errs() << " call=" << callee->getName();
                        }
                        if (blockingIndirectCall) {
                            errs() << " call=<indirect-or-asm>";
                        }
                        errs() << "\n";
                    }
                    if (canChunk) {
                        // Each source branch is a potential verifier path;
                        // selects were included above because the BPF backend
                        // lowers them to branches.  Cap the multiplier to keep
                        // the estimate useful instead of overflowing on a
                        // switch-heavy loop.
                        unsigned pathBits = branchFanout ? std::min(branchFanout - 1, 4u) : 0;
                        uint64_t pathFactor = uint64_t(1) << pathBits;
                        uint64_t entryFactor = preheader ? 1 : 2;
                        auto verifierCost = [&](unsigned count) { return uint64_t(count - 1) * bodyIr * pathFactor * entryFactor; };
                        uint64_t hotness = functionHotness.lookup(func);
                        unsigned loopDepth = li.getLoopDepth(loop->getHeader());
                        hotness *= uint64_t(1) << std::min(loopDepth ? loopDepth - 1 : 0, 12u);
                        ChunkCandidate candidate;
                        candidate.Header = loop->getHeader();
                        candidate.Latch = latch;
                        candidate.Preheader = chunkEntry;
                        candidate.BaseTrips = baseTrips;
                        candidate.DesiredTrips = desiredTrips;
                        candidate.BaseCost = verifierCost(baseTrips);
                        candidate.DesiredCost = verifierCost(desiredTrips);
                        candidate.Hotness = hotness;
                        candidate.Canonical = bool(preheader);
                        candidate.Blocks.append(loop->block_begin(), loop->block_end());
                        chunks.push_back(std::move(candidate));
                        continue;
                    }
                    virtualized++;
                    continue;
                }

                NativeLoopHeaders_.insert(loop->getHeader());
                native++;
                savedBackedges += trips - 1;
                expandedIr += expansion;
                extraLinearIr += linearExtension;
                // A variable maximum always needs to be made verifier-visible.
                // An exact loop already carries its own constant exit.  The
                // old verifier's separate CFG-shape rule is handled after
                // machine block layout, where fallthrough is actually known.
                if (!exactTrips) {
                    guards.push_back({loop->getHeader(), latch, preheader, trips});
                    guarded++;
                }
            }
        }

        // A monolithic BPF load has a finite cumulative verifier budget, even
        // though its global subprograms are checked independently.  Give every
        // candidate the same local base/desired choices, then allocate that
        // finite resource by marginal dispatches saved per verifier-cost unit.
        // The capacity is at least one fixed target-cost allowance and grows
        // only with canonical work that brings its own conservative budget.
        // Unrelated straight-line IR therefore cannot change an existing
        // function's choice.  A hot noncanonical loop can replace colder
        // canonical work instead of falling off a module-size threshold.
        uint64_t chunkBudget = 0;
        for (const ChunkCandidate& chunk : chunks) {
            if (chunk.Canonical) {
                chunkBudget += chunk.BaseCost;
            }
        }
        constexpr uint64_t MinArenaChunkVerifierCost = 32768;
        constexpr uint64_t MinMapChunkVerifierCost = 4096;
        chunkBudget = std::max(chunkBudget, bpf::UseArena() ? MinArenaChunkVerifierCost : MinMapChunkVerifierCost);
        uint64_t chunkCost = 0;
        auto stableTie = [&](unsigned a, unsigned b) {
            Function* af = chunks[a].Header->getParent();
            Function* bf = chunks[b].Header->getParent();
            if (af->getName() != bf->getName()) {
                return af->getName() < bf->getName();
            }
            if (chunks[a].Header->getName() != chunks[b].Header->getName()) {
                return chunks[a].Header->getName() < chunks[b].Header->getName();
            }
            return a < b;
        };

        // Base chunks and their larger local optima compete for the same
        // verifier budget.  Allocating every base first can exhaust the budget
        // before a very hot loop is allowed to grow, even when that growth
        // saves far more dispatches than a cold base costs.  Select the best
        // currently available marginal step globally.  A boost becomes
        // eligible only after its base, so every selected state is valid.
        for (;;) {
            unsigned best = chunks.size();
            uint64_t bestCost = 0;
            __uint128_t bestGain = 0;
            uint64_t bestDenominator = 1;
            for (unsigned i = 0; i < chunks.size(); i++) {
                const ChunkCandidate& chunk = chunks[i];
                uint64_t cost;
                __uint128_t gain;
                uint64_t denominator;
                if (!chunk.Trips) {
                    cost = chunk.BaseCost;
                    gain = __uint128_t(chunk.Hotness) * (chunk.BaseTrips - 1);
                    denominator = chunk.BaseTrips;
                } else if (chunk.Trips == chunk.BaseTrips && chunk.DesiredTrips > chunk.BaseTrips) {
                    cost = chunk.DesiredCost - chunk.BaseCost;
                    gain = __uint128_t(chunk.Hotness) * (chunk.DesiredTrips - chunk.BaseTrips);
                    denominator = uint64_t(chunk.BaseTrips) * chunk.DesiredTrips;
                } else {
                    continue;
                }
                if (!cost || cost > chunkBudget - chunkCost) {
                    continue;
                }
                __uint128_t lhs = gain * bestDenominator * bestCost;
                __uint128_t rhs = bestGain * denominator * cost;
                if (best == chunks.size() || lhs > rhs || (lhs == rhs && stableTie(i, best))) {
                    best = i;
                    bestCost = cost;
                    bestGain = gain;
                    bestDenominator = denominator;
                }
            }
            if (best == chunks.size()) {
                break;
            }
            ChunkCandidate& selected = chunks[best];
            selected.Trips = selected.Trips ? selected.DesiredTrips : selected.BaseTrips;
            chunkCost += bestCost;
        }

        for (ChunkCandidate& chunk : chunks) {
            if (!chunk.Trips) {
                virtualized++;
                continue;
            }
            ChunkTrips_[chunk.Header] = chunk.Trips;
            chunked++;
            chunkBackedges += chunk.Trips - 1;
            if (DumpIds) {
                errs() << "stackify-chunk " << chunk.Header->getParent()->getName() << ":" << chunk.Header->getName() << " trips=" << chunk.Trips
                       << " base=" << chunk.BaseTrips << " desired=" << chunk.DesiredTrips << " hotness=" << chunk.Hotness
                       << " cost=" << (chunk.Trips == chunk.DesiredTrips ? chunk.DesiredCost : chunk.BaseCost) << " canonical=" << chunk.Canonical << "\n";
            }
        }

        DenseMap<Function*, BasicBlock*> bailByFunction;
        for (auto guard : guards) {
            GuardNativeLoop(guard.Header, guard.Latch, guard.Preheader, guard.Trips, bailByFunction);
        }
        for (const ChunkCandidate& chunk : chunks) {
            if (chunk.Trips) {
                PrepareChunkedLoop(chunk);
                if (VerifierPointerError_) {
                    return;
                }
            }
        }
        bpf::stats() << "stackify: retained " << native << " small bounded loops (" << guarded << " guarded";
        bpf::stats() << ", max " << savedBackedges << " backedges, ~" << expandedIr << " verifier IR, " << extraLinearIr << " extended from " << sourceIr
                     << " source IR), chunked " << chunked << " dynamic loops (up to " << chunkBackedges << " native backedges/chunk, cost " << chunkCost << "/"
                     << chunkBudget << "), virtualized " << virtualized << " loops; native rejects shape/call/bound/trips/cost " << rejectedShape << "/"
                     << rejectedCalls << "/" << rejectedBound << "/" << rejectedTrips << "/" << rejectedCost << "\n";
    }

    SmallVector<Backedge> Backedges(Function& func, bool includeChunked = true) {
        DominatorTree dt(func);
        LoopInfo li(dt);
        SmallVector<Backedge> edges;
        for (auto* loop : li.getLoopsInPreorder()) {
            if (NativeLoopHeaders_.contains(loop->getHeader())) {
                continue;
            }
            if (BasicBlock* boundary = ChunkBoundaries_.lookup(loop->getHeader())) {
                if (includeChunked) {
                    edges.push_back({boundary, loop->getHeader(), ChunkTrips_.lookup(loop->getHeader())});
                }
                continue;
            }
            for (auto* latch : predecessors(loop->getHeader())) {
                if (loop->contains(latch)) {
                    edges.push_back({latch, loop->getHeader(), ChunkTrips_.lookup(loop->getHeader())});
                }
            }
        }
        return edges;
    }

    uint64_t EstimatedBlockSize(BasicBlock& block) const {
        uint64_t size = 0;
        for (auto&& inst : block) {
            if (isa<AllocaInst>(inst)) {
                continue; // replaced by frame-relative addresses later
            }
            if (auto* ii = dyn_cast<IntrinsicInst>(&inst); ii && ii->isLifetimeStartOrEnd()) {
                continue;
            }
            size++;
        }
        return size;
    }

    // Partition the post-demotion CFG, not the source's linear instruction
    // list.  Every edge crossing partitions becomes an explicit continuation
    // edge.  Cutting all such edges guarantees that alternate branches cannot
    // reconnect two supposedly separate regions behind our back.
    void PlanRegionCuts() {
        unsigned budget = SplitLargerThan;
        if (budget == 0 && !bpf::HasCpuV4()) {
            // v3 conditional branches have signed 16-bit displacement.  This
            // leaves headroom for BPF heap access and spill expansion.
            budget = 6000;
        }
        if (budget == 0) {
            return;
        }

        uint64_t totalCuts = 0;
        uint64_t protectedEdges = 0;
        for (auto&& [funcPtr, infoPtr] : Managed_) {
            Function& func = *funcPtr;
            ManagedFunction& info = *infoPtr;

            uint64_t total = 0;
            for (auto&& block : func) {
                total += EstimatedBlockSize(block);
            }
            if (total <= budget) {
                continue;
            }

            // No one block may defeat the partition.  Split long straight-line
            // blocks first; PHIs stay at the beginning and terminators at the
            // end, so every new block is a valid CFG unit.
            DominatorTree beforeSplitDt(func);
            LoopInfo beforeSplitLi(beforeSplitDt);
            SmallPtrSet<BasicBlock*, 32> nativeLoopBlocks;
            for (Loop* loop : beforeSplitLi.getLoopsInPreorder()) {
                if (!NativeLoopHeaders_.contains(loop->getHeader()) && !ChunkTrips_.contains(loop->getHeader())) {
                    continue;
                }
                nativeLoopBlocks.insert_range(loop->blocks());
            }
            SmallVector<Instruction*> points;
            for (auto&& block : func) {
                // A retained loop is capped at a tiny fraction of this budget
                // and is packed atomically below.  Splitting one of its blocks
                // would only complicate identifying that atomic component.
                if (nativeLoopBlocks.contains(&block)) {
                    continue;
                }
                unsigned size = 0;
                for (auto&& inst : block) {
                    if (isa<AllocaInst>(inst) || isa<PHINode>(inst) || inst.isTerminator()) {
                        continue;
                    }
                    if (auto* ii = dyn_cast<IntrinsicInst>(&inst); ii && ii->isLifetimeStartOrEnd()) {
                        continue;
                    }
                    if (++size >= budget) {
                        if (inst.getNextNode() && !isa<PHINode>(inst.getNextNode())) {
                            points.push_back(inst.getNextNode());
                            size = 0;
                        }
                    }
                }
            }
            for (Instruction* point : points) {
                BasicBlock* block = point->getParent();
                block->splitBasicBlock(point, block->getName() + ".partition");
            }

            // Pack every retained loop as one unit.  A continuation cut inside
            // a cyclic component would not actually separate physical regions:
            // the native backedge reconnects both halves.  Grouping it here
            // makes the estimated partition budget match the CFG we eventually
            // hand to the backend, including tiny loops nested in giant source
            // functions such as zlib's inflate().
            DominatorTree partitionDt(func);
            LoopInfo partitionLi(partitionDt);
            DenseMap<BasicBlock*, BasicBlock*> nativeOwner;
            DenseMap<BasicBlock*, SmallVector<BasicBlock*, 8>> nativeGroups;
            for (Loop* loop : partitionLi.getLoopsInPreorder()) {
                if (!NativeLoopHeaders_.contains(loop->getHeader()) && !ChunkTrips_.contains(loop->getHeader())) {
                    continue;
                }
                auto& blocks = nativeGroups[loop->getHeader()];
                for (BasicBlock* block : loop->blocks()) {
                    nativeOwner[block] = loop->getHeader();
                    blocks.push_back(block);
                }
            }

            DenseMap<BasicBlock*, unsigned> partition;
            SmallPtrSet<BasicBlock*, 32> assigned;
            unsigned current = 0;
            uint64_t load = 0;
            for (auto&& block : func) {
                if (assigned.contains(&block)) {
                    continue;
                }
                BasicBlock* owner = nativeOwner.lookup(&block);
                SmallVector<BasicBlock*, 8> unit;
                if (owner) {
                    unit.append(nativeGroups[owner]);
                } else {
                    unit.push_back(&block);
                }
                uint64_t size = 0;
                for (BasicBlock* member : unit) {
                    size += EstimatedBlockSize(*member);
                }
                if (load != 0 && load + size > budget) {
                    current++;
                    load = 0;
                }
                for (BasicBlock* member : unit) {
                    partition[member] = current;
                    assigned.insert(member);
                }
                load += size;
            }

            SmallVector<Backedge> backedges = Backedges(func);
            auto isVirtualizedBackedge = [&](BasicBlock* from, BasicBlock* to) {
                for (auto edge : backedges) {
                    if (edge.Latch == from && edge.Header == to) {
                        return true;
                    }
                }
                return false;
            };

            // A verifier pointer cannot be reconstructed after a return to
            // the trampoline. Code-size partitioning is our choice, so make
            // every edge inside such a pointer's live range atomic instead of
            // turning an otherwise valid native operation into a compile
            // error. Source-mandated boundaries (managed calls and resumable
            // loops) are validated separately and still produce diagnostics.
            SmallPtrSet<Value*, 32> verifierNative;
            FindVerifierNativeValues(func, verifierNative);
            SmallVector<const AllocaInst*, 8> nativeAllocas = NativeHelperAllocas(func);
            StackLifetime stackLifetime(func, nativeAllocas, StackLifetime::LivenessType::May);
            stackLifetime.run();
            LivenessAnalysis cutLiveness(func);
            auto carriesVerifierPointer = [&](BasicBlock* from, BasicBlock* to) {
                for (const AllocaInst* alloca : nativeAllocas) {
                    if (stackLifetime.isAliveAfter(alloca, from->getTerminator())) {
                        return true;
                    }
                }
                for (Value* value : cutLiveness.liveAcross(from, to)) {
                    if (verifierNative.contains(value) && !IsRematerializableVerifierRoot(value)) {
                        return true;
                    }
                }
                return false;
            };

            for (auto&& block : func) {
                for (BasicBlock* succ : successors(&block)) {
                    if (partition[&block] == partition[succ] || isVirtualizedBackedge(&block, succ)) {
                        continue;
                    }
                    if (carriesVerifierPointer(&block, succ)) {
                        protectedEdges++;
                        continue;
                    }
                    bool duplicate = false;
                    for (auto cut : info.CutEdges) {
                        duplicate |= cut.From == &block && cut.To == succ;
                    }
                    if (!duplicate) {
                        info.CutEdges.push_back({&block, succ});
                        totalCuts++;
                    }
                }
            }
        }
        if (totalCuts) {
            bpf::stats() << "stackify: planned " << totalCuts << " CFG continuation cuts\n";
        }
        if (protectedEdges) {
            bpf::stats() << "stackify: kept " << protectedEdges << " verifier-pointer edges inside physical regions\n";
        }
    }

    // Demoting a PHI replaces it with a load at the top of its block, which may
    // itself end up crossing a call, so repeat until nothing crosses any more.
    void DemoteAcrossCalls(Function& func) {
        SmallVector<CallBase*> calls = SuspensionCalls(func);
        // Prepared chunks carry their PHIs in SSA and serialize explicitly on
        // their cold boundary.  Blanket backedge demotion would put those
        // values back in memory on every hot native iteration.
        SmallVector<Backedge> backedges = Backedges(func, false);
        if (calls.empty() && backedges.empty()) {
            return;
        }

        for (unsigned round = 0;; round++) {
            LivenessAnalysis liveness(func);

            SetVector<Value*> crossing;
            for (auto* call : calls) {
                SmallPtrSet<Value*, 16> live = liveness.liveAfter(call);
                for (auto* v : ValuesInProgramOrder(func, live)) {
                    // SuspendAtCall replaces the callee's result with a load
                    // from the return slot on resume.  Only values already
                    // live before the call need ordinary demotion.
                    if (v == call) {
                        continue;
                    }
                    // Arguments need no demotion: every use reloads them from
                    // the frame. Allocas already live in the frame.
                    if (isa<Argument>(v) || isa<AllocaInst>(v)) {
                        continue;
                    }
                    crossing.insert(v);
                }
            }
            // A backedge becomes a return, so the loop header is re-entered
            // from the resume dispatch rather than from the latch. Every PHI in
            // the header loses its incoming edges, and anything live across the
            // backedge has to survive a return — both mean living in memory.
            //
            // Values defined at or below the header are the exception: resuming
            // re-executes them, so they need no slot. That exception is what
            // makes this terminate, since demoting a header PHI leaves a reload
            // at the top of the header which would otherwise look like it
            // crosses the backedge and be demoted again, forever.
            DominatorTree dt(func);
            for (auto&& edge : backedges) {
                for (auto&& phi : edge.Header->phis()) {
                    crossing.insert(&phi);
                }
                SmallPtrSet<Value*, 16> live = liveness.liveAfter(edge.Latch->getTerminator());
                for (auto* v : ValuesInProgramOrder(func, live)) {
                    if (isa<Argument>(v) || isa<AllocaInst>(v)) {
                        continue;
                    }
                    auto* inst = dyn_cast<Instruction>(v);
                    if (inst && dt.dominates(edge.Header, inst->getParent())) {
                        continue;
                    }
                    crossing.insert(v);
                }
            }
            if (crossing.empty()) {
                break;
            }
            if (round > 8) {
                report_fatal_error(Twine("stackify: demotion did not converge in ") + func.getName());
            }

            DemoteValues(func, crossing);
        }
    }

    void DemoteValues(Function& func, SetVector<Value*>& crossing) {
        auto allocaPoint = func.getEntryBlock().getFirstInsertionPt();
        auto& demotedSlots = DemotedSlots_[&func];

        // PHIs first: DemoteRegToStack cannot handle a PHI directly.
        SmallVector<PHINode*> phis;
        SmallVector<LoadInst*> reloads;
        SmallVector<Instruction*> insts;
        for (auto* v : crossing) {
            if (auto* phi = dyn_cast<PHINode>(v)) {
                phis.push_back(phi);
            } else if (
                auto* load = dyn_cast<LoadInst>(v); load && demotedSlots.contains(dyn_cast<AllocaInst>(getUnderlyingObject(load->getPointerOperand())))
            ) {
                reloads.push_back(load);
            } else {
                insts.push_back(cast<Instruction>(v));
            }
        }

        // DemotePHIToStack writes each incoming value in its predecessor.
        // On a critical edge that predecessor also has an exit successor, so
        // the write happens on both edges.  A loop-carried `i + 1`, for
        // example, then overwrites the current `i` on loop exit.  Split those
        // edges first so every generated store is edge-local.  This is a
        // correctness requirement, not CFG cleanup: SQLite's tokenizer was
        // the minimal real-world repro (`for (...; table[z[i]]; i++)`).
        SmallPtrSet<BasicBlock*, 8> phiBlocks;
        for (PHINode* phi : phis) {
            phiBlocks.insert(phi->getParent());
        }
        SmallVector<std::pair<Instruction*, unsigned>, 8> criticalEdges;
        for (BasicBlock& phiBlock : func) {
            if (!phiBlocks.contains(&phiBlock)) {
                continue;
            }
            for (BasicBlock& predecessor : func) {
                Instruction* terminator = predecessor.getTerminator();
                if (terminator->getNumSuccessors() < 2) {
                    continue;
                }
                for (unsigned i = 0; i < terminator->getNumSuccessors(); i++) {
                    if (terminator->getSuccessor(i) == &phiBlock) {
                        criticalEdges.push_back({terminator, i});
                    }
                }
            }
        }
        for (auto [terminator, successor] : criticalEdges) {
            SplitCriticalEdge(terminator, successor);
        }

        // PHIs are parallel assignments. DemotePHIToStack handles one PHI at
        // a time, so a latch such as `a.next = b; b.next = a` can otherwise
        // reload the first slot after it has already been updated while
        // demoting the second PHI. Materialize direct PHI-to-PHI incoming
        // values before any generated slot stores. Later simplification may
        // fold the identity select, but the aliasing reload remains ordered
        // before the stores that update the continuation state.
        for (PHINode* source : phis) {
            for (Use& use : make_early_inc_range(source->uses())) {
                auto* target = dyn_cast<PHINode>(use.getUser());
                if (!target) {
                    continue;
                }
                Instruction* terminator = target->getIncomingBlock(use)->getTerminator();
                auto* snapshot = SelectInst::Create(
                    ConstantInt::getTrue(Ctx_), source, PoisonValue::get(source->getType()), source->getName() + ".parallel", terminator->getIterator()
                );
                snapshot->setDebugLoc(target->getDebugLoc());
                use.set(snapshot);
            }
        }

        for (auto* phi : phis) {
            AllocaInst* slot = DemotePHIToStack(phi, allocaPoint);
            if (slot) {
                demotedSlots.insert(slot);
            }
        }
        for (auto* reload : reloads) {
            LocalizeSpillReload(*reload);
        }
        for (auto* inst : insts) {
            AllocaInst* slot = DemoteRegToStack(*inst, false, allocaPoint);
            if (slot) {
                demotedSlots.insert(slot);
            }
        }
    }

    // A load from a reg2mem slot is pure rematerialization: the slot is
    // compiler-private and cannot be reached by source pointers or a managed
    // callee.  Re-spilling the load creates reload-of-reload chains; cloning it
    // at each use gives every continuation region its own SSA definition.
    void LocalizeSpillReload(LoadInst& reload) {
        for (Use& use : make_early_inc_range(reload.uses())) {
            auto* user = cast<Instruction>(use.getUser());
            BasicBlock::iterator at = user->getIterator();
            if (auto* phi = dyn_cast<PHINode>(user)) {
                at = phi->getIncomingBlock(use)->getTerminator()->getIterator();
            }
            auto* local = cast<LoadInst>(reload.clone());
            local->setName(reload.getName() + ".local");
            local->insertBefore(at);
            use.set(local);
        }
        if (reload.use_empty()) {
            reload.eraseFromParent();
        }
    }

    // FinishStepGroups eventually adds a direct dispatch edge to every resume
    // root.  That edge does not exist while demotion runs, so an ordinary
    // DominatorTree incorrectly says that reloads above the loop dominate the
    // resumed execution.  Model the future edge explicitly: if a use is
    // reachable from a chunk resume without visiting the reload's block, put
    // a private load at the use.  The slots are compiler-private SSA spill
    // slots; LocalizeSpillReload is therefore rematerialization, not motion of
    // an observable source-memory read.
    void LocalizeReloadsBypassedByChunkResume(Function& func) {
        auto& demotedSlots = DemotedSlots_[&func];
        SmallVector<BasicBlock*> resumes;
        for (BasicBlock& block : func) {
            if (BasicBlock* resume = ChunkResumes_.lookup(&block)) {
                resumes.push_back(resume);
            }
        }
        if (resumes.empty()) {
            return;
        }

        auto reachableWithout = [](BasicBlock* start, BasicBlock* target, BasicBlock* avoid) {
            if (start == avoid) {
                return false;
            }
            SmallPtrSet<BasicBlock*, 32> seen;
            SmallVector<BasicBlock*, 32> worklist{start};
            seen.insert(start);
            while (!worklist.empty()) {
                BasicBlock* block = worklist.pop_back_val();
                if (block == target) {
                    return true;
                }
                for (BasicBlock* succ : successors(block)) {
                    if (succ != avoid && seen.insert(succ).second) {
                        worklist.push_back(succ);
                    }
                }
            }
            return false;
        };

        SmallVector<LoadInst*> bypassed;
        for (Instruction& inst : instructions(func)) {
            auto* load = dyn_cast<LoadInst>(&inst);
            auto* slot = load ? dyn_cast<AllocaInst>(getUnderlyingObject(load->getPointerOperand())) : nullptr;
            if (!load || !demotedSlots.contains(slot)) {
                continue;
            }
            bool bad = false;
            for (Use& use : load->uses()) {
                auto* user = cast<Instruction>(use.getUser());
                BasicBlock* useBlock = user->getParent();
                if (auto* phi = dyn_cast<PHINode>(user)) {
                    useBlock = phi->getIncomingBlock(use);
                }
                for (BasicBlock* resume : resumes) {
                    if (reachableWithout(resume, useBlock, load->getParent())) {
                        bad = true;
                        break;
                    }
                }
                if (bad) {
                    break;
                }
            }
            if (bad) {
                bypassed.push_back(load);
            }
        }
        for (LoadInst* load : bypassed) {
            LocalizeSpillReload(*load);
        }
    }

    void DemoteAcrossRegionCuts(Function& func) {
        ManagedFunction& info = *ManagedByFunction_.lookup(&func);
        for (unsigned round = 0;; round++) {
            LivenessAnalysis liveness(func);
            DominatorTree dt(func);
            SetVector<Value*> crossing;
            for (auto cut : info.CutEdges) {
                for (auto&& phi : cut.To->phis()) {
                    crossing.insert(&phi);
                }
                SmallPtrSet<Value*, 16> live = liveness.liveAcross(cut.From, cut.To);
                for (auto* v : ValuesInProgramOrder(func, live)) {
                    if (isa<Argument>(v) || isa<AllocaInst>(v)) {
                        continue;
                    }
                    // A value defined at or below the resume target is
                    // recomputed after dispatch.  Trying to spill it creates
                    // a reload that appears to cross a cyclic cut forever.
                    auto* inst = dyn_cast<Instruction>(v);
                    if (inst && dt.dominates(cut.To, inst->getParent())) {
                        continue;
                    }
                    crossing.insert(v);
                }
            }
            if (crossing.empty()) {
                break;
            }
            if (round > 8) {
                errs() << "stackify: persistent region-cut values (" << crossing.size() << ") in " << func.getName() << ":\n";
                unsigned shown = 0;
                for (Value* value : crossing) {
                    value->print(errs());
                    errs() << "\n";
                    if (++shown == 12) {
                        break;
                    }
                }
                report_fatal_error(Twine("stackify: region-cut demotion did not converge in ") + func.getName());
            }
            DemoteValues(func, crossing);
        }
    }

    // --------------------------------------------------------------- layout

    void ComputeFrameLayout() {
        const DataLayout& dl = Module_.getDataLayout();
        uint64_t largestFrame = 0;
        Function* largestFrameOwner = nullptr;
        uint64_t smallestFrame = UINT64_MAX;
        for (auto&& [func, info] : Managed_) {
            uint64_t cursor = info->LocalsOffset;
            for (auto&& inst : instructions(*func)) {
                auto* alloca = dyn_cast<AllocaInst>(&inst);
                if (!alloca) {
                    continue;
                }
                if (NativeHelperAllocas_.contains(alloca)) {
                    continue;
                }
                if (!alloca->isStaticAlloca()) {
                    // Dynamic alloca needs a checked run-time SP decrement.
                    // Keep the first unified-stack ABI exact and add that
                    // operation independently rather than silently reserving
                    // a second stack representation.
                    func->getContext().emitError(alloca, Twine("stackify: dynamic alloca survived VLA lowering in ") + func->getName());
                    InputError_ = true;
                    return;
                }
                uint64_t align = alloca->getAlign().value();
                cursor = (cursor + align - 1) & ~(align - 1);
                info->AllocaOffsets[alloca] = cursor;
                uint64_t bytes = dl.getTypeAllocSize(alloca->getAllocatedType());
                if (auto* n = dyn_cast<ConstantInt>(alloca->getArraySize())) {
                    bytes *= n->getZExtValue();
                }
                cursor += bytes;
            }

            // The result lives at the upper end of the frame. That boundary
            // is also the caller's frame base and remains stable through a
            // chain of differently-sized tail calls, so callers never need
            // the completed callee's dynamic frame size to find its result.
            cursor += info->ReturnSize;
            info->FrameSize = (cursor + 15) & ~uint64_t(15);
            if (info->FrameSize > largestFrame) {
                largestFrame = info->FrameSize;
                largestFrameOwner = func;
            }
            smallestFrame = std::min(smallestFrame, info->FrameSize);
        }
        // Fixed-tier regions are 2 MiB. A power-of-two fiber stack no larger than a
        // region divides that size exactly, so a region-aligned stack bank can
        // contain any number of fibers without one stack crossing a backing-map
        // boundary. Fiber count is deliberately unrestricted by this check;
        // the bank continues through direct and ARRAY-backed regions.
        if (!FiberStackBytes || !isPowerOf2_32(FiberStackBytes) || FiberStackBytes > (2u * 1024u * 1024u)) {
            report_fatal_error("stackify: fiber stack size must be a power of two no larger than 2 MiB");
        }
        FiberStackSize_ = FiberStackBytes;
        // The upper tail of every physical fiber stack is a guard at least as large
        // as any frame. A subtract that walks below byte zero therefore wraps
        // into storage no live frame can occupy. The trampoline catches the
        // encoded out-of-range cursor before dispatching that callee. This
        // proves stack safety once per dispatch instead of branching at every
        // call site.
        if (largestFrame > FiberStackSize_ / 2) {
            largestFrameOwner->getContext().emitError(
                Twine("stackify: managed frame in ") + largestFrameOwner->getName() + " is " + Twine(largestFrame) + " bytes, more than half of the " +
                Twine(FiberStackSize_) + "-byte per-fiber stack"
            );
            InputError_ = true;
            return;
        }
        StackLimit_ = FiberStackSize_ - largestFrame;
        bpf::stats() << "stackify: variable frames " << smallestFrame << ".." << largestFrame << " bytes, " << StackLimit_ / 1024 << " KiB usable + "
                     << (FiberStackSize_ - StackLimit_) / 1024 << " KiB guard per fiber, " << (FiberStackSize_ * FiberCount_) / 1024
                     << " KiB unified stack storage\n";
    }

    // Threaded interpreters represent the next virtual instruction as an
    // indirect tail call. With exact variable frames, every such transition
    // has to load the callee size, move SP while preserving the upper frame
    // boundary, translate the new address, and publish SP. Compute the same
    // closed target set used by whole-program indirect-call analysis and pad
    // each connected tail class to its largest member. A valid transition can
    // then overwrite the current frame in place. Padding does not accumulate
    // along the tail chain: the entire chain still owns exactly one frame.
    void EqualizeIndirectTailFrames() {
        DenseMap<Function*, SmallVector<Function*, 4>> adjacent;
        SmallPtrSet<Function*, 32> participants;
        SmallVector<CallBase*> tailSites;
        unsigned tailCalls = 0;

        for (auto&& [caller, callerInfo] : Managed_) {
            for (Instruction& instruction : instructions(*caller)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || call->getCalledFunction() || !IsManagedCall(call) || !FindTailForward(call)) {
                    continue;
                }

                bool foundTarget = false;
                for (auto&& [target, targetInfo] : Managed_) {
                    if (!target->hasAddressTaken() || target->getFunctionType() != call->getFunctionType()) {
                        continue;
                    }
                    adjacent[caller].push_back(target);
                    adjacent[target].push_back(caller);
                    participants.insert(caller);
                    participants.insert(target);
                    foundTarget = true;
                }
                if (foundTarget) {
                    tailSites.push_back(call);
                    tailCalls++;
                }
            }
        }

        SmallPtrSet<Function*, 32> visited;
        unsigned classes = 0;
        unsigned functions = 0;
        unsigned paddedFunctions = 0;
        uint64_t paddingBytes = 0;
        uint64_t largestClassFrame = 0;
        for (Function* start : participants) {
            if (!visited.insert(start).second) {
                continue;
            }

            SmallVector<Function*> worklist{start};
            SmallVector<Function*> component;
            uint64_t classFrameSize = 0;
            while (!worklist.empty()) {
                Function* function = worklist.pop_back_val();
                component.push_back(function);
                classFrameSize = std::max(classFrameSize, ManagedByFunction_.lookup(function)->FrameSize);
                for (Function* neighbor : adjacent[function]) {
                    if (visited.insert(neighbor).second) {
                        worklist.push_back(neighbor);
                    }
                }
            }

            uint32_t tailClass = ++classes;
            functions += component.size();
            largestClassFrame = std::max(largestClassFrame, classFrameSize);
            for (Function* function : component) {
                ManagedFunction* info = ManagedByFunction_.lookup(function);
                info->TailClass = tailClass;
                uint64_t& frameSize = info->FrameSize;
                if (frameSize != classFrameSize) {
                    paddingBytes += classFrameSize - frameSize;
                    paddedFunctions++;
                    frameSize = classFrameSize;
                }
            }
        }

        TailClassCount_ = classes;
        for (CallBase* call : tailSites) {
            ManagedFunction* caller = ManagedByFunction_.lookup(call->getFunction());
            if (!caller || !caller->TailClass) {
                report_fatal_error("stackify: indirect tail site has no frame class");
            }
            EqualFrameTailCalls_[call] = caller->TailClass;
        }

        if (tailCalls) {
            bpf::stats() << "stackify: equalized " << tailCalls << " indirect tail calls in " << classes << " classes (" << functions << " functions, "
                         << paddedFunctions << " padded by " << paddingBytes << " layout bytes, largest " << largestClassFrame << ")\n";
        }
    }

    void CreateStackGlobals() {
        auto* stackType = ArrayType::get(I8_, FiberStackSize_ * FiberCount_);
        Stack_ = new GlobalVariable(Module_, stackType, false, GlobalVariable::InternalLinkage, Constant::getNullValue(stackType), "bpf_call_stack");
        Stack_->setAlignment(Align(16));
        Stack_->setMetadata("bpf.fiber.stack.size", MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I64_, FiberStackSize_))));
    }

    // Publish the error in the current fiber. The driver observes it between
    // physical steps and reclaims the managed stack without a kernel-specific
    // exception mechanism.
    void EmitAbort(IRBuilder<>& b, int32_t code, Value* fiber = nullptr) {
        StoreInst* store = b.CreateStore(ConstantInt::get(I64_, bpf::ExitWordValue(code)), ExitWordPtr(b, fiber));
        store->setMetadata("bpf.capsule.exit.store", MDNode::get(Ctx_, {}));
    }

    // Convert a byte SP inside one fiber stack into an ordinary pointer in the
    // program's unified flat memory. MemoryPass later turns this into an arena
    // pointer on 6.9 or a scalar virtual address routed through maps on 5.15.
    Value* StackPtr(IRBuilder<>& b, Value* offset, Value* fiber = nullptr) {
        Value* normalizedFiber = NormalizeFiber(b, fiber ? fiber : CurrentFiberValue(b));
        Value* normalized = b.CreateZExtOrTrunc(offset, I64_);
        normalized = b.CreateAnd(normalized, ConstantInt::get(I64_, FiberStackSize_ - 1), "stack.offset");
        Value* linear =
            b.CreateAdd(b.CreateMul(b.CreateZExt(normalizedFiber, I64_), ConstantInt::get(I64_, FiberStackSize_)), normalized, "stack.linear.offset");
        return b.CreateGEP(I8_, Stack_, {linear}, "fiber.stack");
    }

    Value* EncodeStackCursor(IRBuilder<>& b, Value* sp) {
        // Zero is the public idle value. Encode a live SP as SP+1 instead of
        // spending the high bit: all frames and SPs are 16-byte aligned, so a
        // subtract that underflows cannot wrap this value to zero. Values
        // 1..StackLimit are live, StackLimit+1 is completed, and anything
        // larger is rejected by the trampoline. Besides being simpler, the
        // small constants avoid two-instruction 64-bit immediates in every
        // tiny Capsule program.
        return b.CreateAdd(b.CreateZExtOrTrunc(sp, I64_), ConstantInt::get(I64_, 1), "stack.cursor");
    }

    Value* DecodeStackCursor(IRBuilder<>& b, Value* cursor) {
        return b.CreateSub(cursor, ConstantInt::get(I64_, 1), "stack.sp");
    }

    Constant* CompletedStackCursor() {
        return ConstantInt::get(I64_, StackLimit_ + 1);
    }

    void LoadTopFrame(IRBuilder<>& b, Value* fiber, Value*& sp, Value*& frame) {
        Value* cursor = b.CreateLoad(I64_, StackCursorPtr(b, fiber), "stack.cursor");
        sp = DecodeStackCursor(b, cursor);
        frame = StackPtr(b, sp, fiber);
    }

    Value* FrameResultPtr(IRBuilder<>& b, Value* frame, uint64_t frameSize, uint64_t returnSize) {
        if (!returnSize || returnSize > frameSize) {
            report_fatal_error("stackify: invalid frame result layout");
        }
        return b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, frameSize - returnSize)}, "frame.result");
    }

    // ------------------------------------------------------------ transform

    void TransformFunction(ManagedFunction& info) {
        Function& func = *info.Original;
        Function* step = info.Stage;

        // Find the backedges before the body moves: afterwards the blocks
        // belong to the group function and its CFG is a different shape.
        SmallVector<Backedge> backedges = Backedges(func);

        // Move the body into the group function. Its blocks keep their own
        // debug locations, rewritten to look like an inline of the original
        // function into the group — the group owns the only DISubprogram.
        BasicBlock* origEntry = &func.getEntryBlock();
        SmallVector<BasicBlock*> body;
        for (auto&& block : func) {
            body.push_back(&block);
        }
        step->splice(step->end(), &func);

        auto* entry = BasicBlock::Create(Ctx_, func.getName() + ".entry", step, origEntry);
        info.Entry = entry;

        DebugLoc debugLoc;
        if (auto* sp = func.getSubprogram()) {
            debugLoc = DILocation::get(Ctx_, 0, 0, sp);
        }

        IRBuilder<> b(entry);
        Value* sp = nullptr;
        Value* frame = nullptr;
        LoadTopFrame(b, nullptr, sp, frame);
        info.Sp = sp;
        info.Frame = frame;
        info.States.push_back({info.EntryPc, origEntry});

        // Allocas become fixed slots inside this frame.
        SmallVector<AllocaInst*> allocas;
        for (auto* block : body) {
            for (auto&& inst : *block) {
                if (auto* a = dyn_cast<AllocaInst>(&inst)) {
                    if (!NativeHelperAllocas_.contains(a)) {
                        allocas.push_back(a);
                    }
                }
            }
        }
        for (auto* alloca : allocas) {
            auto found = info.AllocaOffsets.find(alloca);
            if (found == info.AllocaOffsets.end()) {
                report_fatal_error("stackify: alloca is missing from its frame layout");
            }

            SmallVector<Instruction*> lifetimes;
            for (auto* u : alloca->users()) {
                if (auto* ii = dyn_cast<IntrinsicInst>(u); ii && ii->isLifetimeStartOrEnd()) {
                    lifetimes.push_back(ii);
                }
            }
            for (auto* lt : lifetimes) {
                lt->eraseFromParent();
            }
            ReplaceAllocaUses(*alloca, frame, found->second, debugLoc);
            alloca->eraseFromParent();
        }

        // Arguments are reloaded from the frame at each use, so they never
        // need to survive a suspension.
        for (auto&& [idx, arg] : enumerate(func.args())) {
            ReplaceArgumentUses(arg, frame, info.ArgOffsets[idx], debugLoc);
        }

        // A semantic tail call replaces the current continuation frame rather
        // than pushing another one. This is required for threaded
        // interpreters (wasm3's next opcode is a tail call), where treating
        // every opcode as ordinary recursion makes stack use grow with the
        // guest instruction count. Identify these while the source returns
        // are still present; ordinary return lowering destroys that shape.
        SmallVector<CallBase*> calls;
        SmallVector<CallBase*> yields;
        for (auto* block : body) {
            for (auto&& inst : *block) {
                if (auto* call = dyn_cast<CallBase>(&inst)) {
                    if (IsManagedCall(call)) {
                        calls.push_back(call);
                    } else if (IsYieldCall(call)) {
                        yields.push_back(call);
                    }
                }
            }
        }

        SmallVector<CallBase*> ordinaryCalls;
        for (CallBase* call : calls) {
            if (!LowerTailCall(call, frame, sp, info.FrameSize, debugLoc)) {
                ordinaryCalls.push_back(call);
            }
        }

        // Returns pop the frame. Lower them before splitting at ordinary
        // calls, or a return sharing a block with a call would end up in a
        // resume block that is no longer part of `body`.
        SmallVector<ReturnInst*> returns;
        for (auto* block : body) {
            if (auto* ret = dyn_cast_or_null<ReturnInst>(block->getTerminator()); ret && !ret->getMetadata("bpf.tail.call")) {
                returns.push_back(ret);
            }
        }
        for (auto* ret : returns) {
            LowerReturn(ret, frame, sp, info.FrameSize, debugLoc);
        }

        // Physical partition edges first, for the same reason backedges go
        // before calls: they only redirect terminators, so captured call sites
        // remain valid.  Each target needs one PC, but each incoming cut gets
        // its own suspension block so unrelated source partitions do not
        // become connected through a shared block.
        DenseMap<BasicBlock*, uint32_t> cutPc;
        for (auto cut : info.CutEdges) {
            uint32_t& resumePc = cutPc[cut.To];
            if (resumePc == 0) {
                resumePc = NextPc_++;
                info.States.push_back({resumePc, cut.To});
            }

            auto* suspend = BasicBlock::Create(Ctx_, cut.From->getName() + ".partition.suspend", step);
            IRBuilder<> sb(suspend);
            sb.CreateStore(ConstantInt::get(I32_, resumePc), sb.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}))->setDebugLoc(debugLoc);
            sb.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
            cut.From->getTerminator()->replaceSuccessorWith(cut.To, suspend);
        }

        for (auto&& edge : backedges) {
            uint32_t resumePc = NextPc_++;
            BasicBlock* root = edge.ChunkTrips ? SuspendAtChunkedBackedge(edge, frame, resumePc, debugLoc) : SuspendAtBackedge(edge, frame, resumePc, debugLoc);
            info.States.push_back({resumePc, root});
        }
        for (auto* call : ordinaryCalls) {
            uint32_t resumePc = NextPc_++;
            info.States.push_back({resumePc, SuspendAtCall(call, frame, sp, resumePc, debugLoc)});
        }
        for (auto* call : yields) {
            uint32_t resumePc = NextPc_++;
            info.States.push_back({resumePc, SuspendAtYield(call, frame, resumePc, debugLoc)});
        }

        // This branch only keeps the staging function structurally complete.
        // Physical group dispatch replaces it after region formation.
        b.SetInsertPoint(entry);
        b.CreateBr(origEntry)->setDebugLoc(debugLoc);

        for (auto&& inst : *entry) {
            if (!inst.getDebugLoc()) {
                inst.setDebugLoc(debugLoc);
            }
        }
    }

    // Like arguments, frame-local pointers are materialized where used.  A
    // single GEP in the staging entry could not be shared after regions move
    // into different physical functions.
    void ReplaceAllocaUses(AllocaInst& alloca, Value* frame, uint64_t offset, DebugLoc debugLoc) {
        DenseMap<BasicBlock*, Value*> phiSlots;
        auto slotAt = [&](BasicBlock::iterator at) {
            IRBuilder<> b(at->getParent(), at);
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, offset)}, alloca.getName() + ".slot");
            if (auto* inst = dyn_cast<Instruction>(slot)) {
                inst->setDebugLoc(debugLoc);
            }
            return slot;
        };
        for (Use& use : make_early_inc_range(alloca.uses())) {
            auto* user = cast<Instruction>(use.getUser());
            if (auto* phi = dyn_cast<PHINode>(user)) {
                BasicBlock* pred = phi->getIncomingBlock(use);
                Value*& cached = phiSlots[pred];
                if (!cached) {
                    cached = slotAt(pred->getTerminator()->getIterator());
                }
                use.set(cached);
            } else {
                use.set(slotAt(user->getIterator()));
            }
        }
    }

    void ReplaceArgumentUses(Argument& arg, Value* frame, uint64_t offset, DebugLoc debugLoc) {
        // A PHI may hold several entries for one predecessor (a switch with
        // many cases to one target), and the verifier requires them to carry
        // the same value — so reloads feeding PHIs are cached per incoming
        // block rather than created per use.
        DenseMap<BasicBlock*, Value*> phiReloads;
        if (arg.hasAttribute("bpf.capsule.borrowed")) {
            auto currentAt = [&](BasicBlock::iterator at) -> Value* {
                IRBuilder<> b(at->getParent(), at);
                auto* value = b.CreateCall(BorrowedCurrent_, {}, arg.getName());
                value->setDebugLoc(debugLoc);
                return value;
            };
            for (Use& use : make_early_inc_range(arg.uses())) {
                auto* user = cast<Instruction>(use.getUser());
                if (auto* phi = dyn_cast<PHINode>(user)) {
                    BasicBlock* pred = phi->getIncomingBlock(use);
                    Value*& cached = phiReloads[pred];
                    if (!cached) {
                        cached = currentAt(pred->getTerminator()->getIterator());
                    }
                    use.set(cached);
                } else {
                    use.set(currentAt(user->getIterator()));
                }
            }
            return;
        }
        auto reloadAt = [&](BasicBlock::iterator at) {
            IRBuilder<> b(at->getParent(), at);
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, offset)});
            auto* value = b.CreateLoad(arg.getType(), slot, arg.getName());
            value->setDebugLoc(debugLoc);
            return value;
        };
        for (auto&& use : make_early_inc_range(arg.uses())) {
            auto* user = cast<Instruction>(use.getUser());
            if (auto* phi = dyn_cast<PHINode>(user)) {
                BasicBlock* pred = phi->getIncomingBlock(use);
                Value*& cached = phiReloads[pred];
                if (!cached) {
                    cached = reloadAt(pred->getTerminator()->getIterator());
                }
                use.set(cached);
                continue;
            }
            use.set(reloadAt(user->getIterator()));
        }
    }

    struct TailForward {
        PHINode* Phi = nullptr;
    };

    // Recognize the canonical forms left by LLVM for a value returned
    // directly from a call:
    //
    //   %v = call ...       %v = call ...
    //   ret %v              br merge; merge: %r = phi [%v, ...]; ret %r
    //
    // Debug and lifetime intrinsics are transparent. The second form is
    // common when each side of a source conditional invokes the next
    // threaded-interpreter opcode. Restricting this to exact forwarding keeps
    // it semantic: LLVM's permissive `tail` marker alone is not enough (it is
    // also attached to calls whose result is inspected by the caller).
    std::optional<TailForward> FindTailForward(CallBase* call) {
        // Direct tail calls already have a finite static call graph and the
        // ordinary continuation lowering is correct for them. Keep this
        // first implementation on the case that cannot otherwise be bounded:
        // indirect threaded dispatch. Direct frame reuse will be enabled once
        // its allocator/return-value conformance cases are independently
        // covered.
        if (call->getCalledFunction()) {
            return std::nullopt;
        }
        auto nextReal = [](Instruction* inst) -> Instruction* {
            for (Instruction* next = inst->getNextNode(); next; next = next->getNextNode()) {
                auto* intrinsic = dyn_cast<IntrinsicInst>(next);
                if (isa<DbgInfoIntrinsic>(next) || (intrinsic && intrinsic->isLifetimeStartOrEnd())) {
                    continue;
                }
                return next;
            }
            return nullptr;
        };

        Instruction* next = nextReal(call);
        if (auto* ret = dyn_cast_or_null<ReturnInst>(next)) {
            if ((call->getType()->isVoidTy() && !ret->getReturnValue()) || ret->getReturnValue() == call) {
                return TailForward{};
            }
            return std::nullopt;
        }

        auto* branch = dyn_cast_or_null<BranchInst>(next);
        if (!branch || !branch->isUnconditional()) {
            return std::nullopt;
        }
        BasicBlock* merge = branch->getSuccessor(0);
        PHINode* forwarding = nullptr;
        for (User* user : call->users()) {
            auto* phi = dyn_cast<PHINode>(user);
            if (!phi || phi->getParent() != merge || phi->getIncomingValueForBlock(call->getParent()) != call) {
                continue;
            }
            if (forwarding) {
                return std::nullopt;
            }
            forwarding = phi;
        }
        if (!forwarding) {
            return std::nullopt;
        }

        Instruction* mergeNext = &*merge->getFirstNonPHIIt();
        if (mergeNext != merge->getTerminator()) {
            // Skip the same transparent intrinsics at the merge head.
            mergeNext = nextReal(mergeNext->getPrevNode());
        }
        auto* ret = dyn_cast_or_null<ReturnInst>(mergeNext);
        if (!ret || ret->getReturnValue() != forwarding) {
            return std::nullopt;
        }
        return TailForward{forwarding};
    }

    bool LowerTailCall(CallBase* call, Value* frame, Value* sp, uint64_t callerFrameSize, DebugLoc debugLoc) {
        std::optional<TailForward> forward = FindTailForward(call);
        if (!forward) {
            return false;
        }

        BasicBlock* block = call->getParent();
        SmallVector<Instruction*> erase;
        for (Instruction* inst = call; inst; inst = inst->getNextNode()) {
            erase.push_back(inst);
        }

        IRBuilder<> b(call);
        Value* calleePc = CalleePc(b, call);
        auto equalizedClass = EqualFrameTailCalls_.find(call);
        bool equalized = equalizedClass != EqualFrameTailCalls_.end();
        Value* calleeSize = nullptr;
        Value* validSize = nullptr;
        if (equalized) {
            uint32_t tailClass = equalizedClass->second;
            Value* relative = b.CreateSub(calleePc, ConstantInt::get(I32_, TailClassFirst_[tailClass]), "tail.class.offset");
            validSize = b.CreateICmpULT(relative, ConstantInt::get(I32_, TailClassMembers_[tailClass]), "tail.class.valid");
        } else {
            calleeSize = CalleeFrameSize(b, call, calleePc);
            validSize = b.CreateICmpNE(calleeSize, ConstantInt::get(I64_, 0));
        }
        Value* valid = validSize;
        Value* upper = nullptr;
        if (!equalized) {
            upper = b.CreateAdd(sp, ConstantInt::get(I64_, callerFrameSize), "tail.frame.end");
        }
        auto* commit = BasicBlock::Create(Ctx_, block->getName() + ".tail", block->getParent());
        auto* overflow = BasicBlock::Create(Ctx_, block->getName() + ".tail.overflow", block->getParent());
        b.CreateCondBr(valid, commit, overflow);

        IRBuilder<> cb(commit);
        Value* nextSp = sp;
        Value* calleeFrame = frame;
        if (!equalized) {
            nextSp = cb.CreateSub(upper, calleeSize, "tail.sp");
            calleeFrame = StackPtr(cb, nextSp);
        }
        InitializeFrame(cb, calleeFrame, call, calleePc);
        if (!equalized) {
            cb.CreateStore(EncodeStackCursor(cb, nextSp), StackCursorPtr(cb));
        }
        auto* ret = cb.CreateRet(ConstantInt::get(I32_, ActionContinue));
        ret->setDebugLoc(call->getDebugLoc() ? call->getDebugLoc() : debugLoc);
        ret->setMetadata("bpf.tail.call", MDNode::get(Ctx_, {}));

        IRBuilder<> ob(overflow);
        EmitAbort(ob, CAPSULE_ERROR_STACK_OVERFLOW);
        ob.CreateRet(ConstantInt::get(I32_, ActionContinue));

        if (forward->Phi) {
            forward->Phi->removeIncomingValue(block, /*DeletePHIIfEmpty=*/false);
        }
        for (Instruction* inst : reverse(erase)) {
            inst->dropDbgRecords();
            inst->eraseFromParent();
        }
        block->deleteTrailingDbgRecords();
        TailCallsLowered_++;
        return true;
    }

    // Split the block at `call`, push the callee's frame and return to the
    // trampoline; the remainder of the block becomes the resume target.
    BasicBlock* SuspendAtCall(CallBase* call, Value* frame, Value* sp, uint32_t resumePc, DebugLoc debugLoc) {
        BasicBlock* block = call->getParent();
        BasicBlock* resume = block->splitBasicBlock(call, block->getName() + ".resume");

        // block now ends with an unconditional branch into `resume`.
        Instruction* br = block->getTerminator();
        IRBuilder<> b(br);

        Value* calleePc = CalleePc(b, call);
        Value* calleeSize = CalleeFrameSize(b, call, calleePc);
        Value* validSize = b.CreateICmpNE(calleeSize, ConstantInt::get(I64_, 0));
        auto* push = BasicBlock::Create(Ctx_, block->getName() + ".push", block->getParent(), resume);
        auto* overflow = BasicBlock::Create(Ctx_, block->getName() + ".overflow", block->getParent(), resume);
        b.CreateCondBr(validSize, push, overflow);
        br->eraseFromParent();

        IRBuilder<> ob(overflow);
        EmitAbort(ob, CAPSULE_ERROR_STACK_OVERFLOW);
        ob.CreateRet(ConstantInt::get(I32_, ActionContinue));

        b.SetInsertPoint(push);
        Value* nextSp = b.CreateSub(sp, calleeSize, "callee.sp");
        auto* calleeFrame = StackPtr(b, nextSp);
        InitializeFrame(b, calleeFrame, call, calleePc);

        b.CreateStore(ConstantInt::get(I32_, resumePc), b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}));
        b.CreateStore(EncodeStackCursor(b, nextSp), StackCursorPtr(b));
        b.CreateRet(ConstantInt::get(I32_, ActionContinue));

        // The result is immediately below the caller frame. This upper frame
        // boundary is invariant even if the callee tail-called another
        // function with a different frame size.
        IRBuilder<> rb(call);
        if (!call->getType()->isVoidTy()) {
            uint64_t returnSize = Module_.getDataLayout().getTypeAllocSize(call->getType()).getFixedValue();
            Value* result = rb.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, -int64_t(returnSize))}, "completed.callee.result");
            call->replaceAllUsesWith(rb.CreateLoad(call->getType(), result, "callret"));
        }
        call->eraseFromParent();

        for (auto&& inst : *block) {
            if (!inst.getDebugLoc()) {
                inst.setDebugLoc(debugLoc);
            }
        }
        return resume;
    }

    // A voluntary yield preserves the current frame and returns control to the
    // native caller. Unlike a managed call it pushes nothing: continuation
    // resumes at the instruction immediately following the marker.
    BasicBlock* SuspendAtYield(CallBase* call, Value* frame, uint32_t resumePc, DebugLoc debugLoc) {
        BasicBlock* block = call->getParent();
        BasicBlock* resume = block->splitBasicBlock(call, block->getName() + ".yield.resume");
        Instruction* branch = block->getTerminator();

        IRBuilder<> b(branch);
        b.CreateStore(ConstantInt::get(I32_, resumePc), b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}))->setDebugLoc(debugLoc);
        b.CreateStore(ConstantInt::get(I64_, CAPSULE_YIELD), ExitWordPtr(b))->setDebugLoc(debugLoc);
        b.CreateRet(ConstantInt::get(I32_, ActionYield))->setDebugLoc(debugLoc);
        branch->eraseFromParent();
        call->eraseFromParent();
        return resume;
    }

    // For a direct call the id is a constant; for an indirect one the called
    // value already holds it, because every address-of use of a managed
    // function was replaced by its id.
    Value* CalleePc(IRBuilder<>& b, CallBase* call) {
        if (Function* callee = call->getCalledFunction()) {
            return ConstantInt::get(I32_, ManagedByFunction_.lookup(callee)->EntryPc);
        }
        Value* token = b.CreatePtrToInt(call->getCalledOperand(), I64_, "callee.token");
        return b.CreateTrunc(b.CreateSub(token, ConstantInt::get(I64_, BPF_CAPSULE_FUNCTION_TOKEN_BASE)), I32_, "callee.pc");
    }

    // Replace the branch back to the header with "record where to resume, then
    // return". The trampoline re-enters this same frame, the entry dispatch
    // jumps to the header, and the loop makes one more iteration — without a
    // backedge ever existing in the BPF program.
    BasicBlock* SuspendAtBackedge(const Backedge& edge, Value* frame, uint32_t resumePc, DebugLoc debugLoc) {
        Instruction* term = edge.Latch->getTerminator();

        IRBuilder<> b(term);
        auto* store = b.CreateStore(ConstantInt::get(I32_, resumePc), b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}));
        store->setDebugLoc(debugLoc);

        // The latch may branch to the header conditionally; only the edge back
        // to the header becomes a return, so give it a block of its own.
        auto* suspend = BasicBlock::Create(Ctx_, edge.Latch->getName() + ".suspend", edge.Latch->getParent());
        IRBuilder<> sb(suspend);
        sb.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);

        term->replaceSuccessorWith(edge.Header, suspend);
        return edge.Header;
    }

    // Finish a chunk prepared before frame layout.  The boundary already
    // stores its loop-carried next values and the resume block reloads them;
    // replace the temporary cyclic edge by a real continuation return.
    BasicBlock* SuspendAtChunkedBackedge(const Backedge& edge, Value* frame, uint32_t resumePc, DebugLoc debugLoc) {
        Instruction* term = edge.Latch->getTerminator();
        IRBuilder<> builder(term);
        builder.CreateStore(ConstantInt::get(I32_, resumePc), builder.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}))->setDebugLoc(debugLoc);
        builder.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
        term->eraseFromParent();

        BasicBlock* resume = ChunkResumes_.lookup(edge.Header);
        if (!resume) {
            report_fatal_error("stackify: chunk has no prepared resume block");
        }
        return resume;
    }

    void StoreCallArguments(IRBuilder<>& b, Value* frame, CallBase* call) {
        Function* callee = call->getCalledFunction();
        for (unsigned i = 0; i < call->arg_size(); i++) {
            // Verifier-owned pointers (XDP ctx today) are threaded through the
            // typed native driver. They may never be spilled into a map or the
            // arena: doing so destroys PTR_TO_CTX provenance and is rejected.
            if (callee && i < callee->arg_size() && callee->getArg(i)->hasAttribute("bpf.capsule.borrowed")) {
                continue;
            }
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, ArgsOffset_ + i * ArgSlotSize_)});
            b.CreateStore(call->getArgOperand(i), slot);
        }
    }

    Value* CalleeFrameSize(IRBuilder<>& b, CallBase* call, Value* pc = nullptr) {
        if (Function* callee = call->getCalledFunction()) {
            ManagedFunction* info = ManagedByFunction_.lookup(callee);
            if (!info || !info->FrameSize) {
                report_fatal_error("stackify: direct callee has no frame layout");
            }
            return ConstantInt::get(I64_, info->FrameSize);
        }

        if (!pc) {
            pc = CalleePc(b, call);
        }
        uint64_t count = cast<ArrayType>(FrameSizeTable_->getValueType())->getNumElements();
        Value* valid = b.CreateICmpULT(pc, ConstantInt::get(I32_, count), "callee.pc.valid");
        // The selected zero index keeps the memory access valid even for a
        // forged function value.  Slot zero contains size zero, which the
        // caller treats as an invalid target and aborts before pushing.
        Value* safePc = b.CreateSelect(valid, pc, ConstantInt::get(I32_, 0), "callee.pc.safe");
        Value* slot = b.CreateInBoundsGEP(FrameSizeTable_->getValueType(), FrameSizeTable_, {ConstantInt::get(I64_, 0), b.CreateZExt(safePc, I64_)});
        return b.CreateZExt(b.CreateLoad(I32_, slot, "callee.frame.size"), I64_);
    }

    void InitializeFrame(IRBuilder<>& b, Value* frame, CallBase* call, Value* pc = nullptr) {
        b.CreateStore(pc ? pc : CalleePc(b, call), b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}));
        StoreCallArguments(b, frame, call);
    }

    void LowerReturn(ReturnInst* ret, Value* frame, Value* sp, uint64_t frameSize, DebugLoc debugLoc) {
        IRBuilder<> b(ret);
        if (Value* value = ret->getReturnValue()) {
            uint64_t returnSize = Module_.getDataLayout().getTypeAllocSize(value->getType()).getFixedValue();
            b.CreateStore(value, FrameResultPtr(b, frame, frameSize, returnSize));
        }
        Value* callerSp = b.CreateAdd(sp, ConstantInt::get(I64_, frameSize), "caller.sp");
        b.CreateStore(EncodeStackCursor(b, callerSp), StackCursorPtr(b));
        auto* newRet = b.CreateRet(ConstantInt::get(I32_, ActionContinue));
        newRet->setDebugLoc(ret->getDebugLoc() ? ret->getDebugLoc() : debugLoc);
        ret->eraseFromParent();
    }

    // ----------------------------------------------------------- trampoline

    // One dispatch of the software stack's top frame. It reports completion
    // when the stack drains; exhausting the bounded driver remains pending.
    Function* BuildStepFunction(bool borrowed, Function* decl = nullptr) {
        StringRef name = borrowed ? "__bpf_capsule_trampoline_ctx_step" : "__bpf_capsule_trampoline_step";
        SmallVector<Type*> parameters;
        if (borrowed) {
            parameters.push_back(PointerType::get(Ctx_, 0));
        }
        parameters.push_back(I32_);
        parameters.push_back(PointerType::get(Ctx_, 0));
        if (!bpf::UseArena()) {
            parameters.push_back(PointerType::get(Ctx_, 0));
        }
        auto* step = Function::Create(FunctionType::get(I32_, parameters, false), Function::ExternalLinkage, name, Module_);
        step->setCallingConv(CallingConv::C);
        step->addFnAttr(Attribute::NoInline);
        if (borrowed) {
            step->getArg(0)->setName("ctx");
            step->addParamAttr(0, Attribute::get(Ctx_, "bpf.capsule.borrowed"));
        }
        Value* fiber = step->getArg(FiberArgumentIndex(borrowed));
        fiber->setName("fiber");
        Value* fiberControl = step->getArg(ControlArgumentIndex(borrowed));
        fiberControl->setName("fiber_control");
        step->addParamAttr(ControlArgumentIndex(borrowed), Attribute::get(Ctx_, "bpf.capsule.control"));
        NativeFiberControls_[step] = fiberControl;
        Value* stackBacking = nullptr;
        if (!bpf::UseArena()) {
            stackBacking = step->getArg(StackRegionArgumentIndex(borrowed));
            stackBacking->setName("stack_base");
            step->addParamAttr(StackRegionArgumentIndex(borrowed), Attribute::get(Ctx_, "bpf.capsule.stack.backing"));
        }

        // Create the optional diagnostic storage after region planning.  A
        // driver should not have to declare this implementation detail, and
        // injecting it into input IR before optimization can perturb global
        // layout (which defeats a diagnostic intended to explain a specific
        // execution).  Its own map also keeps production .data maps unchanged.
        GlobalVariable* histogram = nullptr;
        if (StepHistogram) {
            histogram = Module_.getGlobalVariable("bpf_step_hist");
            if (!histogram) {
                auto* type = ArrayType::get(I64_, 4096);
                histogram = new GlobalVariable(Module_, type, false, GlobalValue::ExternalLinkage, ConstantAggregateZero::get(type), "bpf_step_hist");
                histogram->setSection(".bss.statshist");
                histogram->setAlignment(Align(8));
            }
        }

        auto* entry = BasicBlock::Create(Ctx_, "entry", step);
        auto* route = BasicBlock::Create(Ctx_, "route", step);
        auto* dispatch = BasicBlock::Create(Ctx_, "dispatch", step);
        auto* validate = BasicBlock::Create(Ctx_, "validate", step);
        auto* terminal = BasicBlock::Create(Ctx_, "terminal", step);
        auto* completed = BasicBlock::Create(Ctx_, "completed", step);
        auto* done = BasicBlock::Create(Ctx_, "done", step);
        auto* overflow = BasicBlock::Create(Ctx_, "stack.overflow", step);
        auto* trap = BasicBlock::Create(Ctx_, "bad.id", step);

        IRBuilder<> b(entry);
        auto* controlReady = BasicBlock::Create(Ctx_, "control.ready", step, route);
        auto* controlMissing = BasicBlock::Create(Ctx_, "control.missing", step, route);
        b.CreateCondBr(b.CreateICmpNE(fiberControl, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), controlReady, controlMissing);
        IRBuilder<> cmb(controlMissing);
        cmb.CreateRet(ConstantInt::get(I32_, 1));
        b.SetInsertPoint(controlReady);
        if (stackBacking) {
            auto* ready = BasicBlock::Create(Ctx_, "stack.ready", step, route);
            auto* missing = BasicBlock::Create(Ctx_, "stack.missing", step, route);
            b.CreateCondBr(b.CreateICmpNE(stackBacking, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), ready, missing);
            IRBuilder<> mb(missing);
            EmitAbort(mb, CAPSULE_ERROR_MEMORY_FAULT, fiber);
            mb.CreateRet(ConstantInt::get(I32_, 1));
            b.SetInsertPoint(ready);
        }
        Value* cursorSlot = StackCursorPtr(b, fiber);
        Value* cursor = b.CreateLoad(I64_, cursorSlot, "stack.cursor");
        Value* sp = DecodeStackCursor(b, cursor);
        if (stackBacking) {
            Value* abort = ExitWordPtr(b, fiber);
            auto* anchor = InlineAsm::get(
                FunctionType::get(Type::getVoidTy(Ctx_), {stackBacking->getType(), I64_, abort->getType()}, false), "# bpf_capsule_stack_anchor", "r,r,r",
                /*hasSideEffects=*/true
            );
            b.CreateCall(anchor, {stackBacking, sp, abort});
        }
        Value* isCompleted = b.CreateICmpEQ(cursor, CompletedStackCursor());
        Value* hasExited = b.CreateICmpNE(b.CreateLoad(I64_, ExitWordPtr(b, fiber)), ConstantInt::get(I64_, 0));
        Value* stopped = b.CreateOr(b.CreateICmpEQ(cursor, ConstantInt::get(I64_, 0)), b.CreateOr(isCompleted, hasExited));
        b.CreateCondBr(stopped, terminal, validate);

        b.SetInsertPoint(terminal);
        b.CreateCondBr(isCompleted, completed, done);

        b.SetInsertPoint(completed);
        b.CreateStore(ConstantInt::get(I64_, 0), cursorSlot);
        b.CreateBr(done);

        b.SetInsertPoint(validate);
        b.CreateCondBr(b.CreateICmpULE(cursor, ConstantInt::get(I64_, StackLimit_)), route, overflow);

        b.SetInsertPoint(done);
        b.CreateRet(ConstantInt::get(I32_, 1)); // stop iterating

        b.SetInsertPoint(overflow);
        EmitAbort(b, CAPSULE_ERROR_STACK_OVERFLOW, fiber);
        b.CreateRet(ConstantInt::get(I32_, 1));

        b.SetInsertPoint(route);
        Value* frame = StackPtr(b, sp, fiber);
        auto* pc = b.CreateLoad(I32_, b.CreateGEP(I8_, frame, {ConstantInt::get(I64_, PcOffset)}), "pc");
        b.CreateCondBr(b.CreateICmpULT(pc, ConstantInt::get(I32_, NextPc_)), dispatch, trap);

        b.SetInsertPoint(dispatch);
        auto* groupSlot = b.CreateInBoundsGEP(PcGroupTable_->getValueType(), PcGroupTable_, {ConstantInt::get(I64_, 0), b.CreateZExt(pc, I64_)});
        auto* groupId = b.CreateLoad(I8_, groupSlot, "physical.group");
        // Off by default: the index is variable, and the verifier explores it
        // per dispatch path, which costs more than the whole million-insn
        // budget for the entry program.
        if (auto* hist = histogram) {
            uint64_t size = cast<ArrayType>(hist->getValueType())->getNumElements();
            auto* index = b.CreateAnd(b.CreateZExt(pc, I64_), ConstantInt::get(I64_, size - 1));
            auto* slot = b.CreateGEP(hist->getValueType(), hist, {ConstantInt::get(I64_, 0), index});
            b.CreateStore(b.CreateAdd(b.CreateLoad(I64_, slot), ConstantInt::get(I64_, 1)), slot);
        }
        auto* sw = b.CreateSwitch(groupId, trap, Groups_.size());
        for (auto&& group : Groups_) {
            if (group.BorrowedContext && !borrowed) {
                continue;
            }
            auto* caseBlock = BasicBlock::Create(Ctx_, group.Func->getName(), step, done);
            IRBuilder<> cb(caseBlock);
            SmallVector<Value*, 4> arguments;
            if (group.BorrowedContext) {
                arguments.push_back(step->getArg(0));
            }
            arguments.push_back(fiber);
            arguments.push_back(fiberControl);
            if (stackBacking) {
                arguments.push_back(stackBacking);
            }
            Value* action = cb.CreateCall(group.Func, arguments);
            cb.CreateRet(cb.CreateZExt(cb.CreateICmpEQ(action, ConstantInt::get(I32_, ActionYield)), I32_));
            unsigned groupIndex = unsigned(&group - Groups_.data());
            sw->addCase(ConstantInt::get(cast<IntegerType>(I8_), groupIndex), caseBlock);
        }

        b.SetInsertPoint(trap);
        b.CreateCall(GetExitSetter(), {fiber, ConstantInt::get(I64_, CAPSULE_ERROR_INVALID_DISPATCH)});
        b.CreateRet(ConstantInt::get(I32_, 1));

        if (!Module_.debug_compile_units().empty()) {
            DIBuilder debugBuilder(Module_, false, *Module_.debug_compile_units_begin());
            SmallVector<Metadata*> signature{BtfGetInt(debugBuilder, 32, true)};
            if (borrowed) {
                signature.push_back(BorrowedDebugType_);
            }
            signature.push_back(BtfGetInt(debugBuilder, 32, false));
            auto* controlByteType = debugBuilder.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
            uint64_t controlBytes = Module_.getDataLayout().getTypeAllocSize(FiberControlType_);
            auto* controlSubrange = debugBuilder.getOrCreateSubrange(0, controlBytes);
            auto* controlType = debugBuilder.createArrayType(controlBytes * 8u, 8, controlByteType, debugBuilder.getOrCreateArray({controlSubrange}));
            signature.push_back(debugBuilder.createPointerType(controlType, 64));
            if (!bpf::UseArena()) {
                auto* byteType = debugBuilder.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
                auto* subrange = debugBuilder.getOrCreateSubrange(0, FiberStackSize_);
                auto* regionType = debugBuilder.createArrayType(uint64_t(FiberStackSize_) * 8u, 8, byteType, debugBuilder.getOrCreateArray({subrange}));
                signature.push_back(debugBuilder.createPointerType(regionType, 64));
            }
            BtfFunctionAddDebugInfo(debugBuilder, *step, signature);
            debugBuilder.finalize();
        }

        if (decl) {
            decl->replaceAllUsesWith(step);
            decl->eraseFromParent();
        }

        return step;
    }

    // The runtime supplies a two-level bounded driver. Runtime iterations
    // multiply while each global loop is verified only once.
    Function* BuildStepDriver(bool borrowed) {
        StringRef driverName = borrowed ? "__bpf_capsule_trampoline_ctx" : "__bpf_capsule_trampoline";
        StringRef levelName = borrowed ? "__bpf_capsule_trampoline_ctx_l1" : "__bpf_capsule_trampoline_l1";
        StringRef stepName = borrowed ? "__bpf_capsule_trampoline_ctx_step" : "__bpf_capsule_trampoline_step";
        Function* driver0 = Module_.getFunction(driverName);
        Function* level0 = Module_.getFunction(levelName);
        if (!driver0 || driver0->isDeclaration() || !level0 || level0->isDeclaration()) {
            report_fatal_error(Twine("stackify: program-supplied driver requires ") + driverName + " and " + levelName);
        }
        // The program declares this extern; take over the declaration rather
        // than creating a second, differently-named function beside it.
        Function* decl = Module_.getFunction(stepName);
        if (decl && !decl->isDeclaration()) {
            report_fatal_error(Twine("stackify: ") + stepName + " already defined");
        }
        if (decl) {
            decl->setName((Twine(stepName) + ".decl").str());
        }

        BuildStepFunction(borrowed, decl);
        return driver0;
    }

    void RemoveStepDriver(bool borrowed) {
        StringRef driverName = borrowed ? "__bpf_capsule_trampoline_ctx" : "__bpf_capsule_trampoline";
        StringRef levelName = borrowed ? "__bpf_capsule_trampoline_ctx_l1" : "__bpf_capsule_trampoline_l1";
        StringRef stepName = borrowed ? "__bpf_capsule_trampoline_ctx_step" : "__bpf_capsule_trampoline_step";
        Function* unusedDriver = Module_.getFunction(driverName);
        Function* unusedLevel = Module_.getFunction(levelName);
        Function* unusedStep = Module_.getFunction(stepName);

        // The typed pair is pinned in llvm.compiler.used until Stackify can
        // choose a driver.  That is a lifetime-retention reference, not an
        // executable use.  Drop it before deciding whether the other ABI is
        // genuinely called by an entry program and before erasing the pair.
        removeFromUsedLists(Module_, [&](Constant* value) {
            Value* target = value->stripPointerCasts();
            return target == unusedDriver || target == unusedLevel;
        });
        if (unusedDriver) {
            unusedDriver->removeDeadConstantUsers();
        }
        if (unusedLevel) {
            unusedLevel->removeDeadConstantUsers();
        }
        if (unusedDriver) {
            if (!unusedDriver->hasNUsesOrMore(1) || llvm::all_of(unusedDriver->users(), [](User* user) {
                    auto* call = dyn_cast<CallBase>(user);
                    return call && !IsEntryProgram(*call->getFunction());
                })) {
                unusedDriver->dropAllReferences();
                unusedDriver->eraseFromParent();
                unusedDriver = nullptr;
            } else {
                report_fatal_error(Twine("stackify: unused Capsule driver remains reachable: ") + driverName);
            }
        }
        if (unusedLevel && unusedLevel->use_empty()) {
            unusedLevel->dropAllReferences();
            unusedLevel->eraseFromParent();
        }
        if (unusedStep && unusedStep->use_empty()) {
            unusedStep->eraseFromParent();
        }
    }

    void BuildTrampoline() {
        bool scalarRoot = !BorrowedContext_;
        if (BorrowedContext_) {
            for (Function& function : Module_) {
                for (Instruction& instruction : instructions(function)) {
                    auto* call = dyn_cast<CallBase>(&instruction);
                    if (call && call->getOperandBundle("bpf.capsule.call") && call->getCalledFunction() != BorrowedFunction_) {
                        scalarRoot = true;
                    }
                }
            }
        }

        if (scalarRoot) {
            ScalarTrampoline_ = BuildStepDriver(false);
        } else {
            RemoveStepDriver(false);
        }
        if (BorrowedContext_) {
            BorrowedTrampoline_ = BuildStepDriver(true);
        } else {
            RemoveStepDriver(true);
        }
    }

    // Native code enters managed code only through an explicit capsule_call.
    // Ordinary calls in entries and their native helpers remain native BPF.
    void RewriteEntryPrograms() {
        for (auto&& func : Module_) {
            if (func.isDeclaration()) {
                continue;
            }
            SmallVector<CallBase*> calls;
            for (auto&& inst : instructions(func)) {
                if (auto* call = dyn_cast<CallBase>(&inst); call && call->getCalledFunction() && IsManagedCall(call)) {
                    calls.push_back(call);
                }
            }
            if (calls.empty()) {
                continue;
            }
            for (auto* call : calls) {
                if (!call->getOperandBundle("bpf.capsule.call")) {
                    Function* callee = call->getCalledFunction();
                    report_fatal_error(
                        Twine("stackify: native function ") + func.getName() + " calls Capsule function " + (callee ? callee->getName() : "indirectly") +
                        " without capsule_call"
                    );
                }
                RewriteEntryCall(call);
            }
        }
    }

    // A return value survives suspension in the root frame at the fixed upper
    // edge of the fiber stack. capsule_continue() has no source-level call to
    // identify that root, so its marker carries the destination's constant
    // size and alignment. Expand the copy here, where the final stack limit is
    // known. The 1/2/4/8-byte operations are exactly the shapes understood by
    // both arena memory and the old-kernel sharded-memory accessors.
    void RewriteReturnCopies() {
        Function* marker = Module_.getFunction("__bpf_capsule_copy_return");
        if (!marker) {
            return;
        }

        SmallVector<CallBase*> calls;
        for (User* user : marker->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledOperand()->stripPointerCasts() != marker) {
                report_fatal_error("stackify: address of __bpf_capsule_copy_return escapes");
            }
            calls.push_back(call);
        }

        for (CallBase* call : calls) {
            if (call->arg_size() != 4) {
                report_fatal_error("stackify: malformed Capsule return copy");
            }
            auto* sizeValue = dyn_cast<ConstantInt>(call->getArgOperand(2));
            auto* alignmentValue = dyn_cast<ConstantInt>(call->getArgOperand(3));
            if (!sizeValue || !alignmentValue || !isPowerOf2_64(alignmentValue->getZExtValue())) {
                report_fatal_error("stackify: Capsule return size and alignment must be constant");
            }
            uint64_t size = sizeValue->getZExtValue();
            uint64_t alignment = alignmentValue->getZExtValue();
            if (!size || size > StackLimit_) {
                report_fatal_error("stackify: invalid Capsule return size");
            }

            IRBuilder<> b(call);
            Value* fiber = NormalizeFiber(b, call->getArgOperand(0));
            Value* output = call->getArgOperand(1);
            Value* source = StackPtr(b, ConstantInt::get(I64_, StackLimit_ - size), fiber);
            uint64_t offset = 0;
            while (offset < size) {
                uint64_t width = std::min<uint64_t>(8, alignment);
                while (width > size - offset || offset % width) {
                    width >>= 1;
                }
                Type* type = IntegerType::get(Ctx_, width * 8);
                Value* sourcePart = b.CreateGEP(I8_, source, ConstantInt::get(I64_, offset));
                Value* outputPart = b.CreateGEP(I8_, output, ConstantInt::get(I64_, offset));
                Value* value = b.CreateAlignedLoad(type, sourcePart, Align(width));
                b.CreateAlignedStore(value, outputPart, Align(width));
                offset += width;
            }
            call->eraseFromParent();
        }

        if (marker->use_empty()) {
            marker->eraseFromParent();
        }
    }

    // BTF reports externally-linked functions as global subprograms, and the
    // verifier only accepts those with scalar arguments and return values.
    // Keep only generated runtime functions and proven scalar islands global;
    // every other leftover source function becomes static.
    void InternalizeOrdinaryFunctions() {
        SmallPtrSet<Function*, 8> keepGlobal;
        if (ScalarTrampoline_) {
            keepGlobal.insert(ScalarTrampoline_);
        }
        if (BorrowedTrampoline_) {
            keepGlobal.insert(BorrowedTrampoline_);
        }
        for (auto&& group : Groups_) {
            keepGlobal.insert(group.Func);
        }

        for (auto&& func : Module_) {
            if (func.isDeclaration() || IsEntryProgram(func) || keepGlobal.contains(&func) || func.getMetadata("bpf.native.scalar")) {
                continue;
            }
            // Same for the driver: a global subprogram is verified once and
            // not descended into, which is what lets the drive loops call it
            // thousands of times without exhausting the jump budget.
            if (func.getName().starts_with("__bpf_capsule_trampoline")) {
                continue;
            }
            // The heap accessors take and return scalars, so they qualify as
            // global subprograms — checked once each instead of re-walked at
            // every one of their tens of thousands of call sites.
            if (func.getName().starts_with("bpf_heap_") || func.getName().starts_with("bpf_stack_")) {
                continue;
            }
            func.setLinkage(GlobalValue::InternalLinkage);

            // BTF takes the linkage from the debug info, so the subprogram has
            // to be rebuilt as local-to-unit.
            auto* sp = func.getSubprogram();
            if (!sp || sp->isLocalToUnit()) {
                continue;
            }
            DIBuilder debugBuilder(Module_, false, sp->getUnit());
            auto* local = debugBuilder.createFunction(
                sp->getScope(), sp->getName(), sp->getLinkageName(), sp->getFile(), sp->getLine(), sp->getType(), sp->getScopeLine(), sp->getFlags(),
                sp->getSPFlags() | DISubprogram::SPFlagLocalToUnit
            );
            func.setSubprogram(local);
            RemapDebugLocations(func, *local);
            debugBuilder.finalize();
        }
    }

    // Rewrite every debug location in `func` so its outermost scope is `sp`.
    void RemapDebugLocations(Function& func, DISubprogram& sp) {
        DenseMap<const MDNode*, MDNode*> cache;
        for (auto&& block : func) {
            for (auto&& inst : block) {
                inst.dropDbgRecords();
                if (auto loc = inst.getDebugLoc()) {
                    inst.setDebugLoc(DebugLoc::replaceInlinedAtSubprogram(loc, sp, Ctx_, cache));
                }
                updateLoopMetadataDebugLocations(inst, [&](Metadata* md) -> Metadata* {
                    if (auto* loc = dyn_cast_or_null<DILocation>(md)) {
                        return DebugLoc::replaceInlinedAtSubprogram(loc, sp, Ctx_, cache);
                    }
                    return md;
                });
            }
        }
    }

    void RewriteEntryCall(CallBase* call) {
        IRBuilder<> b(call);

        std::optional<OperandBundleUse> boundary = call->getOperandBundle("bpf.capsule.call");
        if (!boundary || boundary->Inputs.size() != 1) {
            report_fatal_error("stackify: Capsule call boundary is missing its fiber ID");
        }
        Value* fiber = NormalizeFiber(b, boundary->Inputs[0].get());

        Function* callee = call->getCalledFunction();
        bool borrowsContext = callee == BorrowedFunction_;
        Value* borrowedContext = nullptr;
        if (borrowsContext) {
            if (BorrowedArgument_ >= call->arg_size()) {
                report_fatal_error("stackify: borrowed-context Capsule root is missing its context argument");
            }
            borrowedContext = call->getArgOperand(BorrowedArgument_);
        }

        ManagedFunction* root = ManagedByFunction_.lookup(call->getCalledFunction());
        if (!root || !root->FrameSize) {
            report_fatal_error("stackify: Capsule root has no frame layout");
        }
        uint64_t rootSp = StackLimit_ - root->FrameSize;
        Value* frame = StackPtr(b, ConstantInt::get(I64_, rootSp), fiber);
        b.CreateStore(ConstantInt::get(I64_, 0), ExitWordPtr(b, fiber));
        InitializeFrame(b, frame, call);
        b.CreateStore(ConstantInt::get(I64_, root->ReturnSize), ReturnSizePtr(b, fiber));
        b.CreateStore(ConstantInt::get(I64_, rootSp + 1), StackCursorPtr(b, fiber));
        if (borrowsContext) {
            if (!BorrowedTrampoline_) {
                report_fatal_error("stackify: borrowed-context Capsule root has no typed trampoline");
            }
            b.CreateCall(BorrowedTrampoline_, {borrowedContext, fiber});
        } else {
            if (!ScalarTrampoline_) {
                report_fatal_error("stackify: scalar Capsule root has no scalar trampoline");
            }
            b.CreateCall(ScalarTrampoline_, {fiber});
        }

        if (!call->getType()->isVoidTy()) {
            call->replaceAllUsesWith(b.CreateLoad(call->getType(), FrameResultPtr(b, frame, root->FrameSize, root->ReturnSize)));
        }
        call->eraseFromParent();
    }

    Module& Module_;
    LLVMContext& Ctx_;
    Type* I8_;
    Type* I32_;
    Type* I64_;

    // DemoteRegToStack may return null for a value made use-empty by another
    // demotion. Keep only real, function-owned compiler spill slots here:
    // source-memory loads must never be localized and re-executed after a
    // managed call. Per-function ownership also prevents stale instruction
    // addresses from being mistaken for slots in a later function.
    DenseMap<Function*, SmallPtrSet<AllocaInst*, 32>> DemotedSlots_;
    SmallPtrSet<AllocaInst*, 32> NativeHelperAllocas_;
    SmallVector<AllocaInst*> NativeHelperAllocaOrder_;
    SmallPtrSet<BasicBlock*, 32> NativeLoopHeaders_;
    SmallPtrSet<Function*, 32> NativeScalarFunctions_;
    DenseMap<CallBase*, uint32_t> EqualFrameTailCalls_;
    DenseMap<BasicBlock*, unsigned> ChunkTrips_;
    DenseMap<BasicBlock*, BasicBlock*> ChunkBoundaries_;
    DenseMap<BasicBlock*, BasicBlock*> ChunkResumes_;
    SmallVector<std::pair<Function*, std::unique_ptr<ManagedFunction>>> Managed_;
    DenseMap<Function*, ManagedFunction*> ManagedByFunction_;
    SmallVector<std::unique_ptr<Region>> Regions_;
    SmallVector<StepGroup> Groups_;
    uint32_t NextPc_ = 1;
    uint32_t TailClassCount_ = 0;
    SmallVector<uint32_t> TailClassFirst_;
    SmallVector<uint32_t> TailClassMembers_;

    uint64_t FiberStackSize_ = 0;
    uint64_t StackLimit_ = 0;
    unsigned TailCallsLowered_ = 0;
    uint64_t ArgsOffset_ = 0;
    uint64_t ArgSlotSize_ = 8;
    uint64_t FiberCount_ = 1;
    GlobalVariable* Stack_ = nullptr;
    GlobalVariable* FiberControls_ = nullptr;
    ArrayType* FiberControlsType_ = nullptr;
    StructType* FiberControlType_ = nullptr;
    GlobalVariable* FiberConfig_ = nullptr;
    StructType* FiberConfigType_ = nullptr;
    DenseMap<Function*, Value*> NativeFiberControls_;
    GlobalVariable* FrameSizeTable_ = nullptr;
    GlobalVariable* PcGroupTable_ = nullptr;
    Function* ScalarTrampoline_ = nullptr;
    Function* BorrowedTrampoline_ = nullptr;
    Function* CurrentFiber_ = nullptr;
    Function* ActiveFiberCount_ = nullptr;
    Function* YieldMarker_ = nullptr;
    Function* ExitWordAccessor_ = nullptr;
    Function* ExitSetter_ = nullptr;
    bool BorrowedContext_ = false;
    Function* BorrowedFunction_ = nullptr;
    unsigned BorrowedArgument_ = 0;
    Metadata* BorrowedDebugType_ = nullptr;
    Function* BorrowedCurrent_ = nullptr;
    bool YieldError_ = false;
    bool VerifierPointerError_ = false;
    bool InputError_ = false;
};

} // namespace

PreservedAnalyses Stackify::run(Module& module, ModuleAnalysisManager&) {
    StackifyImpl impl(module);
    if (!impl.run()) {
        // Input diagnostics can be discovered after domain selection has
        // already inlined or erased functions. Be conservative about every
        // analysis whenever the implementation reports failure.
        return PreservedAnalyses::none();
    }
    // Unmanaged runtime routines and native scalar islands survive as global
    // BPF subprograms. Their BTF records are checked independently, but -O2
    // may have dropped the parameter variables and left anonymous arguments
    // that Linux 5.15 rejects ("FUNC __bpf_dadd Invalid arg#1"). Rebuild an
    // exact scalar signature with named parameters. One DIBuilder is finalized
    // once; finalizing one builder per function corrupts the compile unit.
    if (!module.debug_compile_units().empty()) {
        auto* cu = *module.debug_compile_units_begin();
        DIBuilder db(module, false, cu);
        bool any = false;
        for (auto&& func : module) {
            // The trampoline family carries genuine pointer parameters with
            // deliberate BTF (the step's is built above); flattening them to
            // scalars would make the verifier reject their pointer-passing
            // callers.
            bool needsScalarBtf =
                (func.getName().starts_with("__bpf_") && !func.getName().starts_with("__bpf_capsule_trampoline")) || func.getMetadata("bpf.native.scalar");
            // Optimizers may discard the original DISubprogram entirely for
            // a small C helper. A native island still needs FUNC/FUNC_PROTO
            // records so libbpf can relocate calls to it; the compile unit is
            // sufficient to synthesize those records from the proven ABI.
            if (!needsScalarBtf) {
                continue;
            }
            auto intFor = [&](Type* t) -> Metadata* {
                if (t->isVoidTy()) {
                    return nullptr;
                }
                return BtfGetInt(db, t->isIntegerTy() ? t->getIntegerBitWidth() : 64, true);
            };
            SmallVector<Metadata*> sigTypes;
            sigTypes.push_back(intFor(func.getReturnType()));
            for (auto&& arg : func.args()) {
                sigTypes.push_back(intFor(arg.getType()));
            }
            auto* sig = db.createSubroutineType(db.getOrCreateTypeArray(sigTypes));
            auto* sp = db.createFunction(
                cu, func.getName(), func.getName(), cu->getFile(), 0, sig, 0, DINode::FlagZero,
                func.isDeclaration() ? DISubprogram::SPFlagZero : DISubprogram::SPFlagDefinition
            );
            func.setSubprogram(nullptr);
            func.setSubprogram(sp);
            // The names are what BTF was missing; the verifier also needs the
            // argument list to be real, or a routine that reads its second
            // argument is rejected ("R2 !read_ok").
            for (auto&& [i, arg] : enumerate(func.args())) {
                db.createParameterVariable(sp, "a" + Twine(i).str(), i + 1, cu->getFile(), 0, cast<DIType>(sigTypes[i + 1]), true);
            }
            for (auto&& inst : instructions(func)) {
                inst.setDebugLoc(DILocation::get(module.getContext(), 0, 0, sp));
                // Loop metadata carries its own locations, still scoped to
                // the subprogram just replaced; it has no use left this late.
                inst.setMetadata(LLVMContext::MD_loop, nullptr);
            }
            any = true;
        }
        if (any) {
            db.finalize();
        }
    }

    // Bodies assembled from managed functions inherit this pass's subprogram,
    // and a function with debug info may not contain an inlinable call
    // without a location. Calls carried in from passes that ran while the
    // caller still had no debug info (soft-float's arithmetic calls in -g0
    // sources) get a synthetic one.
    for (auto&& func : module) {
        DISubprogram* sp = func.getSubprogram();
        if (!sp) {
            continue;
        }
        for (auto&& inst : instructions(func)) {
            if (!inst.getDebugLoc() && isa<CallBase>(&inst)) {
                inst.setDebugLoc(DILocation::get(func.getContext(), 0, 0, sp));
            }
        }
    }

    if (verifyModule(module, &errs())) {
        report_fatal_error("stackify produced an invalid module");
    }
    return PreservedAnalyses::none();
}
