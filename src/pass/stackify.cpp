// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "stackify.h"

#include "common.h"
#include "inline_policy.h"
#include "runtime_symbols.h"
#include "target.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/MapVector.h>
#include <llvm/ADT/SCCIterator.h>
#include <llvm/ADT/SetVector.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpressions.h>
#include <llvm/Analysis/StackLifetime.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/IntrinsicsBPF.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <limits>

using namespace llvm;

// Inlining a function into its callers costs stack: its spills join the
// caller's frame, and every frame is capped at 512 bytes.
// The verifier rejects any loop it cannot bound and simulates every iteration
// of the ones it can. Turning each hostile backedge into explicit state leaves
// the step functions acyclic; bounded chunks are driven by a helper callback.

namespace {

// The continuation PC lives in the fiber's pc register, not in the frame:
// every suspension writes its resume target there, calls write the callee's
// entry PC there and park the caller's resume PC in the linkage. Managed
// function addresses are based tokens whose low word is the entry PC.
// Physical placement is deliberately absent from the continuation ABI: an
// ordinary scalar object has one application step.

static cl::opt<unsigned> FiberStackBytes(
    "bpf-fiber-stack-size", cl::init(256u * 1024u), cl::desc("Bytes of unified program memory reserved for each Capsule fiber stack"));

// An intra-frame continuation immediately re-enters the managed dispatcher.
constexpr int ActionContinue = 0;
// Same frame, but return to the native caller before dispatching it again.
// Step actions are deliberately boolean: zero continues, one stops.
constexpr int ActionYield = 1;

// A managed link keeps its two scalar domains independent: the caller's
// full fp pointer at fp-16 and the 32-bit resume PC at fp-8. Packing them
// into one word would save one virtual-memory access, but adds a shift and
// OR to every call and makes the old verifier track a packed value which
// is later reused in frame-address arithmetic.
constexpr uint64_t LinkageBytes = 16;
constexpr int64_t ReturnPcOffset = -8;
constexpr int64_t SavedFpOffset = -16;
constexpr int64_t JumpPcOffset = 0;
constexpr int64_t JumpSpOffset = 8;
constexpr int64_t JumpFpOffset = 16;
constexpr int64_t JumpResultOffset = 24;

// The bounds the nosuspend proof enforces: a proven non-suspendable runtime
// operation must fit an ordinary scalar BPF subprogram the verifier can check
// once against unknown arguments.
constexpr uint64_t NoSuspendFunctionIrLimit = 1024;
constexpr uint64_t NoSuspendExpandedLoopLimit = 4096;
constexpr uint64_t NoSuspendAllocaLimit = 256;
constexpr unsigned NoSuspendLoopTripLimit = 64;

// CPU v3's dispatch hierarchy uses power-of-two local key spaces so selecting
// one costs a single shift. Keys remain private compiler data.
constexpr unsigned V3DispatchShardUnits = 64;

// Linux rejects a loaded program with more than 256 BPF functions. Temporary
// allocation units disappear in MachineFlatten, but native functions and the
// generated runtime accessors remain real BPF subprograms.
constexpr unsigned MaxBpfFunctions = 256;

// Keep physical roots short enough for the kernel's whole-subprogram
// liveness sweep without spreading code over every available function slot.
// The measured root-count curve and these automatic thresholds are documented
// in DESIGN.md; they are compiler policy, not per-object tuning knobs.
constexpr uint64_t RootLoadTarget = 7500;
constexpr unsigned MaxMergeRoots = 64;
// One allocation unit becomes one disconnected component in a root. Keep its
// post-codegen path comfortably below the verifier's 8192-jump sequence cap.
constexpr uint64_t MaxUnitLoad = 3500;

// The local verifier envelope below scales this ceiling down from the loop's
// own body, branches and memory operations.  It is deliberately shared by
// both memory representations: target selection must not change program
// semantics or require an application-specific scheduling override.
constexpr unsigned ChunkTripLimit = 8;
constexpr unsigned NativeLinearTripLimit = 64;

cl::opt<bool> TestSuspendAllLoops(
    "bpf-test-suspend-all-loops", cl::desc("Force every managed loop through a suspension edge for tests"), cl::init(false), cl::Hidden);

bool IsLateMemoryIntrinsic(const Function& func) {
    return func.getName() == bpf::sym::HeapStart || func.getName() == bpf::sym::HeapSize;
}

Function* ResolveDirectCallee(const CallBase& call) {
    return dyn_cast<Function>(call.getCalledOperand()->stripPointerCastsAndAliases());
}

bool IsStackifiable(Function& func) {
    if (func.isDeclaration() || func.getName().starts_with("llvm.")) {
        return false;
    }
    // The driver and its callback are the machinery that runs managed code;
    // they cannot themselves be managed.
    if (bpf::HasFunctionClass(func, bpf::cls::Trampoline) || bpf::HasFunctionClass(func, bpf::cls::HeapAccessor)) {
        return false;
    }
    // Explicit nosuspend operations are flattened and proved below; every
    // other Capsule function uses the universal managed fallback.
    if (bpf::HasFunctionClass(func, bpf::cls::NoSuspend)) {
        return false;
    }
    return bpf::IsCapsuleFunction(func) && !bpf::IsEntryProgram(func);
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
    Value* Fp = nullptr;
    Value* Frame = nullptr;
    Value* Control = nullptr; // staged fiber control, replaced by the physical step argument
    uint32_t EntryPc = 0;
    enum class StateKind : uint8_t { Entry, Backedge, Call, Yield, Setjmp };
    struct State {
        uint32_t Pc = 0;
        BasicBlock* Root = nullptr;
        StateKind Kind = StateKind::Entry;
    };
    SmallVector<State> States;
    SmallVector<int64_t> ArgOffsets; // boundary-relative offset of each incoming argument (negative)
    DenseMap<AllocaInst*, uint64_t> AllocaOffsets;
    // A run-time-sized allocation is carved below the frame; sp itself is
    // the carving frontier. Each site keeps an 8-byte handle so the
    // computed pointer survives suspensions like every other frame value,
    // and each stack save keeps its frontier snapshot.
    DenseMap<AllocaInst*, uint64_t> DynamicHandleOffsets;
    DenseMap<CallBase*, uint64_t> StackSaveOffsets;
    DenseMap<CallBase*, uint64_t> JumpResultOffsets;
    uint64_t LocalsOffset = 0; // = result landing zone; statics start here
    uint64_t FrameSize = 0;    // fp - sp at entry: zone + locals + spills + args + linkage
    uint64_t ReturnSize = 0;
};

// A maximal connected piece of transformed CFG.  Suspension edges have
// already become returns, so a region can move independently between LLVM
// functions without introducing cross-function control flow.
struct Region {
    ManagedFunction* Owner = nullptr;
    SmallVector<BasicBlock*> Blocks;
    SmallVector<ManagedFunction::State> States;
    uint64_t Size = 0;
    unsigned Unit = 0;
    bool BorrowedContext = false;
};

// One temporary code-generation function. All continuation regions owned by
// one source function stay together so ordinary IR optimization can share
// their common code. LLVM still allocates each source function independently;
// the machine flattener removes every unit boundary before BPF emission.
struct AllocationUnit {
    Function* Func = nullptr;
    DISubprogram* Subprogram = nullptr;
    BasicBlock* Dispatch = nullptr;
    bool Merged = false; // this unit IS the dispatcher step for its class
    Value* Fp = nullptr;
    Value* Frame = nullptr;
    SmallVector<ManagedFunction::State> States;
    bool BorrowedContext = false;
    uint32_t DispatchKey = 0;
    unsigned OutputRoot = 0;
};

class StackifyImpl {
public:
    explicit StackifyImpl(Module& module, bool fixedMemory, bool directDispatch, bool boundedDispatch)
        : Module_(module)
        , Ctx_(module.getContext())
        , I8_(Type::getInt8Ty(Ctx_))
        , I32_(Type::getInt32Ty(Ctx_))
        , I64_(Type::getInt64Ty(Ctx_))
        , FixedMemory_(fixedMemory)
        , DirectDispatch_(directDispatch)
        , BoundedDispatch_(boundedDispatch) {
    }

    bool run() {
        bpf::MaterializeFunctionClasses(Module_);
        CanonicalizeManagedAliases();
        ChooseManagedFunctions();
        if (InputError_) {
            return false;
        }
        ValidateYieldCalls();
        ValidateJumpCalls();
        if (YieldError_ || JumpError_) {
            return false;
        }
        if (Managed_.empty()) {
            return RemoveUnusedRuntimeDrivers();
        }
        ValidateGeneratedNamespace();
        ConfigureStackGeometry();
        LayOutArguments();
        if (InputError_) {
            return false;
        }
        ConfigureFibers();
        ConfigureBorrowedContext();
        if (InputError_) {
            return false;
        }
        RematerializeBorrowedContextAccesses();
        ValidateScalarRootsDoNotReachBorrowedContext();
        if (InputError_) {
            return false;
        }
        DiscoverNativeHelperAllocas();
        if (VerifierPointerError_) {
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
        ComputeFrameLayout();
        if (InputError_) {
            return false;
        }
        CreateStackGlobals();
        CreateStages();

        for (auto&& func : Managed_) {
            TransformFunction(*func.second);
            if (InputError_) {
                return false;
            }
        }
        if (YieldMarker_) {
            if (!YieldMarker_->use_empty()) {
                report_fatal_error("stackify: capsule_yield marker survived function transformation");
            }
            YieldMarker_->eraseFromParent();
            YieldMarker_ = nullptr;
        }
        for (Function* marker : {SetjmpMarker_, LongjmpMarker_}) {
            if (marker) {
                if (!marker->use_empty()) {
                    report_fatal_error("stackify: setjmp/longjmp marker survived function transformation");
                }
                marker->eraseFromParent();
            }
        }
        FormRegionsAndCreateAllocationUnits();
        ReplaceFiberUses();
        ReplaceBorrowedContextUses();
        // The resume dispatch jumps into loop bodies, and the fix-irreducible
        // pass that untangles the result can only rewire BranchInst
        // terminators — a switch edge into the irreducible region crashes
        // LLVM's ControlFlowHub. Splitting every critical switch edge leaves
        // the switches (and their speed) alone while guaranteeing the hub
        // only ever has to redirect a branch.
        for (auto&& unit : Units_) {
            SmallVector<std::pair<Instruction*, unsigned>> edges;
            for (auto&& block : *unit.Func) {
                // getTerminator() asserts on a block that has none rather than
                // returning null, so dyn_cast_or_null on it never guarded
                // anything; region construction does leave blocks unterminated
                // at this point. A switch is a terminator, so it can only be
                // the last instruction, and asking that way is well defined.
                auto* sw = block.empty() ? nullptr : dyn_cast<SwitchInst>(&block.back());
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
        FinishAllocationUnits();
        BuildTrampoline();
        RewriteEntryPrograms();
        RewriteReturnCopies();
        InternalizeOrdinaryFunctions();

        // O2's module inliner leaves call-site cycle-prevention history which
        // refers to the functions it traversed. No inliner runs after
        // Stackify, and managed functions are about to become integer PCs;
        // retaining the metadata would RAUW its required Function operands
        // into invalid inttoptr constants.
        for (Function& function : Module_) {
            for (Instruction& instruction : instructions(function)) {
                if (auto* call = dyn_cast<CallBase>(&instruction)) {
                    call->setMetadata(LLVMContext::MD_inline_history, nullptr);
                }
            }
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
            // The compile-time token is the bare displacement; MemoryPass
            // rebases every code use onto the window (a folded frozen-config
            // read) and initializer slots are rebased at initialization.
            func->replaceAllUsesWith(
                ConstantExpr::getIntToPtr(ConstantInt::get(I64_, BPF_CAPSULE_FUNCTION_TOKEN_DISPLACEMENT + info->EntryPc), func->getType()));
            func->eraseFromParent();
        }

        return true;
    }

private:
    // ---------------------------------------------------------------- policy

    void ValidateGeneratedNamespace() {
        for (StringRef name : {bpf::sym::CallStack, bpf::sym::PcUnitTable, bpf::sym::SetOutcome}) {
            if (Module_.getNamedValue(name)) {
                report_fatal_error(Twine("stackify: reserved generated symbol already exists: ") + name);
            }
        }
        for (GlobalValue& value : Module_.global_values()) {
            if (value.getName().starts_with(bpf::sym::StagePrefix) || value.getName().starts_with(bpf::sym::AllocationUnitPrefix) ||
                value.getName().starts_with(bpf::sym::DispatchRouterPrefix)) {
                report_fatal_error(Twine("stackify: reserved generated symbol already exists: ") + value.getName());
            }
        }
    }

    Function* GetOrCreateAccessor(StringRef name, FunctionType* type) {
        GlobalValue* existing = Module_.getNamedValue(name);
        if (!existing) {
            return Function::Create(type, GlobalValue::ExternalLinkage, name, Module_);
        }
        auto* function = dyn_cast<Function>(existing);
        if (!function || !function->isDeclaration() || function->getFunctionType() != type) {
            report_fatal_error(Twine("stackify: reserved accessor has the wrong ABI: ") + name);
        }
        return function;
    }

    // Managed functions become integer continuation tokens, which an LLVM
    // GlobalAlias cannot represent as its aliasee. Replace every alias use by
    // the actual function while both are still ordinary IR values. Native
    // aliases remain untouched because they are loader-visible ELF ABI.
    void CanonicalizeManagedAliases() {
        SmallVector<GlobalAlias*> aliases;
        for (GlobalAlias& alias : Module_.aliases()) {
            auto* target = dyn_cast_or_null<Function>(alias.getAliaseeObject());
            if (!target || !bpf::IsCapsuleFunction(*target)) {
                continue;
            }
            alias.replaceAllUsesWith(target);
            aliases.push_back(&alias);
        }
        for (GlobalAlias* alias : aliases) {
            alias->eraseFromParent();
        }
    }

    bool RemoveUnusedRuntimeDrivers() {
        SmallVector<Function*> drivers;
        SmallPtrSet<Function*, 8> driverSet;
        for (Function& func : Module_) {
            if (bpf::HasFunctionClass(func, bpf::cls::Trampoline)) {
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
        FiberControls_ = Module_.getGlobalVariable(bpf::sym::FiberControls, true);
        FiberControlsType_ = FiberControls_ ? dyn_cast<ArrayType>(FiberControls_->getValueType()) : nullptr;
        FiberControlType_ = FiberControlsType_ ? dyn_cast<StructType>(FiberControlsType_->getElementType()) : nullptr;
        if (!bpf::IsFiberControlLayout(FiberControlType_)) {
            report_fatal_error("stackify: runtime is missing bpf_capsule_fibers control");
        }
        FiberCount_ = FiberControlsType_->getNumElements();
        if (!FiberCount_ || FiberCount_ > BPF_CAPSULE_MAX_FIBERS_LIMIT) {
            report_fatal_error("stackify: bpf_capsule_fibers count is outside the shared Capsule ABI");
        }
        FiberConfig_ = Module_.getGlobalVariable(bpf::sym::Config, true);
        FiberConfigType_ = FiberConfig_ ? dyn_cast<StructType>(FiberConfig_->getValueType()) : nullptr;
        if (!FiberConfigType_ || FiberConfigType_->getNumElements() != BPF_CAPSULE_OBJECT_CONFIG_FIELD_COUNT ||
            !FiberConfigType_->getElementType(BPF_CAPSULE_OBJECT_CONFIG_FIBER_COUNT)->isIntegerTy(32)) {
            report_fatal_error("stackify: runtime is missing bpf_capsule_config");
        }
        CurrentFiber_ = GetOrCreateAccessor(bpf::sym::CurrentFiberIndex, FunctionType::get(I32_, false));
        ActiveFiberCount_ = GetOrCreateAccessor(bpf::sym::ActiveFiberCount, FunctionType::get(I32_, false));
        OutcomeAccessor_ = GetOrCreateAccessor(bpf::sym::OutcomePointer, FunctionType::get(PointerType::get(Ctx_, 0), false));
        GetOutcomeSetter();
        // The frozen config's backend field is a compile-time constant of the
        // runtime build; it selects the frame-anchor shape (a stored fp is
        // the frame address itself on the arena tier, and re-roots in the
        // stack bank global on the fixed tier).
        if (FiberConfig_->hasInitializer()) {
            auto* backend =
                dyn_cast_or_null<ConstantInt>(FiberConfig_->getInitializer()->getAggregateElement(unsigned(BPF_CAPSULE_OBJECT_CONFIG_MEMORY_BACKEND)));
            ArenaTier_ = backend && backend->getZExtValue() == BPF_CAPSULE_MEMORY_ARENA;
        }
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
            gep->setMetadata(bpf::md::SectionedBounded, MDNode::get(Ctx_, {}));
        }
        return control;
    }

    Value* OutcomePtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_STATUS, "fiber.outcome");
    }

    Value* PcPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_PC, "fiber.pc");
    }

    Value* SpPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_SP, "fiber.sp");
    }

    Value* FpPtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_FP, "fiber.fp");
    }

    Value* ReturnSizePtr(IRBuilder<>& b, Value* fiber = nullptr) {
        return b.CreateStructGEP(FiberControlType_, FiberControlPtr(b, fiber), BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE, "fiber.return.size");
    }

    Function* GetOutcomeSetter() {
        if (OutcomeSetter_) {
            return OutcomeSetter_;
        }
        OutcomeSetter_ = Function::Create(FunctionType::get(I32_, {I32_, I64_}, false), GlobalValue::ExternalLinkage, bpf::sym::SetOutcome, Module_);
        OutcomeSetter_->setCallingConv(CallingConv::C);
        OutcomeSetter_->addFnAttr(Attribute::NoInline);
        OutcomeSetter_->setMetadata(bpf::md::NativeScalar, MDNode::get(Ctx_, {}));
        OutcomeSetter_->getArg(0)->setName("fiber");
        OutcomeSetter_->getArg(1)->setName("outcome");

        BasicBlock* entry = BasicBlock::Create(Ctx_, "entry", OutcomeSetter_);
        IRBuilder<> b(entry);
        StoreInst* store = b.CreateStore(OutcomeSetter_->getArg(1), OutcomePtr(b, OutcomeSetter_->getArg(0)));
        // This function is also a backend barrier: keeping the sectioned-map
        // abort store away from arena-stack store suffixes prevents LLVM's BPF
        // tail merger from producing one instruction with two pointer types.
        store->setVolatile(true);
        b.CreateRet(ConstantInt::get(I32_, 0));

        if (!Module_.debug_compile_units().empty()) {
            DIBuilder db(Module_, false, *Module_.debug_compile_units_begin());
            BtfFunctionAddDebugInfo(db, *OutcomeSetter_, {BtfGetInt(db, 32, true), BtfGetInt(db, 32, false), BtfGetInt(db, 64, false)});
            db.finalize();
        }
        return OutcomeSetter_;
    }

    void PublishExit(IRBuilder<>& builder, Value* fiber, int32_t code) {
        builder.CreateCall(GetOutcomeSetter(), {fiber, ConstantInt::get(I64_, bpf::OutcomeValue(code))});
    }

    Metadata* BorrowedContextDebugType(CallBase& boundary, Value* context) {
        auto* argument = dyn_cast<Argument>(getUnderlyingObject(context));
        DISubprogram* subprogram = argument ? argument->getParent()->getSubprogram() : nullptr;
        auto types = subprogram && subprogram->getType() ? subprogram->getType()->getTypeArray() : DINodeArray();
        if (!argument || types.size() <= argument->getArgNo() + 1 || !types[argument->getArgNo() + 1]) {
            boundary.getContext().emitError(
                &boundary, "stackify: capsule_call_ctx context must derive from a native function argument with debug/BTF type information");
            InputError_ = true;
            return nullptr;
        }
        return types[argument->getArgNo() + 1];
    }

    void ConfigureBorrowedContext() {
        bool hasContextBoundary = false;
        for (Function& function : Module_) {
            for (Instruction& instruction : instructions(function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                std::optional<OperandBundleUse> boundary = call ? call->getOperandBundle(bpf::md::CallBundle) : std::nullopt;
                Function* root = boundary ? ResolveDirectCallee(*call) : nullptr;
                if (!root) {
                    continue;
                }
                if (boundary->Inputs.size() == 2) {
                    hasContextBoundary = true;
                    Metadata* type = BorrowedContextDebugType(*call, boundary->Inputs[1].get());
                    if (!type) {
                        return;
                    }
                    if (BorrowedDebugType_ && BorrowedDebugType_ != type) {
                        call->getContext().emitError(call, "stackify: one borrowed verifier-context type is supported per Capsule object");
                        InputError_ = true;
                        return;
                    }
                    BorrowedDebugType_ = type;
                } else if (boundary->Inputs.size() != 1) {
                    call->getContext().emitError(call, "stackify: Capsule call boundary has an invalid context operand count");
                    InputError_ = true;
                    return;
                }
            }
        }

        if (!hasContextBoundary) {
            return;
        }

        BorrowedContext_ = true;
        BorrowedCurrent_ = GetOrCreateAccessor(bpf::sym::CurrentCtx, FunctionType::get(PointerType::get(Ctx_, 0), false));
    }

    // LLVM may hoist one accessor above several managed calls even when each
    // source use is local. Put the marker beside every use before liveness is
    // checked, so the context itself never appears to cross a suspension and
    // each resumed region receives the current physical invocation's value.
    void RematerializeBorrowedContextAccesses() {
        if (!BorrowedCurrent_) {
            return;
        }
        SmallVector<CallBase*> accessors;
        for (User* user : BorrowedCurrent_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != BorrowedCurrent_) {
                report_fatal_error("stackify: borrowed context accessor has a non-call use");
            }
            accessors.push_back(call);
        }
        for (CallBase* accessor : accessors) {
            DebugLoc debugLoc = accessor->getDebugLoc();
            RematerializeUses(*accessor, [&](BasicBlock::iterator at) -> Value* {
                IRBuilder<> b(at->getParent(), at);
                CallInst* current = b.CreateCall(BorrowedCurrent_);
                current->setDebugLoc(debugLoc);
                return current;
            });
            accessor->eraseFromParent();
        }
    }

    // A verifier context exists only while executing the native entry that
    // supplied it. Reject every statically visible scalar-to-context path;
    // optimizers remain free to prove and delete an unreachable context branch
    // first. Computed managed calls are checked dynamically by the scalar
    // step's deliberately incomplete unit switch: a context PC cannot be
    // dispatched without the typed driver and becomes INVALID_DISPATCH.
    void ValidateScalarRootsDoNotReachBorrowedContext() {
        if (!BorrowedContext_) {
            return;
        }

        SmallVector<Function*> scalarRoots;
        for (Function& function : Module_) {
            for (Instruction& instruction : instructions(function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                std::optional<OperandBundleUse> boundary = call ? call->getOperandBundle(bpf::md::CallBundle) : std::nullopt;
                if (!boundary || boundary->Inputs.size() != 1) {
                    continue;
                }
                Function* root = call->getCalledFunction();
                if (root) {
                    scalarRoots.push_back(root);
                }
            }
        }

        auto directlyUsesBorrowedContext = [&](Function* function) {
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
                    root->getContext().emitError(Twine("stackify: scalar Capsule root ") + root->getName() +
                        " has a direct call path to context-dependent function " + function->getName());
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
        const DataLayout& dataLayout = Module_.getDataLayout();
        for (auto&& [function, info] : Managed_) {
            for (Instruction& instruction : instructions(*function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || !bpf::IsVerifierCall(*call)) {
                    continue;
                }
                for (Use& argument : call->args()) {
                    SmallVector<const Value*, 4> objects;
                    getUnderlyingObjects(argument.get(), objects);
                    for (const Value* object : objects) {
                        const auto* discovered = dyn_cast<AllocaInst>(object);
                        if (!discovered) {
                            continue;
                        }
                        auto* alloca = const_cast<AllocaInst*>(discovered);
                        auto* count = dyn_cast<ConstantInt>(alloca->getArraySize());
                        TypeSize elementSize = dataLayout.getTypeAllocSize(alloca->getAllocatedType());
                        if (!count || elementSize.isScalable()) {
                            function->getContext().emitError(
                                alloca, Twine("stackify: helper-visible allocation in ") + function->getName() + " must have a fixed size");
                            VerifierPointerError_ = true;
                            continue;
                        }
                        uint64_t elementBytes = elementSize.getFixedValue();
                        uint64_t elements = count->getValue().getLimitedValue(513);
                        if (alloca->getAlign().value() > 512 || (elementBytes && elements > 512 / elementBytes)) {
                            function->getContext().emitError(
                                alloca, Twine("stackify: helper-visible allocation in ") + function->getName() + " exceeds the 512-byte native BPF stack");
                            VerifierPointerError_ = true;
                            continue;
                        }
                        alloca->setMetadata(bpf::md::NativeAlloca, MDNode::get(Ctx_, {}));
                        NativeHelperAllocas_.insert(alloca);
                    }
                }
            }
        }
        // Underlying-object discovery is set-valued. Cross back into stable IR
        // order before native stack layout can observe the result.
        for (auto&& [function, info] : Managed_) {
            for (Instruction& instruction : instructions(*function)) {
                if (auto* alloca = dyn_cast<AllocaInst>(&instruction); alloca && NativeHelperAllocas_.contains(alloca)) {
                    NativeHelperAllocaOrder_.push_back(alloca);
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
        return NativeHelperAllocas_.contains(dyn_cast<AllocaInst>(value));
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
        } else if (auto* call = dyn_cast<CallBase>(value); call && call->getCalledFunction() == BorrowedCurrent_) {
            stream << "borrowed verifier context";
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

    bool IsProvenVerifierNativePointer(Value* value, const SmallPtrSetImpl<Value*>& native) const {
        if (isa<ConstantPointerNull>(value) || native.contains(value)) {
            return true;
        }
        SmallVector<const Value*, 4> objects;
        getUnderlyingObjects(value, objects);
        return !objects.empty() && llvm::all_of(objects, [&](const Value* object) { return native.contains(const_cast<Value*>(object)); });
    }

    // Verifier-owned pointers are capabilities for one physical BPF region.
    // They may use registers or native BPF stack spills, but cannot enter the
    // software frame which survives a return to the trampoline. Context
    // accessor uses were rematerialized above, so every region obtains the
    // current invocation's context without source-level repetition.
    void ValidateVerifierPointerStorageAndCalls() {
        for (auto&& [function, info] : Managed_) {
            SmallPtrSet<Value*, 32> native;
            FindVerifierNativeValues(*function, native);
            SmallVector<const AllocaInst*, 8> nativeAllocas = NativeHelperAllocas(*function);
            StackLifetime stackLifetime(*function, nativeAllocas, StackLifetime::LivenessType::May);
            stackLifetime.run();

            for (Instruction& instruction : instructions(*function)) {
                if (auto* call = dyn_cast<CallBase>(&instruction); call && bpf::IsVerifierCall(*call)) {
                    for (auto [index, argument] : llvm::enumerate(call->args())) {
                        if (!argument->getType()->isPointerTy() || IsProvenVerifierNativePointer(argument.get(), native)) {
                            continue;
                        }
                        function->getContext().emitError(call,
                            Twine("stackify: pointer argument ") + Twine(index + 1) + " to a BPF helper in " + function->getName() +
                                " is not provably verifier-native");
                        VerifierPointerError_ = true;
                        return;
                    }
                }
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
                for (auto [index, argument] : llvm::enumerate(call->args())) {
                    if (native.contains(argument.get())) {
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
        // Verifiers can reject a global BPF subprogram whose return type is
        // void, even when every argument is scalar; require a scalar return.
        if (func.isVarArg() || !scalar(func.getReturnType())) {
            return false;
        }
        return llvm::all_of(func.args(), [&](Argument& arg) { return scalar(arg.getType()); });
    }

    bool HasNativeBpfAbi(Function& func) const {
        auto nativeValue = [](Type* type) { return type->isPointerTy() || (type->isIntegerTy() && type->getIntegerBitWidth() <= 64); };
        if (func.isVarArg() || func.arg_size() > 5 || (!func.getReturnType()->isVoidTy() && !nativeValue(func.getReturnType()))) {
            return false;
        }
        return llvm::all_of(func.args(), [&](Argument& arg) { return nativeValue(arg.getType()); });
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

    bool FitsNoSuspendBody(Function& func) const {
        if (func.getInstructionCount() > NoSuspendFunctionIrLimit) {
            return false;
        }

        const DataLayout& dl = Module_.getDataLayout();
        uint64_t stack = 0;
        for (Instruction& inst : instructions(func)) {
            // A nosuspend operation has no fiber argument and therefore no
            // Capsule exit channel. Keep any raw-unreachable or late trap in
            // managed regions, where bpf-define-undef can publish the error
            // against the actual running fiber instead of corrupting fiber 0.
            auto* call = dyn_cast<CallInst>(&inst);
            if (isa<UnreachableInst>(inst) || (call && (call->getIntrinsicID() == Intrinsic::trap || call->getIntrinsicID() == Intrinsic::debugtrap))) {
                return false;
            }
            auto* alloca = dyn_cast<AllocaInst>(&inst);
            if (!alloca) {
                continue;
            }
            auto* count = dyn_cast<ConstantInt>(alloca->getArraySize());
            if (!alloca->isStaticAlloca() || !count) {
                return false;
            }
            TypeSize typeSize = dl.getTypeAllocSize(alloca->getAllocatedType());
            if (typeSize.isScalable()) {
                return false;
            }
            uint64_t elementBytes = typeSize.getFixedValue();
            uint64_t elements = count->getValue().getLimitedValue(NoSuspendAllocaLimit + 1);
            uint64_t alignment = alloca->getAlign().value();
            if (alignment > NoSuspendAllocaLimit || stack > NoSuspendAllocaLimit) {
                return false;
            }
            uint64_t padding = (-stack) & (alignment - 1);
            if (padding > NoSuspendAllocaLimit - stack) {
                return false;
            }
            stack += padding;
            if (elementBytes && elements > (NoSuspendAllocaLimit - stack) / elementBytes) {
                return false;
            }
            stack += elementBytes * elements;
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
            // A ScalarEvolution maximum is a compiler fact, not necessarily a
            // verifier-visible one. In particular, LLVM propagates a callee's
            // `range` attribute into a loop bound, while the BPF verifier sees
            // an ordinary subprogram return as an unconstrained scalar. Keep a
            // nosuspend only when its own latch has an exact constant count.
            if (!trips || trips > NoSuspendLoopTripLimit) {
                return false;
            }
            uint64_t bodyIr = 0;
            for (BasicBlock* block : loop->blocks()) {
                bodyIr += EstimatedBlockSize(*block);
            }
            expanded += uint64_t(trips - 1) * bodyIr;
            if (expanded > NoSuspendExpandedLoopLimit) {
                return false;
            }
        }
        return true;
    }

    bool IsCapsuleRoot(Function& func) const {
        for (Use& use : func.uses()) {
            auto* call = dyn_cast<CallBase>(use.getUser());
            if (call && call->isCallee(&use) && call->getOperandBundle(bpf::md::CallBundle)) {
                return true;
            }
        }
        return false;
    }

    // Everything that survives inlining becomes managed. The only ordinary
    // scalar subprograms left are explicitly proven nosuspend operations and
    // the generated runtime machinery.
    void ChooseManagedFunctions() {
        PrepareNoSuspendFunctions();
        InlineSingleUseFunctions();

        for (auto&& func : Module_) {
            if (!IsStackifiable(func) || func.getMetadata(bpf::md::NoSuspend) || func.getMetadata(bpf::md::NativeScalar)) {
                continue;
            }
            // Entry PCs are handed out after the managed set is fixed.  The
            // physical step unit is deliberately not encoded in them.
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
        bpf::stats() << "stackify: " << Managed_.size() << " managed functions\n";
    }

    // Inline compact, non-recursive helpers into their sole managed caller.
    // A single call site means no source IR is duplicated; address-taken and
    // multiply-called functions remain independent continuation boundaries.
    void InlineSingleUseFunctions() {
        CallGraph callGraph(Module_);
        SmallVector<Function*> order;
        for (auto it = scc_begin(&callGraph); !it.isAtEnd(); ++it) {
            const std::vector<CallGraphNode*>& scc = *it;
            if (scc.size() != 1) {
                continue;
            }
            Function* function = scc.front()->getFunction();
            if (!function || !IsStackifiable(*function) ||
                (function->hasFnAttribute(Attribute::NoInline) && !function->hasFnAttribute(bpf::InlinePolicyVetoAttr)) ||
                function->getMetadata(bpf::md::NoSuspend) || function->getMetadata(bpf::md::NativeScalar)) {
                continue;
            }
            bool selfRecursive = llvm::any_of(*scc.front(), [&](const auto& edge) { return edge.second->getFunction() == function; });
            if (!selfRecursive) {
                order.push_back(function);
            }
        }

        unsigned inlined = 0;
        for (Function* function : order) {
            if (function->getInstructionCount() > bpf::CompactInlineIrLimit) {
                continue;
            }
            CallBase* site = nullptr;
            bool cannotInline = false;
            for (Use& use : function->uses()) {
                auto* call = dyn_cast<CallBase>(use.getUser());
                Function* caller = call ? call->getFunction() : nullptr;
                bool callSiteNoInline = call && call->getAttributes().hasFnAttr(Attribute::NoInline);
                if (!call || !call->isCallee(&use) || callSiteNoInline || site || !caller || !IsStackifiable(*caller) ||
                    caller->getMetadata(bpf::md::NoSuspend) || caller->getMetadata(bpf::md::NativeScalar) || call->getOperandBundle(bpf::md::CallBundle)) {
                    cannotInline = true;
                    break;
                }
                site = call;
            }
            if (cannotInline) {
                continue;
            }
            if (!site) {
                continue;
            }

            // InlineFunction correctly treats noinline as an absolute veto.
            // Lift it only when the attribute records our own pre-O2 policy;
            // restore it if the attempted reconsideration does not succeed.
            bool policyVeto = function->hasFnAttribute(bpf::InlinePolicyVetoAttr);
            if (policyVeto) {
                function->removeFnAttr(Attribute::NoInline);
            }
            InlineFunctionInfo info;
            if (!InlineFunction(*site, info).isSuccess()) {
                if (policyVeto) {
                    function->addFnAttr(Attribute::NoInline);
                }
                continue;
            }
            if (function->use_empty()) {
                function->eraseFromParent();
                inlined++;
            } else if (policyVeto) {
                function->addFnAttr(Attribute::NoInline);
            }
        }
        bpf::stats() << "stackify: inlined " << inlined << " compact single-use functions\n";
    }

    void ConfigureStackGeometry() {
        // Generated masking, frame arithmetic and the configured stack bank
        // share this exact power-of-two contract. Establish it before any
        // source type participates in layout arithmetic.
        if (!FiberStackBytes || !isPowerOf2_32(FiberStackBytes) || FiberStackBytes > bpf::MaxFiberStackBytes) {
            report_fatal_error("stackify: fiber stack size must be a power of two no larger than 2 MiB");
        }
        FiberStackSize_ = FiberStackBytes;
    }

    bool FixedTypeLayout(Function& owner, Type* type, const Twine& role, uint64_t& bytes, uint64_t& alignment) {
        const DataLayout& dl = Module_.getDataLayout();
        if (!type->isSized()) {
            owner.getContext().emitError(Twine("stackify: unsized ") + role + " in " + owner.getName());
            InputError_ = true;
            return false;
        }
        TypeSize size = dl.getTypeAllocSize(type);
        if (size.isScalable()) {
            owner.getContext().emitError(Twine("stackify: scalable ") + role + " in " + owner.getName());
            InputError_ = true;
            return false;
        }
        bytes = size.getFixedValue();
        alignment = dl.getABITypeAlign(type).value();
        if (bytes > FiberStackSize_ || alignment > FiberStackSize_) {
            owner.getContext().emitError(
                Twine("stackify: ") + role + " in " + owner.getName() + " exceeds the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
            InputError_ = true;
            return false;
        }
        return true;
    }

    // Reserved runtime operations are ordinary native BPF functions. Prove
    // their complete reachable call tree non-suspending and leave every
    // surviving edge as an ordinary BPF-to-BPF call. Only the named roots are
    // global scalar subprograms; pointer-bearing implementation routines stay
    // internal. Source inlining is exclusively the generic O2 inliner,
    // controlled by standard attributes and threshold. The exact physical
    // call depth and stack bytes are validated after register allocation.
    void PrepareNoSuspendFunctions() {
        SmallVector<Function*> roots;
        for (Function& function : Module_) {
            if (!function.isDeclaration() && bpf::HasFunctionClass(function, bpf::cls::NoSuspend)) {
                roots.push_back(&function);
            }
        }

        SmallPtrSet<Function*, 32> complete;
        SmallPtrSet<Function*, 32> active;
        SmallVector<Function*, 32> closure;
        auto prove = [&](auto&& self, Function* function, Function* root) -> void {
            if (complete.contains(function)) {
                return;
            }
            if (!active.insert(function).second) {
                report_fatal_error(Twine("stackify: recursive nosuspend call tree rooted at ") + root->getName() + " reaches " + function->getName());
            }
            if (!HasNativeBpfAbi(*function) || !HasOnlyDirectCallUses(*function) || !FitsNoSuspendBody(*function)) {
                report_fatal_error(Twine("stackify: nosuspend call tree rooted at ") + root->getName() +
                    " contains an unbounded or unsupported native BPF function: " + function->getName() + (HasNativeBpfAbi(*function) ? "" : " (abi)") +
                    (HasOnlyDirectCallUses(*function) ? "" : " (uses)") + (FitsNoSuspendBody(*function) ? "" : " (body)"));
            }

            for (Instruction& instruction : instructions(*function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                    continue;
                }
                Function* callee = ResolveDirectCallee(*call);
                if (!callee) {
                    if (!bpf::IsVerifierCall(*call)) {
                        report_fatal_error(Twine("stackify: nosuspend function ") + function->getName() + " has an indirect call");
                    }
                    continue;
                }
                if (callee->isDeclaration()) {
                    if (!IsLateMemoryIntrinsic(*callee) && !bpf::IsVerifierCall(*call)) {
                        report_fatal_error(Twine("stackify: nosuspend function ") + function->getName() + " calls unresolved " + callee->getName());
                    }
                    continue;
                }
                if (bpf::IsEntryProgram(*callee)) {
                    report_fatal_error(Twine("stackify: nosuspend function ") + function->getName() + " calls BPF entry program " + callee->getName());
                }
                self(self, callee, root);
            }

            active.erase(function);
            complete.insert(function);
            closure.push_back(function);
        };

        for (Function* root : roots) {
            if (!HasScalarBpfAbi(*root)) {
                report_fatal_error(Twine("stackify: nosuspend root does not have the global scalar BPF ABI: ") + root->getName());
            }
            prove(prove, root, root);
            root->setLinkage(GlobalValue::ExternalLinkage);
            root->setMetadata(bpf::md::NativeScalar, MDNode::get(Ctx_, {}));
        }

        for (Function* function : closure) {
            function->setMetadata(bpf::md::NoSuspend, MDNode::get(Ctx_, {}));
            for (Instruction& instruction : instructions(*function)) {
                if (auto* alloca = dyn_cast<AllocaInst>(&instruction)) {
                    alloca->setMetadata(bpf::md::NativeAlloca, MDNode::get(Ctx_, {}));
                }
            }
        }

        // Flatten each proven tree into its root so every nosuspend runtime
        // operation is a single physical BPF frame. The kernel's eight-frame
        // call limit is otherwise exhausted when a deep bounded tree — the
        // TLSF allocator (tlsf_free -> block_merge_next -> block_remove) — is
        // reached from a dispatch region under the borrowed-context
        // trampoline (entry -> ctx_l1 -> ctx_step -> step -> region). The tree
        // was just proven acyclic and bounded, so inlining always terminates;
        // the shared implementation routines are then unreferenced and erased.
        {
            InlineFunctionInfo inlineInfo;
            SmallPtrSet<Function*, 16> rootSet(roots.begin(), roots.end());
            for (Function* root : roots) {
                bool changed = true;
                while (changed) {
                    changed = false;
                    for (Instruction& instruction : instructions(*root)) {
                        auto* call = dyn_cast<CallBase>(&instruction);
                        if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                            continue;
                        }
                        Function* callee = ResolveDirectCallee(*call);
                        if (!callee || callee->isDeclaration() || rootSet.contains(callee) || !callee->hasMetadata(bpf::md::NoSuspend)) {
                            continue;
                        }
                        if (InlineFunction(*call, inlineInfo).isSuccess()) {
                            changed = true;
                            break; // instruction iterator invalidated
                        }
                    }
                }
            }
            for (Function* function : closure) {
                if (!rootSet.contains(function) && function->use_empty()) {
                    function->eraseFromParent();
                }
            }
        }

        if (!roots.empty()) {
            bpf::stats() << "stackify: proved " << roots.size() << " non-suspendable runtime roots and " << closure.size() << " native call-tree functions\n";
        }
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
        uint64_t slot = 8;
        uint64_t slotAlignment = 8;
        for (auto&& [func, info] : Managed_) {
            for (auto&& arg : func->args()) {
                uint64_t bytes = 0;
                uint64_t alignment = 0;
                if (!FixedTypeLayout(*func, arg.getType(), "managed argument", bytes, alignment)) {
                    return;
                }
                slot = std::max(slot, bytes);
                slotAlignment = std::max(slotAlignment, alignment);
                FrameAlignment_ = std::max(FrameAlignment_, alignment);
            }
            Type* ret = func->getReturnType();
            if (!ret->isVoidTy()) {
                uint64_t alignment = 0;
                if (!FixedTypeLayout(*func, ret, "managed result", info->ReturnSize, alignment)) {
                    return;
                }
                FrameAlignment_ = std::max(FrameAlignment_, alignment);
            }
            // A computed call can carry a signature which has no direct
            // definition in this module. Its landing-zone type still belongs
            // to the same frame ABI and must participate in the global
            // alignment before any function is laid out.
            for (Instruction& instruction : instructions(*func)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || !IsManagedCall(call) || call->getType()->isVoidTy()) {
                    continue;
                }
                uint64_t bytes = 0;
                uint64_t alignment = 0;
                if (!FixedTypeLayout(*func, call->getType(), "managed call result", bytes, alignment)) {
                    return;
                }
                FrameAlignment_ = std::max(FrameAlignment_, alignment);
            }
        }
        ArgSlotSize_ = alignTo(slot, slotAlignment);
        // The link remains immediately below fp. Arguments begin below it,
        // their module-wide ABI alignment instead of inheriting that eight-
        // byte displacement from an otherwise aligned frame boundary.
        ArgumentTopBytes_ = alignTo(LinkageBytes, slotAlignment);
    }

    // Results of every size land just above the callee's frame boundary,
    // in the caller's result zone. A separate fiber-level result register
    // for scalars measured slower and larger than reusing caller memory
    // that is already hot.
    uint64_t ResultSlotForType(Type* type, Function& owner) {
        if (type->isVoidTy()) {
            return 0;
        }
        uint64_t bytes = 0;
        uint64_t alignment = 0;
        if (!FixedTypeLayout(owner, type, "managed call result", bytes, alignment)) {
            return 0;
        }
        if (alignment > FrameAlignment_) {
            report_fatal_error("stackify: managed call result escaped the precomputed frame alignment");
        }
        return alignTo(bytes, uint64_t(8));
    }

    // Indirect calls are managed too: the callee value already carries the
    // function's integer id, so the trampoline can dispatch on it directly.
    bool IsManagedCall(CallBase* call) const {
        if (call->isInlineAsm() || isa<IntrinsicInst>(call)) {
            return false;
        }
        Function* callee = ResolveDirectCallee(*call);
        if (!callee) {
            // Only the exact inttoptr(number) helper shape is native. Every
            // other computed callee denotes a managed function token.
            return !bpf::IsVerifierCall(*call);
        }
        return ManagedByFunction_.contains(callee);
    }

    bool IsYieldCall(CallBase* call) const {
        return YieldMarker_ && call->getCalledOperand()->stripPointerCasts() == YieldMarker_;
    }

    bool IsSetjmpCall(CallBase* call) const {
        return SetjmpMarker_ && call->getCalledOperand()->stripPointerCasts() == SetjmpMarker_;
    }

    bool IsLongjmpCall(CallBase* call) const {
        return LongjmpMarker_ && call->getCalledOperand()->stripPointerCasts() == LongjmpMarker_;
    }

    void ValidateYieldCalls() {
        YieldMarker_ = Module_.getFunction(bpf::sym::Yield);
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
                    Twine("stackify: capsule_yield may only be called from Capsule code, not ") + call->getFunction()->getName());
                YieldError_ = true;
                return;
            }
        }
    }

    void ValidateJumpCalls() {
        auto validate = [&](StringRef name, bool setjmp) {
            Function* marker = Module_.getFunction(name);
            if (!marker) {
                return marker;
            }
            bool signature = marker->isDeclaration() && marker->arg_size() == (setjmp ? 1u : 2u) && marker->getArg(0)->getType()->isPointerTy() &&
                (setjmp ? marker->getReturnType()->isIntegerTy(32) : marker->getReturnType()->isVoidTy() && marker->getArg(1)->getType()->isIntegerTy(32));
            bool semanticAttribute = marker->hasFnAttribute(setjmp ? Attribute::ReturnsTwice : Attribute::NoReturn);
            if (!signature || !semanticAttribute) {
                report_fatal_error(Twine("stackify: reserved jump marker has the wrong ABI: ") + name);
            }
            for (User* user : marker->users()) {
                auto* call = dyn_cast<CallBase>(user);
                if (!call || call->getCalledOperand()->stripPointerCasts() != marker) {
                    report_fatal_error("stackify: address of setjmp/longjmp marker escapes");
                }
                if (!ManagedByFunction_.contains(call->getFunction())) {
                    call->getContext().emitError(Twine("stackify: setjmp/longjmp may only be called from Capsule code, not ") + call->getFunction()->getName());
                    JumpError_ = true;
                }
            }
            return marker;
        };
        SetjmpMarker_ = validate(bpf::sym::Setjmp, true);
        LongjmpMarker_ = validate(bpf::sym::Longjmp, false);
    }

    SmallVector<CallBase*> SuspensionCalls(Function& func) const {
        SmallVector<CallBase*> calls;
        for (auto&& inst : instructions(func)) {
            if (auto* call = dyn_cast<CallBase>(&inst); call && (IsManagedCall(call) || IsYieldCall(call) || IsSetjmpCall(call))) {
                calls.push_back(call);
            }
        }
        return calls;
    }

    // ---------------------------------------------------------------- units

    struct StepAbi {
        Argument* Fiber;
        Argument* Control;
        Argument* StackBacking;
    };

    SmallVector<Type*, 4> StepParameterTypes(bool borrowed) {
        SmallVector<Type*, 4> parameters;
        if (borrowed) {
            parameters.push_back(PointerType::get(Ctx_, 0));
        }
        parameters.push_back(I32_);
        parameters.push_back(PointerType::get(Ctx_, 0));
        if (FixedMemory_) {
            parameters.push_back(PointerType::get(Ctx_, 0));
        }
        return parameters;
    }

    StepAbi ConfigureStepAbi(Function& function, bool borrowed) {
        if (borrowed) {
            function.getArg(0)->setName("ctx");
            function.addParamAttr(0, Attribute::get(Ctx_, bpf::md::Borrowed));
        }
        Argument* fiber = function.getArg(FiberArgumentIndex(borrowed));
        fiber->setName("fiber");
        Argument* control = function.getArg(ControlArgumentIndex(borrowed));
        control->setName("fiber_control");
        function.addParamAttr(ControlArgumentIndex(borrowed), Attribute::get(Ctx_, bpf::md::Control));
        NativeFiberControls_[&function] = control;
        Argument* stackBacking = nullptr;
        if (FixedMemory_) {
            stackBacking = function.getArg(StackBackingArgumentIndex(borrowed));
            stackBacking->setName("stack_base");
            function.addParamAttr(StackBackingArgumentIndex(borrowed), Attribute::get(Ctx_, bpf::md::StackBacking));
        }
        return {fiber, control, stackBacking};
    }

    // Each logical function is first transformed in a private staging
    // function.  That keeps temporary SSA simple; the staging functions never
    // reach code generation and therefore do not consume the kernel's global
    // subprogram budget.
    void CreateStages() {
        for (auto&& [function, info] : Managed_) {
            info->EntryPc = NextPc_++;
            info->Stage = Function::Create(FunctionType::get(I32_, false), GlobalValue::InternalLinkage, bpf::sym::StagePrefix + Twine(info->EntryPc), Module_);
            info->Stage->setMetadata(bpf::md::Capsule, MDNode::get(Ctx_, {}));
        }
    }

    void CreateAllocationUnits(unsigned scalarUnits, unsigned borrowedUnits) {
        unsigned unitCount = scalarUnits + borrowedUnits;
        Units_.resize(unitCount);
        for (auto&& [idx, unit] : enumerate(Units_)) {
            unit.BorrowedContext = idx >= scalarUnits;
            // A class with a single unit takes over the dispatcher's step
            // symbol outright: it has the step's exact signature, so the
            // driver loop calls it directly — one call level, one BPF
            // frame, and the routing table less per dispatch. Its lifecycle
            // preamble is added when the dispatch is finished.
            // Merging is legal only when the merged unit is the sole
            // unit its driver can dispatch. The scalar step never
            // dispatches borrowed units, so a lone scalar unit always
            // merges; the borrowed step dispatches every unit (that is how
            // ctx-driven computations reach scalar regions), so the
            // borrowed unit merges only when it is the only unit at all.
            unit.Merged = unit.BorrowedContext ? (borrowedUnits == 1 && scalarUnits == 0) : (scalarUnits == 1);
            StringRef stepName = unit.BorrowedContext ? bpf::sym::TrampolineCtxStep : bpf::sym::TrampolineStep;
            Function* stepDecl = nullptr;
            if (unit.Merged) {
                stepDecl = Module_.getFunction(stepName);
                if (stepDecl && !stepDecl->isDeclaration()) {
                    report_fatal_error(Twine("stackify: ") + stepName + " already defined");
                }
                if (stepDecl) {
                    stepDecl->setName((Twine(stepName) + ".decl").str());
                }
            }
            std::string unitName = unit.Merged ? stepName.str() : (bpf::sym::AllocationUnitPrefix + Twine(idx)).str();
            // The backend needs an ordinary function through register
            // allocation. MachineFlatten consumes its MachineFunction before
            // object emission, so this symbol and its BTF record never spend
            // a kernel subprogram slot.
            SmallVector<Type*, 4> parameters = StepParameterTypes(unit.BorrowedContext);
            unit.Func = Function::Create(FunctionType::get(I32_, parameters, false), Function::ExternalLinkage, unitName, Module_);
            unit.Func->setCallingConv(CallingConv::C);
            unit.Func->addFnAttr(Attribute::NoInline);
            if (unit.Merged) {
                // A merged unit IS the step driver; it carries the class
                // exactly like a separately built one.
                unit.Func->addFnAttr(bpf::cls::Trampoline);
            }
            unit.Func->setMetadata(bpf::md::Capsule, MDNode::get(Ctx_, {}));
            unit.Func->setMetadata(bpf::md::AllocationUnit, MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I32_, unit.BorrowedContext ? 1 : 0))));
            unit.Func->setMetadata(bpf::md::StackSize, MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I64_, FiberStackSize_))));

            if (!Module_.debug_compile_units().empty()) {
                DIBuilder db(Module_, false, *Module_.debug_compile_units_begin());
                auto* cu = *Module_.debug_compile_units_begin();
                SmallVector<Metadata*> signature{BtfGetInt(db, 32, true)};
                if (unit.BorrowedContext) {
                    signature.push_back(BorrowedDebugType_);
                }
                signature.push_back(BtfGetInt(db, 32, false));
                uint64_t controlBytes = Module_.getDataLayout().getTypeAllocSize(FiberControlType_);
                DIType* controlDebugType = BtfGetByteArrayPointer(db, controlBytes);
                signature.push_back(controlDebugType);
                DIType* backingDebugType = nullptr;
                if (FixedMemory_) {
                    backingDebugType = BtfGetByteArrayPointer(db, FiberStackSize_);
                    signature.push_back(backingDebugType);
                }
                auto* type = db.createSubroutineType(db.getOrCreateTypeArray(signature));
                unit.Subprogram = db.createFunction(
                    cu, unit.Func->getName(), unit.Func->getName(), cu->getFile(), 0, type, 0, DINode::FlagArtificial, DISubprogram::SPFlagDefinition);
                unit.Func->setSubprogram(unit.Subprogram);
                if (unit.BorrowedContext) {
                    db.createParameterVariable(unit.Subprogram, "ctx", 1, cu->getFile(), 0, cast<DIType>(BorrowedDebugType_), true);
                }
                db.createParameterVariable(unit.Subprogram, "fiber", unit.BorrowedContext ? 2 : 1, cu->getFile(), 0, BtfGetInt(db, 32, false), true);
                db.createParameterVariable(unit.Subprogram, "fiber_control", unit.BorrowedContext ? 3 : 2, cu->getFile(), 0, controlDebugType, true);
                if (backingDebugType) {
                    db.createParameterVariable(unit.Subprogram, "stack_base", unit.BorrowedContext ? 4 : 3, cu->getFile(), 0, backingDebugType, true);
                }
                db.finalize();
            }

            auto* entry = BasicBlock::Create(Ctx_, "unit.entry", unit.Func);
            unit.Dispatch = entry;
            IRBuilder<> b(entry);
            // MemoryPass runs after Stackify. The ABI attributes preserve the
            // verifier-owned context/control/stack pointers after the source
            // root has been dissolved into physical units.
            StepAbi abi = ConfigureStepAbi(*unit.Func, unit.BorrowedContext);
            Value* fiberControl = abi.Control;
            if (unit.Merged) {
                // A merged unit is the public step and must validate its own
                // ABI. Every other unit is reachable only through BuildStep,
                // after that root has validated the same typed arguments.
                // Repeating these guards in every temporary region function
                // bloats a machine-flattened program without adding a path.
                auto* controlReady = BasicBlock::Create(Ctx_, "unit.control.ready", unit.Func);
                auto* controlMissing = BasicBlock::Create(Ctx_, "unit.control.missing", unit.Func);
                b.CreateCondBr(b.CreateICmpNE(fiberControl, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), controlReady, controlMissing);
                IRBuilder<> cmb(controlMissing);
                cmb.CreateRet(ConstantInt::get(I32_, 1));
                b.SetInsertPoint(controlReady);
                unit.Dispatch = controlReady;
            }
            if (FixedMemory_ && unit.Merged) {
                Value* stackBacking = unit.Func->getArg(StackBackingArgumentIndex(unit.BorrowedContext));
                auto* stackReady = BasicBlock::Create(Ctx_, "unit.stack.ready", unit.Func);
                auto* stackMissing = BasicBlock::Create(Ctx_, "unit.stack.missing", unit.Func);
                b.CreateCondBr(b.CreateICmpNE(stackBacking, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), stackReady, stackMissing);
                IRBuilder<> smb(stackMissing);
                EmitAbort(smb, CAPSULE_ERROR_MEMORY_FAULT, unit.Func->getArg(FiberArgumentIndex(unit.BorrowedContext)));
                smb.CreateRet(ConstantInt::get(I32_, 1));
                b.SetInsertPoint(stackReady);
                unit.Dispatch = stackReady;
            }
            LoadFrameAnchor(b, unit.Func->getArg(FiberArgumentIndex(unit.BorrowedContext)), unit.Fp, unit.Frame);
            // Keep the backing pointer needed by the post-RA spill mover
            // visible at one dominance point without emitting an instruction.
            // If this unit has no relocated spills the marker assembles to
            // nothing.
            Value* stackBase = FixedMemory_ ? unit.Func->getArg(StackBackingArgumentIndex(unit.BorrowedContext))
                                            : StackPtr(b, ConstantInt::get(I64_, 0), unit.Func->getArg(FiberArgumentIndex(unit.BorrowedContext)));
            {
                auto* anchor = InlineAsm::get(FunctionType::get(Type::getVoidTy(Ctx_), {stackBase->getType()}, false), ("# " + bpf::sym::StackAnchor).str(),
                    "r", /*hasSideEffects=*/true);
                b.CreateCall(anchor, {stackBase});
            }
            if (stepDecl) {
                stepDecl->replaceAllUsesWith(unit.Func);
                stepDecl->eraseFromParent();
            }
        }
    }

    unsigned FiberArgumentIndex(bool borrowed) const {
        return borrowed ? 1 : 0;
    }

    unsigned ControlArgumentIndex(bool borrowed) const {
        return FiberArgumentIndex(borrowed) + 1;
    }

    unsigned StackBackingArgumentIndex(bool borrowed) const {
        return ControlArgumentIndex(borrowed) + 1;
    }

    bool FunctionBorrowsContext(const Function* function) const {
        return function && function->arg_size() && function->getArg(0)->hasAttribute(bpf::md::Borrowed);
    }

    void MarkFlattenClass(Function& function, StringRef metadataName, unsigned cls) {
        MDNode* metadata = MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I32_, cls)));
        if (MDNode* old = function.getMetadata(metadataName)) {
            auto* value = old->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(old->getOperand(0)) : nullptr;
            if (!value || value->getZExtValue() != cls) {
                report_fatal_error(Twine("stackify: conflicting machine-flatten class on ") + function.getName());
            }
            return;
        }
        function.setMetadata(metadataName, metadata);
    }

    void ReplaceFiberUses() {
        SmallPtrSet<Function*, 32> unitFunctions;
        for (AllocationUnit& unit : Units_) {
            unitFunctions.insert(unit.Func);
        }

        auto fiberFor = [&](CallBase* call) -> Argument* {
            Function* owner = call->getFunction();
            if (!unitFunctions.contains(owner)) {
                report_fatal_error("stackify: fiber accessor escaped its physical step unit");
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
                b.CreateICmpUGE(count, ConstantInt::get(I32_, 1)), b.CreateICmpULE(count, ConstantInt::get(I32_, FiberCount_)), "fiber.count.valid");
            call->replaceAllUsesWith(b.CreateSelect(valid, count, ConstantInt::get(I32_, 0), "fiber.count.bounded"));
            call->eraseFromParent();
        }

        SmallVector<CallBase*> abortCalls;
        for (User* user : OutcomeAccessor_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != OutcomeAccessor_) {
                report_fatal_error("stackify: exit-word accessor has a non-call use");
            }
            abortCalls.push_back(call);
        }
        for (CallBase* call : abortCalls) {
            IRBuilder<> b(call);
            Value* fiber = fiberFor(call);
            Value* abort = OutcomePtr(b, fiber);
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
                    sb.CreateCall(GetOutcomeSetter(), {fiber, code});
                    store->eraseFromParent();
                    continue;
                }
                user->replaceUsesOfWith(call, abort);
            }
            call->eraseFromParent();
        }

        SmallVector<StoreInst*> generatedStores;
        for (AllocationUnit& unit : Units_) {
            for (Instruction& inst : instructions(*unit.Func)) {
                auto* store = dyn_cast<StoreInst>(&inst);
                if (store && store->getMetadata(bpf::md::OutcomeStore)) {
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
            b.CreateCall(GetOutcomeSetter(), {owner->getArg(FiberArgumentIndex(FunctionBorrowsContext(owner))), code});
            store->eraseFromParent();
        }

        if (!CurrentFiber_->use_empty() || !ActiveFiberCount_->use_empty() || !OutcomeAccessor_->use_empty()) {
            report_fatal_error("stackify: Capsule fiber accessors still have uses");
        }
        CurrentFiber_->eraseFromParent();
        ActiveFiberCount_->eraseFromParent();
        OutcomeAccessor_->eraseFromParent();
        CurrentFiber_ = nullptr;
        ActiveFiberCount_ = nullptr;
        OutcomeAccessor_ = nullptr;
    }

    // Replace the temporary zero-argument accessor after transformed regions
    // have reached their final physical unit. Every use then becomes the
    // unit's exact typed argument, preserving verifier provenance without
    // putting the pointer in persistent Capsule state.
    void ReplaceBorrowedContextUses() {
        if (!BorrowedContext_) {
            return;
        }
        SmallPtrSet<Function*, 32> unitFunctions;
        for (AllocationUnit& unit : Units_) {
            unitFunctions.insert(unit.Func);
        }
        SmallVector<CallBase*> calls;
        for (User* user : BorrowedCurrent_->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != BorrowedCurrent_) {
                report_fatal_error("stackify: borrowed context accessor has a non-call use");
            }
            if (!unitFunctions.contains(call->getFunction())) {
                report_fatal_error("stackify: borrowed context escaped its physical step unit");
            }
            calls.push_back(call);
        }
        for (CallBase* call : calls) {
            if (!FunctionBorrowsContext(call->getFunction())) {
                report_fatal_error("stackify: borrowed context use was assigned to a scalar physical unit");
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
    // the reachable regions across bounded temporary code-generation units.
    // MachineFlatten merges the allocated machine blocks into one emitted
    // step per verifier-pointer signature after register allocation.
    void FormRegionsAndCreateAllocationUnits() {
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

        // A component without a continuation root cannot be entered: region
        // construction follows both predecessor and successor edges, so any
        // executable edge would have connected it to a rooted component.
        // Delete such dead staging CFG now instead of assigning it to an
        // unrelated register-allocation unit and relying on later DCE.
        SmallVector<std::unique_ptr<Region>> dispatchableRegions;
        uint64_t deadBlocks = 0;
        for (auto&& region : Regions_) {
            if (!region->States.empty()) {
                dispatchableRegions.push_back(std::move(region));
                continue;
            }
            for (BasicBlock* block : region->Blocks) {
                if (block->hasAddressTaken()) {
                    report_fatal_error(Twine("stackify: unrooted address-taken block in ") + region->Owner->Original->getName());
                }
                block->dropAllReferences();
                byBlock.erase(block);
                ++deadBlocks;
            }
            for (BasicBlock* block : region->Blocks) {
                block->eraseFromParent();
            }
        }
        Regions_ = std::move(dispatchableRegions);
        if (Regions_.empty()) {
            report_fatal_error("stackify: no dispatchable continuation regions");
        }
        if (deadBlocks) {
            bpf::stats() << "stackify: deleted " << deadBlocks << " unreachable staging blocks\n";
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

        struct SourceUnit {
            ManagedFunction* Owner = nullptr;
            SmallVector<Region*> Regions;
            uint64_t Size = 0;
            bool BorrowedContext = false;
        };
        SmallVector<SourceUnit> sourceUnits;
        DenseMap<ManagedFunction*, unsigned> sourceUnitByOwner;
        for (auto&& [function, info] : Managed_) {
            sourceUnitByOwner[info.get()] = sourceUnits.size();
            sourceUnits.push_back({info.get()});
        }
        for (auto&& region : Regions_) {
            auto found = sourceUnitByOwner.find(region->Owner);
            if (found == sourceUnitByOwner.end()) {
                report_fatal_error("stackify: continuation region lost its source-function owner");
            }
            SourceUnit& source = sourceUnits[found->second];
            source.Regions.push_back(region.get());
            source.Size += region->Size;
            source.BorrowedContext |= region->BorrowedContext;
        }

        // A single managed source function whose continuation regions together
        // exceed the verifier's per-subprogram complexity cannot load as one
        // dispatch root: Linux caps a subprogram's CFG jump sequence at
        // BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192), and lua's luaV_execute compiles
        // to a step well past that. The regions are disconnected CFG
        // components that exchange state only through the fiber stack (proved
        // above: no value crosses a region), so an oversized source splits
        // into several units. Each becomes its own dispatch root, and the PC
        // table routes every region to its owning root unchanged. Sources
        // under the cap stay whole, preserving the source-function unit.
        {
            SmallVector<SourceUnit> partitioned;
            partitioned.reserve(sourceUnits.size());
            for (SourceUnit& source : sourceUnits) {
                if (source.Size <= MaxUnitLoad || source.Regions.size() <= 1) {
                    partitioned.push_back(std::move(source));
                    continue;
                }
                unsigned parts = unsigned(std::min<uint64_t>(source.Regions.size(), divideCeil(source.Size, MaxUnitLoad)));
                SmallVector<SourceUnit> pieces(parts);
                for (SourceUnit& piece : pieces) {
                    piece.Owner = source.Owner;
                    piece.BorrowedContext = source.BorrowedContext;
                }
                SmallVector<Region*> regions(source.Regions.begin(), source.Regions.end());
                llvm::stable_sort(regions, [](const Region* left, const Region* right) { return left->Size > right->Size; });
                for (Region* region : regions) {
                    unsigned best = 0;
                    for (unsigned part = 1; part < parts; ++part) {
                        if (pieces[part].Size < pieces[best].Size) {
                            best = part;
                        }
                    }
                    pieces[best].Regions.push_back(region);
                    pieces[best].Size += region->Size;
                }
                for (SourceUnit& piece : pieces) {
                    partitioned.push_back(std::move(piece));
                }
            }
            sourceUnits = std::move(partitioned);
        }

        SmallVector<SourceUnit*> scalarSources;
        SmallVector<SourceUnit*> borrowedSources;
        for (SourceUnit& source : sourceUnits) {
            if (source.Regions.empty()) {
                report_fatal_error(Twine("stackify: managed source function has no continuation region: ") + source.Owner->Original->getName());
            }
            auto& list = source.BorrowedContext ? borrowedSources : scalarSources;
            list.push_back(&source);
        }
        auto largestFirst = [](const SourceUnit* left, const SourceUnit* right) { return left->Size > right->Size; };
        llvm::stable_sort(scalarSources, largestFirst);
        llvm::stable_sort(borrowedSources, largestFirst);

        // Source functions are the natural optimization and allocation unit:
        // their suspension regions share code and semantics, while unrelated
        // source functions never need one arbitrary packing policy. These
        // functions are temporary and disappear in MachineFlatten, so their
        // count does not consume the kernel's emitted-function limit.
        unsigned scalarUnitCount = scalarSources.size();
        unsigned borrowedUnitCount = borrowedSources.size();

        // Count every definition that can conservatively survive emission;
        // managed originals are declarations after their bodies move into
        // staging functions, and staging functions disappear below.
        const bool scalarDriver = NeedsScalarDriver();
        unsigned reservedFunctions = 0;
        for (Function& function : Module_) {
            const bool removedScalarDriver = !scalarDriver && (function.getName() == bpf::sym::Trampoline || function.getName() == bpf::sym::TrampolineL1);
            const bool removedBorrowedDriver =
                !BorrowedContext_ && (function.getName() == bpf::sym::TrampolineCtx || function.getName() == bpf::sym::TrampolineCtxL1);
            if (!function.isDeclaration() && !function.getName().starts_with(bpf::sym::StagePrefix)) {
                reservedFunctions += !removedScalarDriver && !removedBorrowedDriver;
            }
        }
        unsigned classCount = unsigned(!scalarSources.empty()) + unsigned(!borrowedSources.empty());
        // These definitions are created after Stackify, so they are absent
        // from the module count above. A signature needs one dispatcher step. Fixed
        // memory always emits four load and four store accessors; arena
        // memory emits its initializer and the public initialization entry.
        unsigned laterFunctions = classCount + (FixedMemory_ ? 8u : 2u);
        if (reservedFunctions + laterFunctions > MaxBpfFunctions) {
            report_fatal_error("stackify: non-Capsule BPF functions exhaust the kernel's 256-function limit");
        }
        unsigned unitCount = scalarUnitCount + borrowedUnitCount;
        CreateAllocationUnits(scalarUnitCount, borrowedUnitCount);

        SmallVector<uint64_t> load(unitCount, 0);
        auto placeSource = [&](SourceUnit& source, unsigned unit) {
            load[unit] = source.Size;
            for (Region* region : source.Regions) {
                region->Unit = unit;
                Units_[unit].States.append(region->States);
            }
        };
        for (auto&& [index, source] : enumerate(scalarSources)) {
            placeSource(*source, index);
        }
        for (auto&& [index, source] : enumerate(borrowedSources)) {
            placeSource(*source, scalarUnitCount + index);
        }
        for (unsigned index = 0; index < unitCount; ++index) {
            Units_[index].DispatchKey = index;
        }
        // Keep source functions as independent register-allocation units, but
        // do not join all of them into one verifier function. The kernel's
        // liveness pass fixed-points over the complete containing subprogram;
        // a very large root therefore has poor load time. Extra roots are not
        // free, however: their routers and prologues add static and verifier
        // work. The policy below uses only enough roots to bound root size,
        // within the slots left by the kernel ABI.
        unsigned rootBudget = MaxBpfFunctions - reservedFunctions - laterFunctions;
        struct RootClass {
            unsigned Begin;
            unsigned Units;
            uint64_t Load;
            unsigned* Roots;
            unsigned DesiredRoots = 1;
        };
        SmallVector<RootClass, 2> rootClasses;
        auto addRootClass = [&](unsigned begin, unsigned count, unsigned& roots) {
            // A sole unit already owns its public step directly and needs no
            // second call level. A borrowed unit can do that only when there
            // is no scalar class for its driver to route into.
            bool merged = begin == 0 ? count == 1 : count == 1 && scalarUnitCount == 0;
            if (!count || merged) {
                return;
            }
            uint64_t total = 0;
            for (unsigned index = begin; index < begin + count; ++index) {
                total += load[index];
            }
            // A class whose complete load fits one root gains nothing from
            // the funnel layer: every unit would get a 1:1 wrapper call. The
            // whole class merges into its public step instead — the single
            // fast function small programs always had. Only a class too big
            // for one verifier-checked function pays for output roots — and
            // a mixed object always does: the borrowed step routes into the
            // scalar class, and two merged (physical) frames cannot nest, so
            // both classes keep thin routers over roots.
            bool aloneInObject = begin == 0 ? borrowedUnitCount == 0 : scalarUnitCount == 0;
            if (total <= RootLoadTarget && aloneInObject) {
                return;
            }
            rootClasses.push_back({begin, count, total, &roots});
        };
        addRootClass(0, scalarUnitCount, PhysicalScalarRoots_);
        addRootClass(scalarUnitCount, borrowedUnitCount, PhysicalBorrowedRoots_);

        // First give each ABI class one root, then double the class with the
        // largest average IR load until it reaches its load-derived balanced
        // count or no complete split fits. A class can never receive more
        // roots than source functions, and spare slots alone never create
        // another root.
        //
        // Derive each class root count from its load: the largest power of two
        // not exceeding the target-derived count (which keeps the pre-step
        // dispatch tree balanced), clamped by units, remaining slots, and a
        // hard cap. A one-root class merges into its public step and pays no
        // routing at all. The kernel's stack liveness analysis re-sweeps the
        // whole containing subprogram per stack-mark update, so load time
        // grows with (updates x root size)
        // - measured 5.9s at 24 roots vs 41.1s at one root for lua - while
        // verification exploration is provably unchanged across root counts
        // (1.27M vs 1.24M processed insns for the same object). See
        // DESIGN.md "Stackify: regions, loops, dispatch".
        if (rootClasses.size() > rootBudget) {
            report_fatal_error("stackify: managed roots exhaust the kernel's 256-function limit");
        }
        for (RootClass& candidate : rootClasses) {
            uint64_t ideal = std::max<uint64_t>(1, divideCeil(candidate.Load, RootLoadTarget));
            uint64_t bounded = std::min<uint64_t>({ideal, MaxMergeRoots, candidate.Units});
            candidate.DesiredRoots = unsigned(llvm::bit_floor(bounded));
            *candidate.Roots = 1;
            --rootBudget;
        }
        for (;;) {
            unsigned best = rootClasses.size();
            for (unsigned index = 0; index < rootClasses.size(); ++index) {
                const RootClass& candidate = rootClasses[index];
                unsigned current = *candidate.Roots;
                if (current >= candidate.DesiredRoots || current > rootBudget) {
                    continue;
                }
                if (best == rootClasses.size() || __uint128_t(candidate.Load) * *rootClasses[best].Roots > __uint128_t(rootClasses[best].Load) * current) {
                    best = index;
                }
            }
            if (best == rootClasses.size()) {
                break;
            }
            unsigned added = *rootClasses[best].Roots;
            *rootClasses[best].Roots *= 2;
            rootBudget -= added;
        }

        auto assignRoots = [&](unsigned begin, unsigned count, unsigned roots) {
            if (!roots) {
                return;
            }
            SmallVector<uint64_t, 32> rootLoad(roots, 0);
            for (unsigned index = begin; index < begin + count; ++index) {
                unsigned best = 0;
                for (unsigned root = 1; root < roots; ++root) {
                    if (rootLoad[root] < rootLoad[best]) {
                        best = root;
                    }
                }
                Units_[index].OutputRoot = best;
                rootLoad[best] += load[index];
            }
        };
        assignRoots(0, scalarUnitCount, PhysicalScalarRoots_);
        assignRoots(scalarUnitCount, borrowedUnitCount, PhysicalBorrowedRoots_);
        if (BoundedDispatch_) {
            // Units arrive largest-first. Greedily distribute them over the
            // local v3 dispatchers, then encode (shard, local slot) in the
            // private PC table value. A contiguous largest-first assignment
            // makes the first local tree exceed the branch span on QuickJS;
            // balancing estimated IR load keeps every local tree/body window
            // near the global average without adding a runtime table lookup.
            struct DispatchShard {
                uint64_t Load = 0;
                unsigned Count = 0;
            };
            unsigned shardCount = divideCeil(unitCount, V3DispatchShardUnits);
            SmallVector<DispatchShard, 16> shards(shardCount);
            for (unsigned index = 0; index < unitCount; ++index) {
                unsigned best = 0;
                for (unsigned shard = 1; shard < shardCount; ++shard) {
                    bool bestFull = shards[best].Count == V3DispatchShardUnits;
                    bool shardAvailable = shards[shard].Count != V3DispatchShardUnits;
                    if (shardAvailable && (bestFull || shards[shard].Load < shards[best].Load)) {
                        best = shard;
                    }
                }
                Units_[index].DispatchKey = best * V3DispatchShardUnits + shards[best].Count++;
                shards[best].Load += load[index];
            }
        }

        // Kernels without BPF_JMP32_JA cannot encode a dense instruction
        // array.  Keep their verifier state bounded by loading the allocation
        // unit from a read-only table before the sparse comparison tree.
        // Newer targets route the PC directly and have no such data access.
        if (!DirectDispatch_ && llvm::any_of(Units_, [](const AllocationUnit& unit) { return !unit.Merged; })) {
            SmallVector<uint32_t> pcUnits(NextPc_, uint32_t(-1));
            for (auto&& region : Regions_) {
                for (auto state : region->States) {
                    pcUnits[state.Pc] = Units_[region->Unit].DispatchKey;
                }
            }
            auto* pcUnitType = ArrayType::get(I32_, pcUnits.size());
            PcUnitTable_ =
                new GlobalVariable(Module_, pcUnitType, true, GlobalValue::ExternalLinkage, ConstantDataArray::get(Ctx_, pcUnits), bpf::sym::PcUnitTable);
            PcUnitTable_->setSection(bpf::sym::PcUnitSection);
            PcUnitTable_->setAlignment(Align(4));
            PcUnitTable_->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        }

        // Move complete regions into their physical unit.
        for (auto&& regionPtr : Regions_) {
            Region& region = *regionPtr;
            Function* destination = Units_[region.Unit].Func;
            for (BasicBlock* block : region.Blocks) {
                destination->splice(destination->end(), region.Owner->Stage, block->getIterator());
            }
        }
        // A helper-visible source alloca has now reached the one physical
        // unit containing its complete non-suspendable lifetime. Move its
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
                if (llvm::none_of(Units_, [&](const AllocationUnit& unit) { return unit.Func == useOwner; })) {
                    report_fatal_error("stackify: helper-visible alloca use did not reach a physical step unit");
                }
                if (owner && useOwner != owner) {
                    report_fatal_error("stackify: helper-visible alloca crosses physical step units");
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
            auto replaceUses = [&](Value* value, auto unitValue, StringRef what) {
                for (Use& use : make_early_inc_range(value->uses())) {
                    auto* user = cast<Instruction>(use.getUser());
                    if (user->getParent() == info.Entry) {
                        continue;
                    }
                    Region* region = byBlock.lookup(user->getParent());
                    if (!region) {
                        report_fatal_error(Twine("stackify: ") + what + " use outside region in " + func->getName());
                    }
                    use.set(unitValue(Units_[region->Unit]));
                }
            };
            replaceUses(info.Fp, [](AllocationUnit& unit) { return unit.Fp; }, "FP");
            replaceUses(info.Frame, [](AllocationUnit& unit) { return unit.Frame; }, "frame");
            replaceUses(info.Control, [&](AllocationUnit& unit) { return NativeFiberControls_.lookup(unit.Func); }, "fiber control");
            func->setSubprogram(nullptr);
            NativeFiberControls_.erase(info.Stage);
            info.Stage->eraseFromParent();
            info.Stage = nullptr;
            info.Entry = nullptr;
            info.Fp = nullptr;
            info.Frame = nullptr;
            info.Control = nullptr;
        }

        for (auto&& unit : Units_) {
            if (unit.Subprogram) {
                RemapDebugLocations(*unit.Func, *unit.Subprogram);
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
        bpf::stats() << "stackify: " << Regions_.size() << " regions, " << unitCount << " allocation units, largest IR load " << largest << ", largest region "
                     << largestRegion->Size << " (" << largestRegion->Owner->Original->getName() << ")\n";
    }

    void FinishAllocationUnits() {
        for (auto&& unit : Units_) {
            if (unit.States.empty()) {
                report_fatal_error("stackify: physical step unit has no continuation state");
            }
            BasicBlock* entry = unit.Dispatch;
            if (!entry) {
                report_fatal_error("stackify: physical unit has no dispatch entry");
            }
            if (unit.Merged) {
                // The merged unit performs the dispatcher's lifecycle
                // checks itself: idle, completed (sweeping the sentinel to
                // idle), or a published exit stops the driver loop; any
                // other pc dispatches. No pc range check is needed — the
                // dispatch tree's default edge already rejects unknown pcs.
                auto* lifecycle = BasicBlock::Create(Ctx_, "step.lifecycle", unit.Func, entry);
                auto* terminal = BasicBlock::Create(Ctx_, "step.terminal", unit.Func, entry);
                auto* completed = BasicBlock::Create(Ctx_, "step.completed", unit.Func, entry);
                auto* stop = BasicBlock::Create(Ctx_, "step.stop", unit.Func, entry);
                SmallVector<BasicBlock*, 2> entryPredecessors(predecessors(entry));
                if (entryPredecessors.empty()) {
                    report_fatal_error("stackify: merged step dispatch has no entry predecessor");
                }
                for (BasicBlock* predecessor : entryPredecessors) {
                    predecessor->getTerminator()->replaceSuccessorWith(entry, lifecycle);
                }
                IRBuilder<> lb(lifecycle);
                Value* pcSlot = PcPtr(lb);
                Value* pc = lb.CreateLoad(I32_, pcSlot, "pc");
                Value* isCompleted = lb.CreateICmpEQ(pc, DonePc());
                Value* hasExited = lb.CreateICmpNE(lb.CreateLoad(I64_, OutcomePtr(lb)), ConstantInt::get(I64_, 0));
                Value* isIdle = lb.CreateICmpEQ(pc, ConstantInt::get(I32_, 0));
                Value* isTerminal = lb.CreateOr(isCompleted, hasExited);
                Value* stopped = lb.CreateOr(isIdle, isTerminal);
                lb.CreateCondBr(stopped, terminal, entry);
                IRBuilder<> tlb(terminal);
                tlb.CreateCondBr(isCompleted, completed, stop);
                IRBuilder<> clb(completed);
                clb.CreateStore(ConstantInt::get(I32_, 0), pcSlot);
                clb.CreateBr(stop);
                IRBuilder<> slb(stop);
                slb.CreateRet(ConstantInt::get(I32_, 1));
            }
            IRBuilder<> b(entry);
            auto* pc = b.CreateLoad(I32_, PcPtr(b), "pc");

            BasicBlock* unknown = nullptr;
            if (unit.Merged) {
                // A directly emitted step has no outer ownership table and
                // must validate its own sparse PC space.
                unknown = BasicBlock::Create(Ctx_, "unit.unknown", unit.Func);
                IRBuilder<> ub(unknown);
                PublishExit(ub, unit.Func->getArg(FiberArgumentIndex(unit.BorrowedContext)), CAPSULE_ERROR_INVALID_DISPATCH);
                ub.CreateRet(ConstantInt::get(I32_, ActionContinue));
            }

            llvm::stable_sort(unit.States, [](const auto& a, const auto& b) { return a.Pc < b.Pc; });
            struct TestRange {
                BasicBlock* Block;
                unsigned Begin;
                unsigned End;
            };
            // A count-balanced comparison tree gives every state at most
            // ceil(log2(N)) tests without carrying profile policy or weights
            // in the continuation ABI.
            SmallVector<TestRange, 32> pending;
            pending.push_back({entry, 0, unsigned(unit.States.size())});
            while (!pending.empty()) {
                TestRange range = pending.pop_back_val();
                IRBuilder<> tb(range.Block);
                if (range.End - range.Begin == 1) {
                    auto state = unit.States[range.Begin];
                    if (unknown) {
                        tb.CreateCondBr(tb.CreateICmpEQ(pc, ConstantInt::get(I32_, state.Pc)), state.Root, unknown);
                    } else {
                        // The root's PC table selected this unit, so reaching
                        // a leaf proves exact membership without another
                        // comparison or error path.
                        tb.CreateBr(state.Root);
                    }
                    continue;
                }

                unsigned middle = range.Begin + (range.End - range.Begin) / 2;
                auto* left = BasicBlock::Create(Ctx_, "unit.test.left", unit.Func, unknown);
                auto* right = BasicBlock::Create(Ctx_, "unit.test.right", unit.Func, unknown);
                tb.CreateCondBr(tb.CreateICmpULT(pc, ConstantInt::get(I32_, unit.States[middle].Pc)), left, right);
                pending.push_back({right, middle, range.End});
                pending.push_back({left, range.Begin, middle});
            }

            if (unit.Subprogram) {
                SmallVector<BasicBlock*, 2> debugBlocks{entry};
                if (unknown) {
                    debugBlocks.push_back(unknown);
                }
                for (BasicBlock* block : debugBlocks) {
                    for (auto&& inst : *block) {
                        inst.setDebugLoc(DILocation::get(Ctx_, 0, 0, unit.Subprogram));
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

    struct ChunkCandidate {
        BasicBlock* Header = nullptr;
        BasicBlock* Latch = nullptr;
        BasicBlock* Entry = nullptr;
        unsigned Trips = 0;
        SmallVector<BasicBlock*, 8> Blocks;
        unsigned BaselineTrips = 0;
        unsigned PreferredTrips = 0;
        uint64_t BaselineCost = 0;
        uint64_t PreferredCost = 0;
        uint64_t EstimatedFrequency = 1;
        bool HasDedicatedEntry = false;
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
        counter->addIncoming(ConstantInt::get(I32_, 0), chunk.Entry);
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

    DenseMap<Function*, uint64_t> EstimateManagedFunctionHotness() {
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
        // call to its type-compatible address-taken targets, weighted by the
        // caller's own frequency and the site's loop depth.
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
        return functionHotness;
    }

    // A fully virtualized loop is the universal fallback: it is resumable,
    // places no trip-count burden on the verifier, and works on every target.
    // It is also needlessly expensive for a small loop whose bound is already
    // visible in the optimized IR.  Keep only the conservative, profitable
    // subset below as real BPF loops. Exact straight-line loops, resumable
    // chunks, and fully virtualized loops share one verifier-cost model.
    void ClassifyLoops() {
        // Keep the verifier-visible work carried around one native backedge
        // small relative to the complete containing root. This is a compiler
        // policy limit; each loop's cost is derived from its own operations
        // below, including the fixed-memory lowering that has not run yet.
        constexpr uint64_t LoopVerifierCostLimit = 1024;
        struct GuardCandidate {
            BasicBlock* Header;
            BasicBlock* Latch;
            BasicBlock* Preheader;
            unsigned Trips;
        };
        SmallVector<GuardCandidate> guards;
        uint64_t native = 0;
        uint64_t chunked = 0;
        uint64_t virtualized = 0;
        uint64_t savedBackedges = 0;
        uint64_t chunkBackedges = 0;
        uint64_t rejectedShape = 0;
        uint64_t rejectedCalls = 0;
        uint64_t rejectedBound = 0;
        uint64_t rejectedTrips = 0;
        SmallVector<ChunkCandidate> chunks;
        DenseMap<Function*, uint64_t> functionHotness = EstimateManagedFunctionHotness();

        TargetLibraryInfoImpl tliImpl(Triple(Module_.getTargetTriple()));
        TargetLibraryInfo tli(tliImpl);
        for (auto&& [func, info] : Managed_) {
            AssumptionCache ac(*func);
            DominatorTree dt(*func);
            LoopInfo li(dt);
            ScalarEvolution se(*func, tli, ac, dt, li);

            for (Loop* loop : li.getLoopsInPreorder()) {
                uint64_t verifierBodyCost = 0;
                unsigned branchFanout = 0;
                bool managedCall = false;
                bool nonScalarExecutableCall = false;
                for (BasicBlock* block : loop->blocks()) {
                    // A loop with several data-dependent paths is much more
                    // expensive for the verifier than a straight-line loop
                    // of the same IR size: every retained iteration carries
                    // those distinct abstract states around the backedge.
                    // Count excess CFG successors as a small, target-agnostic
                    // proxy for that cost.  The latch itself contributes one,
                    // as it should -- its exit condition also evolves state.
                    branchFanout += block->getTerminator()->getNumSuccessors() > 0 ? block->getTerminator()->getNumSuccessors() - 1 : 0;
                    for (Instruction& inst : *block) {
                        verifierBodyCost = SaturatingAdd(verifierBodyCost, EstimatedVerifierInstructionCost(inst));
                        // BPF has no conditional move.  LLVM selects therefore
                        // become control-flow branches after this pass and must
                        // count toward the verifier's path product even though
                        // they are not CFG successors yet.
                        branchFanout += isa<SelectInst>(inst);
                        auto* call = dyn_cast<CallBase>(&inst);
                        managedCall |= call && IsManagedCall(call);
                        bool executable = call && !isa<IntrinsicInst>(call);
                        // An explicitly proven nosuspend operation has a
                        // scalar ABI, bounded local loops, and its own global-
                        // subprogram verifier proof. It is safe to invoke from a native chunk without
                        // turning the source call into a suspension boundary.
                        // Numbered helpers and kfuncs are also physical BPF
                        // calls, not Capsule suspension points.  The earlier
                        // verifier-pointer backedge proof guarantees that a
                        // capability they return is dead before this loop's
                        // latch; keeping several iterations in one physical
                        // step therefore does not extend its lifetime.  Empty
                        // scalar inline-asm is Clang's common range barrier and
                        // is equally safe.  Other asm and ordinary calls keep
                        // the conservative one-iteration fallback.
                        Function* callee = executable ? call->getCalledFunction() : nullptr;
                        auto scalarType = [](Type* type) { return type->isVoidTy() || (type->isIntegerTy() && type->getIntegerBitWidth() <= 64); };
                        auto* assembly = call && call->isInlineAsm() ? cast<InlineAsm>(call->getCalledOperand()) : nullptr;
                        bool scalarBarrier = assembly && assembly->getAsmString().empty() && scalarType(call->getType()) &&
                            llvm::all_of(call->args(), [&](const Use& argument) { return scalarType(argument->getType()); });
                        bool physicalCall = call &&
                            ((callee && (callee->getMetadata(bpf::md::NoSuspend) || callee->getMetadata(bpf::md::NativeScalar))) ||
                                bpf::IsVerifierCall(*call) || scalarBarrier || (callee && callee == BorrowedCurrent_));
                        nonScalarExecutableCall |= executable && !physicalCall;
                    }
                }

                // Innermost, simplified single-latch loops stay self-contained when
                // calls and physical continuation regions are formed.  SCEV's
                // predicate-free maximum is a proof over the actual optimized
                // IR, rather than a source annotation the verifier may not be
                // able to reproduce.
                unsigned exactTrips = se.getSmallConstantTripCount(loop);
                // SCEV maximum-trip proofs qualify too: the loop then lacks a
                // verifier-visible constant exit, so admission synthesizes a
                // tiny induction guard (GuardNativeLoop) that makes the bound
                // real for the kernel.
                unsigned trips = exactTrips ? exactTrips : se.getSmallConstantMaxTripCount(loop);
                BasicBlock* latch = loop->getLoopLatch();
                BasicBlock* preheader = loop->getLoopPreheader();
                BasicBlock* predecessor = loop->getLoopPredecessor();
                bool nativeShape = loop->isInnermost() && latch && preheader && loop->isLoopSimplifyForm();
                // Branches and fixed-memory expansion are costs, not target
                // switches.  Charge both below and let the same local
                // verifier envelope decide how many iterations survive.
                unsigned pathBits = branchFanout ? std::min(branchFanout - 1, 4u) : 0;
                uint64_t pathFactor = uint64_t(1) << pathBits;
                uint64_t entryFactor = preheader ? 1 : 2;
                auto verifierCost = [&](unsigned count) {
                    return SaturatingMultiply(SaturatingMultiply(uint64_t(count - 1), verifierBodyCost), pathFactor * entryFactor);
                };
                unsigned maxNativeTrips = branchFanout <= 1 ? NativeLinearTripLimit : ChunkTripLimit;
                // Exact and predicate-free maximum proofs both qualify: the
                // guard below turns either proof into the simple induction
                // bound the kernel can see. A large body carried around a long
                // backedge still multiplies verifier work, so admission is
                // subject to the same local expansion budget as chunking.
                bool guardedCost = trips && verifierCost(trips) <= LoopVerifierCostLimit;
                bool keepNative = !TestSuspendAllLoops && nativeShape && !managedCall && trips <= maxNativeTrips && guardedCost;
                if (!keepNative) {
                    if (!nativeShape) {
                        rejectedShape++;
                    } else if (managedCall) {
                        rejectedCalls++;
                    } else if (!trips) {
                        rejectedBound++;
                    } else if (trips > maxNativeTrips) {
                        rejectedTrips++;
                    }
                    // Dynamic loops are the hot case in interpreters and
                    // codecs.  Running one managed dispatch per traversal is
                    // correct but catastrophically expensive.  A bounded
                    // native chunk retains exact suspension semantics while
                    // amortizing dispatch and PC selection.
                    // A managed call cannot carry a chunk counter across its
                    // suspension. Ordinary subprograms are also excluded:
                    // nesting a bounded callee loop inside a large chunk has
                    // multiplied verifier exploration past the analysis
                    // budget. Explicit nosuspend operations are independently
                    // bounded and verified as global scalar subprograms.
                    // Straight-line loops create one evolving verifier state,
                    // so their chunk only adds linear work.
                    // Every loop starts from the same conservative ceiling;
                    // its body, branch fanout, entry shape and memory lowering
                    // reduce that ceiling through verifierCost().
                    const unsigned baselineMaxChunkTrips = ChunkTripLimit;
                    // Linear loops may request a larger local optimum; the
                    // marginal-cost allocator below spends finite global
                    // verifier headroom on the hottest requests instead of
                    // changing every loop at one arbitrary module-size cliff.
                    const unsigned desiredMaxChunkTrips = branchFanout <= 1 ? 16 : ChunkTripLimit;
                    auto sizeChunk = [&](unsigned maximum) {
                        if (!verifierBodyCost) {
                            return 0u;
                        }
                        uint64_t oneBackedgeCost = verifierCost(2);
                        if (!oneBackedgeCost || oneBackedgeCost > LoopVerifierCostLimit) {
                            return 0u;
                        }
                        return std::min<unsigned>(maximum, 1 + LoopVerifierCostLimit / oneBackedgeCost);
                    };
                    unsigned baselineTrips = sizeChunk(baselineMaxChunkTrips);
                    unsigned desiredTrips = std::max(sizeChunk(desiredMaxChunkTrips), baselineTrips);
                    // Chunking only rewires the unique latch -> header edge;
                    // unlike full LoopSimplify it does not consume or modify
                    // exit blocks. It also only needs one outside predecessor
                    // to seed carried PHIs; that predecessor may own a second
                    // zero-trip exit edge and therefore need not satisfy
                    // LLVM's stricter preheader definition.
                    BasicBlock* chunkEntry = preheader ? preheader : predecessor;
                    bool canChunk = loop->isInnermost() && latch && chunkEntry && !nonScalarExecutableCall && baselineTrips >= 2;
                    if (canChunk) {
                        ChunkCandidate candidate;
                        candidate.Header = loop->getHeader();
                        candidate.Latch = latch;
                        candidate.Entry = chunkEntry;
                        candidate.Blocks.append(loop->block_begin(), loop->block_end());
                        // Each source branch is a potential verifier path;
                        // selects count above because the BPF backend lowers
                        // them to branches.  Cap the multiplier to keep the
                        // estimate useful instead of overflowing on a
                        // switch-heavy loop.
                        uint64_t hotness = functionHotness.lookup(func);
                        unsigned loopDepth = li.getLoopDepth(loop->getHeader());
                        hotness = SaturatingMultiply(hotness, uint64_t(1) << std::min(loopDepth ? loopDepth - 1 : 0, 12u));
                        candidate.BaselineTrips = baselineTrips;
                        candidate.PreferredTrips = desiredTrips;
                        candidate.BaselineCost = verifierCost(baselineTrips);
                        candidate.PreferredCost = verifierCost(desiredTrips);
                        candidate.EstimatedFrequency = hotness;
                        candidate.HasDedicatedEntry = bool(preheader);
                        chunks.push_back(std::move(candidate));
                        continue;
                    }
                    virtualized++;
                    continue;
                }

                NativeLoopHeaders_.insert(loop->getHeader());
                native++;
                savedBackedges += trips - 1;
                // Every retained loop gets the induction guard, exact trip
                // counts included: the source counter routinely strength-
                // reduces into pointer compares over arena scalars, which the
                // verifier cannot count — identical backedge states then read
                // as an infinite loop. The guard is the loop bound the kernel
                // can always see.
                guards.push_back({loop->getHeader(), latch, preheader, trips});
            }
        }

        DenseMap<Function*, BasicBlock*> bailByFunction;
        for (auto guard : guards) {
            GuardNativeLoop(guard.Header, guard.Latch, guard.Preheader, guard.Trips, bailByFunction);
        }

        if (TestSuspendAllLoops) {
            virtualized += chunks.size();
            chunks.clear();
        }

        // A monolithic BPF load has a finite cumulative verifier budget, even
        // though its global subprograms are checked independently.  Give every
        // candidate the same local baseline/preferred choices, then allocate
        // that finite resource by marginal dispatches saved per verifier-cost
        // unit.
        // The capacity grows with loops that have a dedicated preheader and
        // always permits one locally preferred candidate. A loop entered
        // directly from a conditional predecessor costs twice as much because
        // the verifier carries both the zero-trip and loop-entry states.
        // A cold branching loop whose expanded paths would drown the verifier
        // simply stays virtualized: suspension is the verifier boundary.
        uint64_t chunkBudget = 0;
        uint64_t singleLoopBudget = 0;
        for (const ChunkCandidate& chunk : chunks) {
            if (chunk.HasDedicatedEntry) {
                chunkBudget = SaturatingAdd(chunkBudget, chunk.BaselineCost);
            }
            singleLoopBudget = std::max(singleLoopBudget, chunk.PreferredCost);
        }
        // A small module must be able to select one locally preferred loop;
        // larger modules contribute the conservative cost of their simple
        // loop-entry shapes. Both terms come from the candidates themselves:
        // there is no module-size threshold or fixed budget floor.
        chunkBudget = std::max(chunkBudget, singleLoopBudget);
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
        // verifier budget: select the best currently available marginal step
        // globally.  A boost becomes eligible only after its base.
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
                    cost = chunk.BaselineCost;
                    gain = __uint128_t(chunk.EstimatedFrequency) * (chunk.BaselineTrips - 1);
                    denominator = chunk.BaselineTrips;
                } else if (chunk.Trips == chunk.BaselineTrips && chunk.PreferredTrips > chunk.BaselineTrips) {
                    cost = chunk.PreferredCost - chunk.BaselineCost;
                    gain = __uint128_t(chunk.EstimatedFrequency) * (chunk.PreferredTrips - chunk.BaselineTrips);
                    denominator = uint64_t(chunk.BaselineTrips) * chunk.PreferredTrips;
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
            selected.Trips = selected.Trips ? selected.PreferredTrips : selected.BaselineTrips;
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
        }

        for (const ChunkCandidate& chunk : chunks) {
            if (chunk.Trips) {
                PrepareChunkedLoop(chunk);
                if (VerifierPointerError_) {
                    return;
                }
            }
        }
        bpf::stats() << "stackify: retained " << native << " small bounded loops (" << guards.size() << " guarded, " << savedBackedges
                     << " native backedges), chunked " << chunked << " dynamic loops (" << chunkBackedges << " native backedges/chunk, cost " << chunkCost
                     << "/" << chunkBudget << "), virtualized " << virtualized << " loops; native rejects shape/call/bound/trips " << rejectedShape << "/"
                     << rejectedCalls << "/" << rejectedBound << "/" << rejectedTrips << "\n";
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

    static uint64_t SaturatingAdd(uint64_t left, uint64_t right) {
        return left > std::numeric_limits<uint64_t>::max() - right ? std::numeric_limits<uint64_t>::max() : left + right;
    }

    static uint64_t SaturatingMultiply(uint64_t left, uint64_t right) {
        if (!left || !right) {
            return 0;
        }
        return left > std::numeric_limits<uint64_t>::max() / right ? std::numeric_limits<uint64_t>::max() : left * right;
    }

    uint64_t EstimatedVerifierInstructionCost(const Instruction& inst) const {
        if (isa<AllocaInst>(inst)) {
            return 0; // replaced by a frame-relative address later
        }
        if (auto* intrinsic = dyn_cast<IntrinsicInst>(&inst); intrinsic && intrinsic->isLifetimeStartOrEnd()) {
            return 0;
        }
        if (!FixedMemory_ || !isa<LoadInst, StoreInst, AtomicRMWInst, AtomicCmpXchgInst>(inst)) {
            return 1;
        }

        // The fixed-memory pass runs after stackification. Conservatively
        // account here for the concrete work its longest ordinary access path
        // adds: expose the pointer as a scalar, narrow and mask the offset,
        // compare and select a verifier-bounded value, extend and add the map
        // base, then perform the access (or call its separately verified
        // accessor). The empty range barriers emit no BPF instruction.
        constexpr uint64_t ExposePointer = 1;
        constexpr uint64_t NarrowAndMaskOffset = 2;
        constexpr uint64_t BoundOffset = 2;
        constexpr uint64_t MaterializeAddress = 2;
        constexpr uint64_t PerformAccess = 1;
        return ExposePointer + NarrowAndMaskOffset + BoundOffset + MaterializeAddress + PerformAccess;
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
            } else if (auto* load = dyn_cast<LoadInst>(v);
                load && demotedSlots.contains(dyn_cast<AllocaInst>(getUnderlyingObject(load->getPointerOperand())))) {
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
        // correctness requirement, not CFG cleanup; the minimal repro is a
        // scanning loop of the shape `for (...; table[z[i]]; i++)`.
        SmallPtrSet<BasicBlock*, 8> phiBlocks;
        for (PHINode* phi : phis) {
            phiBlocks.insert(phi->getParent());
        }
        SmallVector<std::pair<Instruction*, unsigned>, 8> criticalEdges;
        for (BasicBlock& phiBlock : func) {
            if (!phiBlocks.contains(&phiBlock)) {
                continue;
            }
            SmallPtrSet<BasicBlock*, 8> seenPredecessors;
            for (BasicBlock* predecessor : predecessors(&phiBlock)) {
                if (!seenPredecessors.insert(predecessor).second) {
                    continue;
                }
                Instruction* terminator = predecessor->getTerminator();
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
                    ConstantInt::getTrue(Ctx_), source, PoisonValue::get(source->getType()), source->getName() + ".parallel", terminator->getIterator());
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

    // FinishAllocationUnits eventually adds a direct dispatch edge to every resume
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

    // --------------------------------------------------------------- layout

    std::optional<uint64_t> ReserveFrameBytes(Function& owner, uint64_t& cursor, uint64_t bytes, uint64_t alignment, StringRef purpose) {
        if (!alignment || !isPowerOf2_64(alignment)) {
            report_fatal_error("stackify: internal frame alignment is not a power of two");
        }
        if (cursor > FiberStackSize_ || bytes > FiberStackSize_ || alignment > FiberStackSize_) {
            owner.getContext().emitError(Twine("stackify: frame layout in ") + owner.getName() + " exceeds the " + Twine(FiberStackSize_) +
                "-byte per-fiber stack while reserving " + purpose);
            InputError_ = true;
            return std::nullopt;
        }
        uint64_t padding = (-cursor) & (alignment - 1);
        if (padding > FiberStackSize_ - cursor || bytes > FiberStackSize_ - cursor - padding) {
            owner.getContext().emitError(Twine("stackify: frame layout in ") + owner.getName() + " exceeds the " + Twine(FiberStackSize_) +
                "-byte per-fiber stack while reserving " + purpose);
            InputError_ = true;
            return std::nullopt;
        }
        uint64_t offset = cursor + padding;
        cursor = offset + bytes;
        return offset;
    }

    void ComputeFrameLayout() {
        const DataLayout& dl = Module_.getDataLayout();

        // Every fp/sp is a boundary in one universal frame convention. A
        // static object's explicit alignment therefore contributes to that
        // convention; dynamic objects align their absolute logical offset
        // but still require the backing stack itself to carry the alignment.
        for (auto&& [func, info] : Managed_) {
            for (Instruction& instruction : instructions(*func)) {
                auto* alloca = dyn_cast<AllocaInst>(&instruction);
                if (!alloca || NativeHelperAllocas_.contains(alloca)) {
                    continue;
                }
                TypeSize typeSize = dl.getTypeAllocSize(alloca->getAllocatedType());
                if (typeSize.isScalable()) {
                    func->getContext().emitError(alloca, Twine("stackify: scalable alloca in ") + func->getName());
                    InputError_ = true;
                    return;
                }
                uint64_t alignment = alloca->getAlign().value();
                if (alignment > FiberStackSize_) {
                    func->getContext().emitError(
                        alloca, Twine("stackify: alloca alignment in ") + func->getName() + " exceeds the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
                    InputError_ = true;
                    return;
                }
                StackAlignment_ = std::max(StackAlignment_, alignment);
                if (alloca->isStaticAlloca()) {
                    FrameAlignment_ = std::max(FrameAlignment_, alignment);
                } else if (typeSize.getFixedValue() && alloca->getArraySize()->getType()->getIntegerBitWidth() > 64) {
                    func->getContext().emitError(alloca, Twine("stackify: dynamic alloca count wider than 64 bits in ") + func->getName());
                    InputError_ = true;
                    return;
                }
            }
        }
        StackAlignment_ = std::max(StackAlignment_, FrameAlignment_);

        SmallPtrSet<Function*, 16> roots;
        for (Function& function : Module_) {
            for (Instruction& instruction : instructions(function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                if (!call || !call->getOperandBundle(bpf::md::CallBundle)) {
                    continue;
                }
                Function* root = call->getCalledFunction();
                if (!root || !ManagedByFunction_.contains(root)) {
                    report_fatal_error("stackify: Capsule boundary does not name a managed root");
                }
                roots.insert(root);
            }
        }

        uint64_t largestFrame = 0;
        Function* largestFrameOwner = nullptr;
        uint64_t smallestFrame = UINT64_MAX;
        uint64_t maxPush = ArgumentTopBytes_;
        Function* maxPushOwner = Managed_.front().first;
        uint64_t maxResult = 0;
        Function* maxResultOwner = nullptr;
        for (auto&& [func, info] : Managed_) {
            // The result landing zone: every callee this function invokes
            // writes its result at its own frame boundary, which is this
            // function's sp at the call. The zone keeps those bytes dead;
            // it is the lowest static, and run-time carvings float above
            // their new sp by the same amount.
            uint64_t zone = 0;
            for (Instruction& inst : instructions(*func)) {
                auto* call = dyn_cast<CallBase>(&inst);
                if (!call || !IsManagedCall(call)) {
                    continue;
                }
                zone = std::max(zone, ResultSlotForType(call->getType(), *func));
                if (InputError_) {
                    return;
                }
            }
            uint64_t cursor = zone;
            auto localsOffset = ReserveFrameBytes(*func, cursor, 0, FrameAlignment_, "the result landing zone");
            if (!localsOffset) {
                return;
            }
            info->LocalsOffset = *localsOffset;
            for (auto&& inst : instructions(*func)) {
                if (auto* jump = dyn_cast<CallBase>(&inst); jump && IsSetjmpCall(jump)) {
                    auto offset = ReserveFrameBytes(*func, cursor, 4, 4, "a setjmp result");
                    if (!offset) {
                        return;
                    }
                    info->JumpResultOffsets[jump] = *offset;
                    continue;
                }
                if (auto* save = dyn_cast<IntrinsicInst>(&inst); save && save->getIntrinsicID() == Intrinsic::stacksave) {
                    // The frontier snapshot must survive suspensions between
                    // the save and its restores.
                    auto offset = ReserveFrameBytes(*func, cursor, 8, 8, "a stack-save snapshot");
                    if (!offset) {
                        return;
                    }
                    info->StackSaveOffsets[save] = *offset;
                    continue;
                }
                auto* alloca = dyn_cast<AllocaInst>(&inst);
                if (!alloca || NativeHelperAllocas_.contains(alloca)) {
                    continue;
                }
                if (!alloca->isStaticAlloca()) {
                    // Run-time-sized: no static space; the carving happens
                    // below the frame and only the 8-byte pointer handle
                    // lives here.
                    auto offset = ReserveFrameBytes(*func, cursor, 8, 8, "a dynamic-allocation handle");
                    if (!offset) {
                        return;
                    }
                    info->DynamicHandleOffsets[alloca] = *offset;
                    continue;
                }
                uint64_t alignment = alloca->getAlign().value();
                uint64_t elementBytes = dl.getTypeAllocSize(alloca->getAllocatedType()).getFixedValue();
                auto* countValue = cast<ConstantInt>(alloca->getArraySize());
                uint64_t count = countValue->getValue().getLimitedValue(FiberStackSize_ + 1);
                if (elementBytes && count > FiberStackSize_ / elementBytes) {
                    func->getContext().emitError(
                        alloca, Twine("stackify: static alloca in ") + func->getName() + " exceeds the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
                    InputError_ = true;
                    return;
                }
                uint64_t bytes = elementBytes * count;
                auto offset = ReserveFrameBytes(*func, cursor, bytes, alignment, "a static alloca");
                if (!offset) {
                    return;
                }
                info->AllocaOffsets[alloca] = *offset;
            }

            // Above the statics sit the incoming arguments and linkage; all
            // of it is this frame. The function's own
            // result does not live here: it lands in the caller's zone above
            // fp.
            if (func->arg_size() > (FiberStackSize_ - ArgumentTopBytes_) / ArgSlotSize_) {
                func->getContext().emitError(
                    Twine("stackify: managed arguments in ") + func->getName() + " exceed the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
                InputError_ = true;
                return;
            }
            uint64_t argsArea = uint64_t(func->arg_size()) * ArgSlotSize_;
            uint64_t pushBytes = ArgumentTopBytes_ + argsArea;
            uint64_t callArea = alignTo(pushBytes, FrameAlignment_);
            if (!ReserveFrameBytes(*func, cursor, callArea, FrameAlignment_, "call linkage and arguments")) {
                return;
            }
            info->FrameSize = cursor;
            for (unsigned i = 0; i < func->arg_size(); i++) {
                info->ArgOffsets.push_back(-int64_t(ArgumentTopBytes_ + (i + 1) * ArgSlotSize_));
            }
            if (pushBytes > maxPush) {
                maxPush = pushBytes;
                maxPushOwner = func;
            }
            if (roots.contains(func)) {
                uint64_t resultReserve = alignTo(info->ReturnSize, FrameAlignment_);
                if (resultReserve > maxResult) {
                    maxResult = resultReserve;
                    maxResultOwner = func;
                }
            }
            if (info->FrameSize > largestFrame) {
                largestFrame = info->FrameSize;
                largestFrameOwner = func;
            }
            smallestFrame = std::min(smallestFrame, info->FrameSize);
        }
        // Every descent is bounded at its source: the entry prologue checks
        // its static claim and each carve site checks its request, both
        // against this floor, so sp can neither wrap nor reach the transient
        // spill words at the slice bottom — and the pushes a checked frame
        // makes (linkage + arguments, below its sp) stay above them too.
        ReserveFloor_ = bpf::TransientReserveBytes(FiberStackSize_);
        if (!ReserveFrameBytes(*maxPushOwner, ReserveFloor_, maxPush, 1, "the transient spill and call-push reserve") ||
            !ReserveFrameBytes(*maxPushOwner, ReserveFloor_, 0, FrameAlignment_, "the aligned reserve floor")) {
            return;
        }
        // Above the root's boundary only a native boundary's result lands;
        // internal results already occupy their caller's per-frame zone.
        // Reserve the largest actual root result, never zero because the
        // boundary itself must remain a valid in-slice offset.
        uint64_t rootResultReserve = std::max(FrameAlignment_, maxResult);
        if (rootResultReserve >= FiberStackSize_) {
            Function* owner = maxResultOwner ? maxResultOwner : largestFrameOwner;
            owner->getContext().emitError(Twine("stackify: managed root reserve for ") + owner->getName() + " needs " + Twine(rootResultReserve) +
                " bytes, too large for the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
            InputError_ = true;
            return;
        }
        RootFp_ = FiberStackSize_ - rootResultReserve;
        if (ReserveFloor_ >= RootFp_ || largestFrame > RootFp_ - ReserveFloor_) {
            largestFrameOwner->getContext().emitError(Twine("stackify: managed frame in ") + largestFrameOwner->getName() + " is " + Twine(largestFrame) +
                " bytes, too large for the " + Twine(FiberStackSize_) + "-byte per-fiber stack");
            InputError_ = true;
            return;
        }
        bpf::stats() << "stackify: variable frames " << smallestFrame << ".." << largestFrame << " bytes, " << (RootFp_ - ReserveFloor_) / 1024
                     << " KiB usable per fiber, " << (FiberStackSize_ * FiberCount_) / 1024 << " KiB unified stack storage\n";
    }

    void CreateStackGlobals() {
        auto* stackType = ArrayType::get(I8_, FiberStackSize_ * FiberCount_);
        Stack_ = new GlobalVariable(Module_, stackType, false, GlobalVariable::InternalLinkage, Constant::getNullValue(stackType), bpf::sym::CallStack);
        // Slice alignment is load-bearing: sp/fp are full pointer values,
        // and the slice-offset mask in StackPtr/SliceOffset is exact only
        // when the bank starts on a FiberStackSize_ boundary (both tiers'
        // memory bases are 4GiB-aligned, so image-offset alignment is
        // address alignment).
        Stack_->setAlignment(Align(std::max(StackAlignment_, FiberStackSize_)));
        Stack_->setMetadata(bpf::md::FiberStackSize, MDNode::get(Ctx_, ConstantAsMetadata::get(ConstantInt::get(I64_, FiberStackSize_))));
    }

    // Publish the error in the current fiber. The driver observes it between
    // physical steps and reclaims the managed stack without a kernel-specific
    // exception mechanism.
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
        Value* visibleNext = bpf::BuildVerifierOpaqueIdentity(gb, next, "bpf.loop.iter.visible");
        gb.CreateCondBr(gb.CreateICmpULT(visibleNext, ConstantInt::get(I32_, trips)), header, bail);
        // The phi advances on the VISIBLE increment, not the barrier output:
        // the verifier must watch the counter grow so each iteration is a
        // distinct bounded state; a barrier-opaque counter collapses every
        // backedge into one identical state and reads as an infinite loop
        // (Linux 7.0 rejects exactly that on PureDOOM copy loops). LLVM
        // still cannot delete the exit compare because its operand is opaque.
        counter->addIncoming(next, guard);
        for (Instruction& inst : *guard) {
            inst.setDebugLoc(debugLoc);
        }
    }

    void EmitAbort(IRBuilder<>& b, int32_t code, Value* fiber = nullptr) {
        StoreInst* store = b.CreateStore(ConstantInt::get(I64_, bpf::OutcomeValue(code)), OutcomePtr(b, fiber));
        store->setMetadata(bpf::md::OutcomeStore, MDNode::get(Ctx_, {}));
    }

    // Root a stack location in the bank global as a pointer in the
    // program's unified flat memory. MemoryPass later turns this into an
    // arena pointer. `offset` may be a slice-relative byte offset or a full
    // frame pointer value: the bank is FiberStackSize_-aligned and both
    // memory bases are 4GiB-aligned, so the mask recovers the slice offset
    // from either form. The mask also keeps a corrupt frame address inside
    // its own fiber's slice — defence in depth: every compiler-generated
    // cursor mutation is bounded at the frame claim or carve which performs
    // it, so ordinary execution never relies on wrapping here.
    Value* StackPtr(IRBuilder<>& b, Value* offset, Value* fiber = nullptr) {
        Value* normalizedFiber = NormalizeFiber(b, fiber ? fiber : CurrentFiberValue(b));
        Value* normalized = b.CreateZExtOrTrunc(offset, I64_);
        normalized = b.CreateAnd(normalized, ConstantInt::get(I64_, FiberStackSize_ - 1), "stack.offset");
        Value* linear =
            b.CreateAdd(b.CreateMul(b.CreateZExt(normalizedFiber, I64_), ConstantInt::get(I64_, FiberStackSize_)), normalized, "stack.linear.offset");
        return b.CreateGEP(I8_, Stack_, {linear}, "fiber.stack");
    }

    // Turn a stored frame pointer value (sp/fp, or arithmetic on them) back
    // into a dereferenceable frame pointer. On the arena tier the value is
    // the address; on the fixed tier StackPtr re-roots it in the bank
    // global so the access keeps the direct map-value path.
    Value* FramePointer(IRBuilder<>& b, Value* address, Value* fiber = nullptr) {
        if (ArenaTier_) {
            return b.CreateIntToPtr(address, PointerType::get(Ctx_, 0), "frame.addr");
        }
        return StackPtr(b, address, fiber);
    }

    // A frame pointer value's offset inside its fiber slice, for the
    // overflow floor checks. Exact because the bank start is
    // FiberStackSize_-aligned in the final layout.
    Value* SliceOffset(IRBuilder<>& b, Value* address) {
        return b.CreateAnd(address, ConstantInt::get(I64_, FiberStackSize_ - 1), "slice.offset");
    }

    // The pc register's completed sentinel: all-ones so BPF compares use the
    // sign-extended -1 immediate instead of a two-instruction 64-bit load.
    Constant* DonePc() {
        return ConstantInt::get(I32_, BPF_CAPSULE_PC_DONE);
    }

    Value* ArenaFrameArgument(IRBuilder<>& b, Value* frame) {
        return b.CreateAddrSpaceCast(frame, PointerType::get(Ctx_, 1), "frame.arena");
    }

    // The dispatch anchor: fp is the running frame's boundary — a full
    // pointer value, valid at every dispatch (the machine call operation
    // sets it, the machine return restores it). Statics address as
    // boundary + negative constant.
    void LoadFrameAnchor(IRBuilder<>& b, Value* fiber, Value*& fp, Value*& frame) {
        fp = b.CreateLoad(I64_, FpPtr(b, fiber), "frame.fp");
        frame = FramePointer(b, fp, fiber);
    }

    // ------------------------------------------------------------ transform

    void TransformFunction(ManagedFunction& info) {
        Function& func = *info.Original;
        Function* step = info.Stage;

        // Find the backedges before the body moves: afterwards the blocks
        // belong to the unit function and its CFG is a different shape.
        SmallVector<Backedge> backedges = Backedges(func);

        // Move the body into the unit function. Its blocks keep their own
        // debug locations, rewritten to look like an inline of the original
        // function into the unit — the unit owns the only DISubprogram.
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
        // Staged regions have no native arguments of their own. Materialize
        // the control pointer once while they still share this temporary
        // owner, then replace it with the final physical step's typed control
        // argument after region placement. Without this handoff, every
        // suspend/return site rebuilds &bpf_capsule_fibers[fiber], keeping the
        // scalar fiber ID live across the whole dispatcher and repeating the
        // map-address calculation in region bodies.
        info.Control = FiberControlPtr(b);
        NativeFiberControls_[step] = info.Control;
        Value* fp = nullptr;
        Value* frame = nullptr;
        LoadFrameAnchor(b, nullptr, fp, frame);
        info.Fp = fp;
        info.Frame = frame;
        // The entry prologue is this function's half of the machine call:
        // bound the static claim against the floor, then place sp at the
        // frame base. It roots the entry state; resumes never run it.
        auto* prologue = BasicBlock::Create(Ctx_, func.getName() + ".prologue", step, origEntry);
        auto* claimFail = BasicBlock::Create(Ctx_, func.getName() + ".prologue.overflow", step, origEntry);
        IRBuilder<> pb(prologue);
        Value* claimed = pb.CreateSub(fp, ConstantInt::get(I64_, info.FrameSize), "frame.sp");
        pb.CreateCondBr(pb.CreateICmpULT(SliceOffset(pb, fp), ConstantInt::get(I64_, info.FrameSize + ReserveFloor_)), claimFail, origEntry)
            ->setDebugLoc(debugLoc);
        IRBuilder<> cf(claimFail);
        EmitAbort(cf, CAPSULE_ERROR_STACK_OVERFLOW);
        cf.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
        IRBuilder<> eb(origEntry, origEntry->getFirstInsertionPt());
        eb.CreateStore(claimed, SpPtr(eb))->setDebugLoc(debugLoc);
        info.States.push_back({info.EntryPc, prologue, ManagedFunction::StateKind::Entry});

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
            SmallVector<Instruction*> lifetimes;
            for (auto* u : alloca->users()) {
                if (auto* ii = dyn_cast<IntrinsicInst>(u); ii && ii->isLifetimeStartOrEnd()) {
                    lifetimes.push_back(ii);
                }
            }
            for (auto* lt : lifetimes) {
                lt->eraseFromParent();
            }
            if (auto found = info.AllocaOffsets.find(alloca); found != info.AllocaOffsets.end()) {
                ReplaceAllocaUses(*alloca, frame, int64_t(found->second) - int64_t(info.FrameSize), debugLoc);
            } else if (auto handle = info.DynamicHandleOffsets.find(alloca); handle != info.DynamicHandleOffsets.end()) {
                LowerDynamicAlloca(*alloca, info, handle->second, body, backedges, debugLoc);
            } else {
                report_fatal_error("stackify: alloca is missing from its frame layout");
            }
            alloca->eraseFromParent();
        }
        LowerStackSaves(info, body, debugLoc);
        if (InputError_) {
            return;
        }

        // Arguments are reloaded from the frame at each use, so they never
        // need to survive a suspension.
        for (auto&& [idx, arg] : enumerate(func.args())) {
            ReplaceArgumentUses(arg, frame, info.ArgOffsets[idx], debugLoc);
        }

        SmallVector<CallBase*> calls;
        SmallVector<CallBase*> yields;
        SmallVector<CallBase*> setjmps;
        SmallVector<CallBase*> longjmps;
        for (auto* block : body) {
            for (auto&& inst : *block) {
                if (auto* call = dyn_cast<CallBase>(&inst)) {
                    if (IsManagedCall(call)) {
                        calls.push_back(call);
                    } else if (IsYieldCall(call)) {
                        yields.push_back(call);
                    } else if (IsSetjmpCall(call)) {
                        setjmps.push_back(call);
                    } else if (IsLongjmpCall(call)) {
                        longjmps.push_back(call);
                    }
                }
            }
        }

        // Returns pop the frame. Lower them before splitting at ordinary
        // calls, or a return sharing a block with a call would end up in a
        // resume block that is no longer part of `body`.
        SmallVector<ReturnInst*> returns;
        for (auto* block : body) {
            if (auto* ret = dyn_cast_or_null<ReturnInst>(block->getTerminator())) {
                returns.push_back(ret);
            }
        }
        for (auto* ret : returns) {
            LowerReturn(ret, &func, frame, info, debugLoc);
        }

        for (auto&& edge : backedges) {
            uint32_t resumePc = NextPc_++;
            BasicBlock* root = edge.ChunkTrips ? SuspendAtChunkedBackedge(edge, resumePc, debugLoc) : SuspendAtBackedge(edge, resumePc, debugLoc);
            info.States.push_back({resumePc, root, ManagedFunction::StateKind::Backedge});
        }
        for (auto* call : calls) {
            uint32_t resumePc = NextPc_++;
            info.States.push_back({resumePc, SuspendAtCall(call, frame, resumePc, info, debugLoc), ManagedFunction::StateKind::Call});
        }
        for (auto* call : yields) {
            uint32_t resumePc = NextPc_++;
            info.States.push_back({resumePc, SuspendAtYield(call, resumePc, debugLoc), ManagedFunction::StateKind::Yield});
        }
        for (auto* call : setjmps) {
            uint32_t resumePc = NextPc_++;
            info.States.push_back({resumePc, LowerSetjmp(call, frame, info, resumePc), ManagedFunction::StateKind::Setjmp});
        }
        for (auto* call : longjmps) {
            LowerLongjmp(call);
        }

        // This branch only keeps the staging function structurally complete.
        // Physical unit dispatch replaces it after region formation.
        b.SetInsertPoint(entry);
        b.CreateBr(origEntry)->setDebugLoc(debugLoc);

        for (auto&& inst : *entry) {
            if (!inst.getDebugLoc()) {
                inst.setDebugLoc(debugLoc);
            }
        }
    }

    // Materialize a value beside each eventual use. PHI operands belong to
    // their incoming edge, and multiple switch edges from one block must carry
    // the same SSA value, so those materializations are cached per predecessor.
    template <typename Materialize>
    void RematerializeUses(Value& source, Materialize materialize) {
        DenseMap<BasicBlock*, Value*> phiValues;
        for (Use& use : make_early_inc_range(source.uses())) {
            auto* user = cast<Instruction>(use.getUser());
            if (auto* phi = dyn_cast<PHINode>(user)) {
                BasicBlock* predecessor = phi->getIncomingBlock(use);
                Value*& cached = phiValues[predecessor];
                if (!cached) {
                    cached = materialize(predecessor->getTerminator()->getIterator());
                }
                use.set(cached);
            } else {
                use.set(materialize(user->getIterator()));
            }
        }
    }

    // Like arguments, frame-local pointers are materialized where used. A
    // single GEP in the staging entry could not be shared after regions move
    // into different physical functions.
    void ReplaceAllocaUses(AllocaInst& alloca, Value* frame, int64_t offset, DebugLoc debugLoc) {
        RematerializeUses(alloca, [&](BasicBlock::iterator at) {
            IRBuilder<> b(at->getParent(), at);
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, offset)}, alloca.getName() + ".slot");
            if (auto* inst = dyn_cast<Instruction>(slot)) {
                inst->setDebugLoc(debugLoc);
            }
            return slot;
        });
    }

    void ReplaceArgumentUses(Argument& arg, Value* frame, int64_t offset, DebugLoc debugLoc) {
        RematerializeUses(arg, [&](BasicBlock::iterator at) -> Value* {
            IRBuilder<> b(at->getParent(), at);
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, offset)});
            auto* value = b.CreateLoad(arg.getType(), slot, arg.getName());
            value->setDebugLoc(debugLoc);
            return value;
        });
    }

    // Carve a run-time-sized allocation below the live frontier — which is
    // sp itself. Bound the request, drop sp, and park the resulting pointer
    // in the frame's handle slot for every later region to reload. The
    // carving sits LocalsOffset bytes above the new sp, keeping the result
    // zone free at the frontier for the next call.
    void LowerDynamicAlloca(AllocaInst& alloca, ManagedFunction& info, uint64_t handleOffset, SmallVectorImpl<BasicBlock*>& body,
        SmallVectorImpl<Backedge>& backedges, DebugLoc debugLoc) {
        Value* frame = info.Frame;
        const DataLayout& dl = Module_.getDataLayout();
        uint64_t elemBytes = dl.getTypeAllocSize(alloca.getAllocatedType()).getFixedValue();
        uint64_t align = std::max<uint64_t>(16, alloca.getAlign().value());

        IRBuilder<> b(&alloca);
        Value* pointer = nullptr;
        if (!elemBytes) {
            Value* frontier = b.CreateLoad(I64_, SpPtr(b), "frontier");
            Value* offset = b.CreateAnd(frontier, ConstantInt::get(I64_, ~(align - 1)), "zero.alloca.aligned");
            pointer = FramePointer(b, offset);
        } else {
            Value* frontier = b.CreateLoad(I64_, SpPtr(b), "frontier");
            Value* count = b.CreateZExtOrTrunc(alloca.getArraySize(), I64_, "carve.count");
            // Bounding the element count first keeps the byte product from
            // wrapping; bounding sp against the floor keeps the carving off
            // the transient spill words and leaves room for the next push.
            Value* tooMany = b.CreateICmpUGT(count, ConstantInt::get(I64_, FiberStackSize_ / elemBytes));
            Value* need = b.CreateMul(count, ConstantInt::get(I64_, elemBytes), "carve.bytes");
            // The new frontier must leave this function's result landing zone
            // below the allocation. Otherwise a later managed callee writes
            // its result over the VLA (and the VLA can overlap the existing
            // frame immediately after the carve).
            uint64_t slack = info.LocalsOffset + (align > FrameAlignment_ ? align : 0) + FrameAlignment_ - 1;
            need = b.CreateAnd(b.CreateAdd(need, ConstantInt::get(I64_, slack)), ConstantInt::get(I64_, ~(FrameAlignment_ - 1)));
            Value* low = b.CreateICmpULT(SliceOffset(b, frontier), b.CreateAdd(need, ConstantInt::get(I64_, ReserveFloor_)));
            Value* over = b.CreateOr(tooMany, low, "carve.overflow");

            BasicBlock* block = alloca.getParent();
            BasicBlock* carve = block->splitBasicBlock(&alloca, block->getName() + ".carve");
            body.push_back(carve);
            // Backedge latches were found before this split; a latch whose
            // terminator moved into the tail must follow it.
            for (auto&& edge : backedges) {
                if (edge.Latch == block) {
                    edge.Latch = carve;
                }
            }
            auto* overflow = BasicBlock::Create(Ctx_, block->getName() + ".carve.abort", block->getParent(), carve);
            IRBuilder<> ob(overflow);
            EmitAbort(ob, CAPSULE_ERROR_STACK_OVERFLOW);
            ob.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
            Instruction* br = block->getTerminator();
            b.SetInsertPoint(br);
            b.CreateCondBr(over, overflow, carve)->setDebugLoc(debugLoc);
            br->eraseFromParent();

            b.SetInsertPoint(&alloca);
            Value* next = b.CreateSub(frontier, need, "frontier.next");
            b.CreateStore(next, SpPtr(b));
            Value* offset = b.CreateAdd(next, ConstantInt::get(I64_, info.LocalsOffset));
            if (align > FrameAlignment_) {
                offset = b.CreateAnd(b.CreateAdd(offset, ConstantInt::get(I64_, align - 1)), ConstantInt::get(I64_, ~(align - 1)));
            }
            pointer = FramePointer(b, offset);
        }
        b.CreateStore(
            pointer, b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, int64_t(handleOffset) - int64_t(info.FrameSize))}, alloca.getName() + ".handle"));
        ReplaceDynamicAllocaUses(alloca, frame, int64_t(handleOffset) - int64_t(info.FrameSize), debugLoc);
    }

    // Like static alloca slots, the carved pointer is rematerialized where
    // used — as a load of its handle, since the address is a run-time value.
    void ReplaceDynamicAllocaUses(AllocaInst& alloca, Value* frame, int64_t handleOffset, DebugLoc debugLoc) {
        RematerializeUses(alloca, [&](BasicBlock::iterator at) -> Value* {
            IRBuilder<> b(at->getParent(), at);
            auto* slot = b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, handleOffset)});
            auto* value = b.CreateLoad(alloca.getType(), slot, alloca.getName());
            value->setDebugLoc(debugLoc);
            return value;
        });
    }

    // A stack save snapshots the frontier into its own frame slot; the
    // matching restore reinstates it, releasing every carving made since.
    void LowerStackSaves(ManagedFunction& info, SmallVectorImpl<BasicBlock*>& body, DebugLoc debugLoc) {
        SmallVector<IntrinsicInst*> saves;
        SmallVector<IntrinsicInst*> restores;
        for (auto* block : body) {
            for (auto&& inst : *block) {
                if (auto* ii = dyn_cast<IntrinsicInst>(&inst)) {
                    if (ii->getIntrinsicID() == Intrinsic::stacksave) {
                        saves.push_back(ii);
                    } else if (ii->getIntrinsicID() == Intrinsic::stackrestore) {
                        restores.push_back(ii);
                    }
                }
            }
        }
        Value* frame = info.Frame;
        for (auto* restore : restores) {
            auto* save = dyn_cast<IntrinsicInst>(restore->getArgOperand(0)->stripPointerCasts());
            auto found = save ? info.StackSaveOffsets.find(save) : info.StackSaveOffsets.end();
            if (found == info.StackSaveOffsets.end()) {
                restore->getContext().emitError(
                    restore, Twine("stackify: stack restore does not name a stack save from the same function in ") + info.Original->getName());
                InputError_ = true;
                return;
            }
            IRBuilder<> b(restore);
            Value* saved =
                b.CreateLoad(I64_, b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, int64_t(found->second) - int64_t(info.FrameSize))}), "frontier.saved");
            b.CreateStore(saved, SpPtr(b));
            restore->eraseFromParent();
        }
        for (auto* save : saves) {
            IRBuilder<> b(save);
            Value* frontier = b.CreateLoad(I64_, SpPtr(b), "frontier");
            b.CreateStore(
                frontier, b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, int64_t(info.StackSaveOffsets.lookup(save)) - int64_t(info.FrameSize))}));
            if (!save->use_empty()) {
                // Every legal consumer was a restore, handled above.
                save->replaceAllUsesWith(Constant::getNullValue(save->getType()));
            }
            save->eraseFromParent();
        }
    }

    // Split the block at `call`. The caller's half of the machine call
    // operation is pushing the {resume pc, caller fp} linkage and
    // arguments at fixed offsets below its sp, installing the callee fp, and
    // naming the callee in the pc register. Its prologue claims the frame.
    BasicBlock* SuspendAtCall(CallBase* call, Value* frame, uint32_t resumePc, ManagedFunction& info, DebugLoc debugLoc) {
        BasicBlock* block = call->getParent();
        BasicBlock* resume = block->splitBasicBlock(call, block->getName() + ".resume");

        // block now ends with an unconditional branch into `resume`.
        Instruction* br = block->getTerminator();
        IRBuilder<> b(br);

        Value* calleePc = CalleePc(b, call);
        if (!call->getCalledFunction()) {
            // A computed callee must name a function entry. Entry PCs are
            // the contiguous low range starting at 1, so validity is one
            // compare, checked before any state changes.
            Value* valid =
                b.CreateICmpULT(b.CreateSub(calleePc, ConstantInt::get(I32_, 1)), ConstantInt::get(I32_, uint32_t(Managed_.size())), "callee.pc.valid");
            auto* push = BasicBlock::Create(Ctx_, block->getName() + ".push", block->getParent(), resume);
            auto* invalid = BasicBlock::Create(Ctx_, block->getName() + ".bad.callee", block->getParent(), resume);
            b.CreateCondBr(valid, push, invalid);
            br->eraseFromParent();
            br = nullptr;
            IRBuilder<> ib(invalid);
            EmitAbort(ib, CAPSULE_ERROR_INVALID_DISPATCH);
            ib.CreateRet(ConstantInt::get(I32_, ActionContinue));
            b.SetInsertPoint(push);
        }

        // The pushes land below this frame's sp: its base when it never
        // carves, the live frontier otherwise. The machine call operation is
        // expanded here rather than in the dispatcher because the site
        // already holds the anchor and both register values; the dispatcher
        // would have to re-derive the fiber addressing per call.
        Value* out = frame;
        int64_t bias = -int64_t(info.FrameSize);
        Value* calleeFp = nullptr;
        if (!info.DynamicHandleOffsets.empty() || !info.StackSaveOffsets.empty()) {
            calleeFp = b.CreateLoad(I64_, SpPtr(b), "frontier");
            out = FramePointer(b, calleeFp);
            bias = 0;
        } else {
            calleeFp = b.CreateSub(info.Fp, ConstantInt::get(I64_, info.FrameSize), "callee.fp");
        }
        b.CreateStore(ConstantInt::get(I32_, resumePc), b.CreateGEP(I8_, out, {ConstantInt::getSigned(I64_, bias + ReturnPcOffset)}, "return.pc.slot"));
        b.CreateStore(info.Fp, b.CreateGEP(I8_, out, {ConstantInt::getSigned(I64_, bias + SavedFpOffset)}, "saved.fp.slot"));
        StoreCallArguments(b, out, bias, call);
        b.CreateStore(calleePc, PcPtr(b));
        b.CreateStore(calleeFp, FpPtr(b));
        b.CreateRet(ConstantInt::get(I32_, ActionContinue));
        if (br) {
            br->eraseFromParent();
        }

        // Resume side: the callee wrote its result into this frame's zone,
        // at what was sp when the call was made — and is sp again now that
        // the machine return restored it.
        IRBuilder<> rb(call);
        if (!call->getType()->isVoidTy()) {
            Value* base = frame;
            int64_t rbias = -int64_t(info.FrameSize);
            if (!info.DynamicHandleOffsets.empty() || !info.StackSaveOffsets.empty()) {
                base = FramePointer(rb, rb.CreateLoad(I64_, SpPtr(rb), "frontier.resume"));
                rbias = 0;
            }
            Value* result = rb.CreateGEP(I8_, base, {ConstantInt::getSigned(I64_, rbias)}, "result.zone");
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
    BasicBlock* SuspendAtYield(CallBase* call, uint32_t resumePc, DebugLoc debugLoc) {
        BasicBlock* block = call->getParent();
        BasicBlock* resume = block->splitBasicBlock(call, block->getName() + ".yield.resume");
        Instruction* branch = block->getTerminator();

        IRBuilder<> b(branch);
        b.CreateStore(ConstantInt::get(I32_, resumePc), PcPtr(b))->setDebugLoc(debugLoc);
        b.CreateStore(ConstantInt::get(I64_, CAPSULE_YIELD), OutcomePtr(b))->setDebugLoc(debugLoc);
        b.CreateRet(ConstantInt::get(I32_, ActionYield))->setDebugLoc(debugLoc);
        branch->eraseFromParent();
        call->eraseFromParent();
        return resume;
    }

    // setjmp's ordinary and restored paths meet at one load. The saved state
    // points longjmp at that frame slot, so no value register or unwinder is
    // part of the machine ABI.
    BasicBlock* LowerSetjmp(CallBase* call, Value* frame, ManagedFunction& info, uint32_t resumePc) {
        BasicBlock* block = call->getParent();
        BasicBlock* resume = block->splitBasicBlock(call, block->getName() + ".setjmp.resume");
        int64_t slotOffset = int64_t(info.JumpResultOffsets.lookup(call)) - int64_t(info.FrameSize);
        IRBuilder<> b(block->getTerminator());
        b.SetCurrentDebugLocation(call->getDebugLoc());
        Value* slot = b.CreateGEP(I8_, frame, ConstantInt::getSigned(I64_, slotOffset), "setjmp.slot");
        Value* env = call->getArgOperand(0);
        auto field = [&](int64_t offset) { return b.CreateGEP(I8_, env, ConstantInt::get(I64_, offset)); };
        b.CreateStore(ConstantInt::get(I32_, 0), slot);
        b.CreateStore(ConstantInt::get(I32_, resumePc), field(JumpPcOffset));
        b.CreateStore(b.CreateLoad(I64_, SpPtr(b)), field(JumpSpOffset));
        b.CreateStore(info.Fp, field(JumpFpOffset));
        b.CreateStore(b.CreatePtrToInt(slot, I64_), field(JumpResultOffset));

        IRBuilder<> rb(call);
        rb.SetCurrentDebugLocation(call->getDebugLoc());
        Value* result = rb.CreateLoad(I32_, rb.CreateGEP(I8_, frame, ConstantInt::getSigned(I64_, slotOffset)), "setjmp.result");
        call->replaceAllUsesWith(result);
        call->eraseFromParent();
        return resume;
    }

    // A non-local jump is a terminal continuation transfer: publish the
    // requested return value, restore the saved software registers, dispatch.
    void LowerLongjmp(CallBase* call) {
        IRBuilder<> b(call);
        b.SetCurrentDebugLocation(call->getDebugLoc());
        Value* env = call->getArgOperand(0);
        auto load = [&](Type* type, int64_t offset) { return b.CreateLoad(type, b.CreateGEP(I8_, env, ConstantInt::get(I64_, offset))); };
        Value* value = call->getArgOperand(1);
        value = b.CreateSelect(b.CreateICmpEQ(value, ConstantInt::get(I32_, 0)), ConstantInt::get(I32_, 1), value, "longjmp.value");
        b.CreateStore(value, b.CreateIntToPtr(load(I64_, JumpResultOffset), PointerType::get(Ctx_, 0)));
        b.CreateStore(load(I64_, JumpSpOffset), SpPtr(b));
        b.CreateStore(load(I64_, JumpFpOffset), FpPtr(b));
        b.CreateStore(load(I32_, JumpPcOffset), PcPtr(b));
        b.CreateRet(ConstantInt::get(I32_, ActionContinue));
        for (Instruction* inst = call; inst;) {
            Instruction* next = inst->getNextNode();
            inst->eraseFromParent();
            inst = next;
        }
    }

    // For a direct call the id is a constant; for an indirect one the called
    // value already holds it, because every address-of use of a managed
    // function was replaced by its id.
    Value* CalleePc(IRBuilder<>& b, CallBase* call) {
        if (Function* callee = ResolveDirectCallee(*call)) {
            return ConstantInt::get(I32_, ManagedByFunction_.lookup(callee)->EntryPc);
        }
        Value* token = b.CreatePtrToInt(call->getCalledOperand(), I64_, "callee.token");
        // The window is 4GiB-aligned and the token displacement is an exact
        // multiple of 4GiB, so the token's low word IS the entry pc.
        return b.CreateTrunc(token, I32_, "callee.pc");
    }

    // Replace the branch back to the header with "record where to resume, then
    // return". The trampoline re-enters this same frame, the entry dispatch
    // jumps to the header, and the loop makes one more iteration — without a
    // backedge ever existing in the BPF program.
    BasicBlock* SuspendAtBackedge(const Backedge& edge, uint32_t resumePc, DebugLoc debugLoc) {
        Instruction* term = edge.Latch->getTerminator();

        IRBuilder<> b(term);
        // An unconditional latch is already the suspension edge; replace its
        // branch in place. For a conditional latch, put both the PC store and
        // return in an edge-local block so the loop-exit path publishes no
        // spurious continuation.
        if (term->getNumSuccessors() == 1) {
            b.CreateStore(ConstantInt::get(I32_, resumePc), PcPtr(b))->setDebugLoc(debugLoc);
            b.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
            term->eraseFromParent();
        } else {
            auto* suspend = BasicBlock::Create(Ctx_, edge.Latch->getName() + ".suspend", edge.Latch->getParent());
            IRBuilder<> sb(suspend);
            sb.CreateStore(ConstantInt::get(I32_, resumePc), PcPtr(sb))->setDebugLoc(debugLoc);
            sb.CreateRet(ConstantInt::get(I32_, ActionContinue))->setDebugLoc(debugLoc);
            term->replaceSuccessorWith(edge.Header, suspend);
        }
        return edge.Header;
    }

    // Finish a chunk prepared before frame layout.  The boundary already
    // stores its loop-carried next values and the resume block reloads them;
    // replace the temporary cyclic edge by a real continuation return.
    BasicBlock* SuspendAtChunkedBackedge(const Backedge& edge, uint32_t resumePc, DebugLoc debugLoc) {
        Instruction* term = edge.Latch->getTerminator();
        IRBuilder<> builder(term);
        builder.CreateStore(ConstantInt::get(I32_, resumePc), PcPtr(builder))->setDebugLoc(debugLoc);
        auto* ret = builder.CreateRet(ConstantInt::get(I32_, ActionContinue));
        ret->setDebugLoc(debugLoc);
        term->eraseFromParent();

        BasicBlock* resume = ChunkResumes_.lookup(edge.Header);
        if (!resume) {
            report_fatal_error("stackify: chunk has no prepared resume block");
        }
        return resume;
    }

    // Write a call's arguments below the callee's frame boundary, which
    // sits at `out + bias`: the linkage occupies its top sixteen bytes and
    // argument i lands one slot stride lower per index, matching the
    // callee's own ArgOffsets.
    void StoreCallArguments(IRBuilder<>& b, Value* out, int64_t bias, CallBase* call) {
        for (unsigned i = 0; i < call->arg_size(); i++) {
            auto* slot = b.CreateGEP(I8_, out, {ConstantInt::getSigned(I64_, bias - int64_t(ArgumentTopBytes_ + (i + 1) * ArgSlotSize_))});
            b.CreateStore(call->getArgOperand(i), slot);
        }
    }

    void LowerReturn(ReturnInst* ret, Function* source, Value* frame, ManagedFunction& info, DebugLoc debugLoc) {
        IRBuilder<> b(ret);
        if (Value* value = ret->getReturnValue()) {
            // The result lands in the caller's zone, directly above this
            // frame's boundary.
            b.CreateStore(value, frame);
        }
        // The machine return, expanded here for the same reason as the
        // call: the boundary is already the anchor in hand. The root's
        // linkage was written by the entry with (DONE, 0), so a root return
        // completes the computation through this same path.
        Value* returnPc = b.CreateLoad(I32_, b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, ReturnPcOffset)}), "return.pc");
        Value* savedFp = b.CreateLoad(I64_, b.CreateGEP(I8_, frame, {ConstantInt::getSigned(I64_, SavedFpOffset)}), "saved.fp");
        b.CreateStore(returnPc, PcPtr(b));
        b.CreateStore(info.Fp, SpPtr(b));
        b.CreateStore(savedFp, FpPtr(b));
        auto* newRet = b.CreateRet(ConstantInt::get(I32_, ActionContinue));
        newRet->setDebugLoc(ret->getDebugLoc() ? ret->getDebugLoc() : debugLoc);
        ret->eraseFromParent();
    }

    // ----------------------------------------------------------- trampoline

    // One dispatch of the software stack's top frame. It reports completion
    // when the stack drains; exhausting the bounded driver remains pending.
    Function* BuildStepFunction(bool borrowed, Function* decl = nullptr) {
        StringRef name = borrowed ? bpf::sym::TrampolineCtxStep : bpf::sym::TrampolineStep;
        SmallVector<Type*, 4> parameters = StepParameterTypes(borrowed);
        auto* step = Function::Create(FunctionType::get(I32_, parameters, false), Function::ExternalLinkage, name, Module_);
        step->setCallingConv(CallingConv::C);
        step->addFnAttr(Attribute::NoInline);
        // Generated drivers carry the trampoline class from birth, exactly
        // like their C-defined callers: pointer-parameter ABI, typed BTF.
        step->addFnAttr(bpf::cls::Trampoline);
        unsigned flattenClass = borrowed ? 1 : 0;
        const unsigned physicalRoots = borrowed ? PhysicalBorrowedRoots_ : PhysicalScalarRoots_;
        const unsigned physicalClassBase = 2 + (borrowed ? PhysicalScalarRoots_ : 0);
        const bool physicalRootMode = physicalRoots != 0;
        if (!physicalRootMode) {
            MarkFlattenClass(*step, bpf::md::FlattenRoot, flattenClass);
        }
        StepAbi stepAbi = ConfigureStepAbi(*step, borrowed);
        Value* fiber = stepAbi.Fiber;
        Value* fiberControl = stepAbi.Control;
        Value* stackBacking = stepAbi.StackBacking;

        auto* entry = BasicBlock::Create(Ctx_, "entry", step);
        auto* iterate = BasicBlock::Create(Ctx_, "iterate", step);
        auto* route = BasicBlock::Create(Ctx_, "route", step);
        auto* lookup = DirectDispatch_ ? nullptr : BasicBlock::Create(Ctx_, "route.lookup", step);
        auto* dispatch = BasicBlock::Create(Ctx_, "dispatch", step);
        auto* terminal = BasicBlock::Create(Ctx_, "terminal", step);
        auto* completed = BasicBlock::Create(Ctx_, "completed", step);
        auto* done = BasicBlock::Create(Ctx_, "done", step);
        auto* trap = BasicBlock::Create(Ctx_, "bad.id", step);

        IRBuilder<> b(entry);
        auto* controlReady = BasicBlock::Create(Ctx_, "control.ready", step, route);
        auto* controlMissing = BasicBlock::Create(Ctx_, "control.missing", step, route);
        b.CreateCondBr(b.CreateICmpNE(fiberControl, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), controlReady, controlMissing);
        IRBuilder<> cmb(controlMissing);
        cmb.CreateRet(ConstantInt::get(I32_, 1));
        b.SetInsertPoint(controlReady);
        if (stackBacking) {
            auto* stackReady = BasicBlock::Create(Ctx_, "stack.ready", step, iterate);
            auto* stackMissing = BasicBlock::Create(Ctx_, "stack.missing", step, iterate);
            b.CreateCondBr(b.CreateICmpNE(stackBacking, ConstantPointerNull::get(PointerType::get(Ctx_, 0))), stackReady, stackMissing);
            IRBuilder<> smb(stackMissing);
            PublishExit(smb, fiber, CAPSULE_ERROR_MEMORY_FAULT);
            smb.CreateRet(ConstantInt::get(I32_, 1));
            b.SetInsertPoint(stackReady);
        }
        // One dispatch per router entry: a loop that cannot iterate must not
        // be built (its counter and carried action pin callee-saved
        // registers).
        b.CreateBr(iterate);
        b.SetInsertPoint(iterate);
        Value* pcSlot = PcPtr(b, fiber);
        Value* pc = b.CreateLoad(I32_, pcSlot, "pc");
        Value* isCompleted = b.CreateICmpEQ(pc, DonePc());
        Value* hasExited = b.CreateICmpNE(b.CreateLoad(I64_, OutcomePtr(b, fiber)), ConstantInt::get(I64_, 0));
        Value* isIdle = b.CreateICmpEQ(pc, ConstantInt::get(I32_, 0));
        Value* isTerminal = b.CreateOr(isCompleted, hasExited);
        Value* stopped = b.CreateOr(isIdle, isTerminal);
        b.CreateCondBr(stopped, terminal, route);

        b.SetInsertPoint(terminal);
        b.CreateCondBr(isCompleted, completed, done);

        // Sweep the completed sentinel to idle: the runtime and the host see
        // pc == 0 exactly where they used to see a drained stack.
        b.SetInsertPoint(completed);
        b.CreateStore(ConstantInt::get(I32_, 0), pcSlot);
        b.CreateBr(done);

        b.SetInsertPoint(done);
        b.CreateRet(ConstantInt::get(I32_, 1)); // stop iterating

        b.SetInsertPoint(route);
        b.CreateBr(DirectDispatch_ ? dispatch : lookup);

        Value* dispatchKey = pc;
        if (!DirectDispatch_) {
            b.SetInsertPoint(lookup);
            if (!PcUnitTable_) {
                report_fatal_error("stackify: routed step has no PC ownership table");
            }
            auto* pcReady = BasicBlock::Create(Ctx_, "route.pc.ready", step, dispatch);
            b.CreateCondBr(b.CreateICmpULT(pc, ConstantInt::get(I32_, NextPc_)), pcReady, trap);
            b.SetInsertPoint(pcReady);
            auto* unitSlot = b.CreateInBoundsGEP(PcUnitTable_->getValueType(), PcUnitTable_, {ConstantInt::get(I64_, 0), b.CreateZExt(pc, I64_)});
            dispatchKey = b.CreateLoad(I32_, unitSlot, "allocation.unit");
            b.CreateBr(dispatch);
        }

        b.SetInsertPoint(dispatch);
        // The continuation PC already is the complete dispatch key. Mapping
        // it through a PC->allocation-unit table and then switching on the
        // unit merely added a load and hid the real control-flow relation.
        // Several PCs may enter one connected allocation unit; they share
        // this one terminal call and the unit resolves only that local choice.
        SwitchInst* sw = nullptr;
        SmallVector<SwitchInst*, 16> shardSwitches;
        SmallVector<Function*, 16> shardFunctions;
        SmallVector<BasicBlock*, 16> scalarCases;
        SmallVector<SwitchInst*, 32> rootSwitches;
        SmallVector<Function*, 32> rootFunctions;
        SmallVector<BasicBlock*, 32> rootCases;
        if (physicalRootMode) {
            sw = b.CreateSwitch(dispatchKey, trap, Units_.size());
            rootSwitches.reserve(physicalRoots);
            rootFunctions.reserve(physicalRoots);
            rootCases.reserve(physicalRoots);
            SmallVector<Type*> rootParameters(parameters.begin(), parameters.end());
            rootParameters.push_back(I32_);
            auto* rootType = FunctionType::get(I32_, rootParameters, false);
            for (unsigned root = 0; root < physicalRoots; ++root) {
                std::string rootName = (bpf::sym::DispatchRouterPrefix + (borrowed ? "output.ctx." : "output.scalar.") + Twine(root)).str();
                Function* output = Function::Create(rootType, Function::ExternalLinkage, rootName, Module_);
                output->setCallingConv(CallingConv::C);
                output->addFnAttr(Attribute::NoInline);
                MarkFlattenClass(*output, bpf::md::FlattenRoot, physicalClassBase + root);
                StepAbi outputAbi = ConfigureStepAbi(*output, borrowed);
                Argument* outputFiber = outputAbi.Fiber;
                Argument* outputControl = outputAbi.Control;
                output->getArg(parameters.size())->setName("dispatch_key");

                BasicBlock* outputEntry = BasicBlock::Create(Ctx_, "entry", output);
                BasicBlock* outputDispatch = BasicBlock::Create(Ctx_, "dispatch", output);
                BasicBlock* outputTrap = BasicBlock::Create(Ctx_, "bad.id", output);
                IRBuilder<> outputBuilder(outputEntry);
                BasicBlock* pointerReady = outputDispatch;
                if (FixedMemory_) {
                    pointerReady = BasicBlock::Create(Ctx_, "stack.check", output, outputDispatch);
                }
                outputBuilder.CreateCondBr(outputBuilder.CreateIsNotNull(outputControl), pointerReady, outputTrap);
                if (FixedMemory_) {
                    IRBuilder<> stackCheck(pointerReady);
                    stackCheck.CreateCondBr(stackCheck.CreateIsNotNull(output->getArg(StackBackingArgumentIndex(borrowed))), outputDispatch, outputTrap);
                }
                outputBuilder.SetInsertPoint(outputDispatch);
                rootSwitches.push_back(outputBuilder.CreateSwitch(output->getArg(parameters.size()), outputTrap));
                IRBuilder<> bad(outputTrap);
                PublishExit(bad, outputFiber, CAPSULE_ERROR_INVALID_DISPATCH);
                bad.CreateRet(ConstantInt::get(I32_, 1));

                BasicBlock* routeRoot = BasicBlock::Create(Ctx_, rootName, step, terminal);
                IRBuilder<> routeBuilder(routeRoot);
                SmallVector<Value*, 4> rootArguments;
                for (Argument& argument : step->args()) {
                    rootArguments.push_back(&argument);
                }
                rootArguments.push_back(dispatchKey);
                routeBuilder.CreateRet(routeBuilder.CreateCall(output, rootArguments));
                rootFunctions.push_back(output);
                rootCases.push_back(routeRoot);
            }
        } else if (BoundedDispatch_ && !DirectDispatch_) {
            // CPU v3 branches have signed 16-bit displacements. Keep the top
            // comparison tree compact and route to independently placed local
            // comparison trees. The router functions are allocator/layout
            // units only: machine flattening removes their calls and symbols
            // together with the region units before BPF assembly.
            unsigned shardCount = divideCeil(unsigned(Units_.size()), V3DispatchShardUnits);
            Value* shard = b.CreateLShr(dispatchKey, ConstantInt::get(I32_, Log2_32(V3DispatchShardUnits)), "dispatch.shard");
            auto* outer = b.CreateSwitch(shard, trap, shardCount);
            shardSwitches.reserve(shardCount);
            shardFunctions.reserve(shardCount);
            scalarCases.resize(shardCount);
            SmallVector<Type*> routerParameters(parameters.begin(), parameters.end());
            routerParameters.push_back(I32_);
            auto* routerType = FunctionType::get(I32_, routerParameters, false);
            for (unsigned index = 0; index < shardCount; ++index) {
                std::string routerName = (bpf::sym::DispatchRouterPrefix + (borrowed ? "ctx." : "scalar.") + Twine(index)).str();
                Function* router = Function::Create(routerType, Function::ExternalLinkage, routerName, Module_);
                router->setCallingConv(CallingConv::C);
                router->addFnAttr(Attribute::NoInline);
                MarkFlattenClass(*router, bpf::md::FlattenUnit, flattenClass);
                router->setMetadata(bpf::md::FlattenRouter, MDNode::get(Ctx_, {}));
                StepAbi routerAbi = ConfigureStepAbi(*router, borrowed);
                Argument* routerFiber = routerAbi.Fiber;
                router->getArg(parameters.size())->setName("dispatch_key");

                BasicBlock* routerEntry = BasicBlock::Create(Ctx_, "dispatch", router);
                BasicBlock* routerTrap = BasicBlock::Create(Ctx_, "bad.id", router);
                IRBuilder<> local(routerEntry);
                unsigned first = index * V3DispatchShardUnits;
                unsigned cases = std::min<unsigned>(V3DispatchShardUnits, Units_.size() - first);
                shardSwitches.push_back(local.CreateSwitch(router->getArg(parameters.size()), routerTrap, cases));
                IRBuilder<> bad(routerTrap);
                PublishExit(bad, routerFiber, CAPSULE_ERROR_INVALID_DISPATCH);
                bad.CreateRet(ConstantInt::get(I32_, 1));

                BasicBlock* routeShard = BasicBlock::Create(Ctx_, routerName, step, terminal);
                IRBuilder<> routeBuilder(routeShard);
                SmallVector<Value*, 5> routerArguments;
                for (Argument& argument : step->args()) {
                    routerArguments.push_back(&argument);
                }
                routerArguments.push_back(dispatchKey);
                routeBuilder.CreateRet(routeBuilder.CreateCall(router, routerArguments));
                outer->addCase(ConstantInt::get(cast<IntegerType>(I32_), index), routeShard);
                shardFunctions.push_back(router);
            }
        } else {
            sw = b.CreateSwitch(dispatchKey, trap, DirectDispatch_ ? NextPc_ : Units_.size());
        }
        auto addDispatchCase = [&](unsigned key, BasicBlock* target) {
            ConstantInt* value = ConstantInt::get(cast<IntegerType>(I32_), key);
            if (shardSwitches.empty()) {
                sw->addCase(value, target);
            } else {
                shardSwitches[key / V3DispatchShardUnits]->addCase(value, target);
            }
        };

        // A context step may also encounter scalar PCs. If the scalar driver
        // exists, cross that genuine verifier-pointer ABI boundary once via
        // its final step rather than making the scalar allocation units part
        // of two different flattened functions.
        Function* scalarStep = borrowed ? Module_.getFunction(bpf::sym::TrampolineStep) : nullptr;
        if (scalarStep && scalarStep->isDeclaration()) {
            scalarStep = nullptr;
        }
        BasicBlock* scalarCase = nullptr;
        if (borrowed && scalarStep && shardFunctions.empty()) {
            scalarCase = BasicBlock::Create(Ctx_, "scalar.step", step, done);
            IRBuilder<> scalarBuilder(scalarCase);
            SmallVector<Value*, 3> scalarArguments{fiber, fiberControl};
            if (stackBacking) {
                scalarArguments.push_back(stackBacking);
            }
            Value* action = scalarBuilder.CreateCall(scalarStep, scalarArguments);
            scalarBuilder.CreateRet(action);
        }
        for (auto&& unit : Units_) {
            if (unit.BorrowedContext && !borrowed) {
                continue;
            }
            unsigned dispatchUnit = unit.DispatchKey;
            unsigned shardIndex = shardFunctions.empty() ? 0 : dispatchUnit / V3DispatchShardUnits;
            Function* caseFunction = shardFunctions.empty() ? step : shardFunctions[shardIndex];
            if (borrowed && !unit.BorrowedContext && scalarStep) {
                if (!shardFunctions.empty() && !scalarCases[shardIndex]) {
                    scalarCases[shardIndex] = BasicBlock::Create(Ctx_, "scalar.step", caseFunction);
                    IRBuilder<> scalarBuilder(scalarCases[shardIndex]);
                    SmallVector<Value*, 3> scalarArguments{
                        caseFunction->getArg(FiberArgumentIndex(borrowed)), caseFunction->getArg(ControlArgumentIndex(borrowed))};
                    if (FixedMemory_) {
                        scalarArguments.push_back(caseFunction->getArg(StackBackingArgumentIndex(borrowed)));
                    }
                    scalarBuilder.CreateRet(scalarBuilder.CreateCall(scalarStep, scalarArguments));
                }
                BasicBlock* target = shardFunctions.empty() ? scalarCase : scalarCases[shardIndex];
                if (DirectDispatch_) {
                    for (auto state : unit.States) {
                        addDispatchCase(state.Pc, target);
                    }
                } else {
                    addDispatchCase(dispatchUnit, target);
                }
                continue;
            }
            if (physicalRootMode) {
                Function* output = rootFunctions[unit.OutputRoot];
                auto* caseBlock = BasicBlock::Create(Ctx_, unit.Func->getName(), output);
                IRBuilder<> cb(caseBlock);
                SmallVector<Value*, 4> arguments;
                if (unit.BorrowedContext) {
                    arguments.push_back(output->getArg(0));
                }
                arguments.push_back(output->getArg(FiberArgumentIndex(borrowed)));
                arguments.push_back(output->getArg(ControlArgumentIndex(borrowed)));
                if (FixedMemory_) {
                    arguments.push_back(output->getArg(StackBackingArgumentIndex(borrowed)));
                }
                cb.CreateRet(cb.CreateCall(unit.Func, arguments));
                auto addRootCase = [&](unsigned key) {
                    ConstantInt* value = ConstantInt::get(cast<IntegerType>(I32_), key);
                    rootSwitches[unit.OutputRoot]->addCase(value, caseBlock);
                    addDispatchCase(key, rootCases[unit.OutputRoot]);
                };
                if (DirectDispatch_) {
                    for (auto state : unit.States) {
                        addRootCase(state.Pc);
                    }
                } else {
                    addRootCase(dispatchUnit);
                }
                MarkFlattenClass(*unit.Func, bpf::md::FlattenUnit, physicalClassBase + unit.OutputRoot);
                continue;
            }
            auto functionArguments = [&](Function* owner) {
                SmallVector<Value*, 4> arguments;
                if (unit.BorrowedContext) {
                    arguments.push_back(owner->getArg(0));
                }
                arguments.push_back(owner->getArg(FiberArgumentIndex(borrowed)));
                arguments.push_back(owner->getArg(ControlArgumentIndex(borrowed)));
                if (FixedMemory_) {
                    arguments.push_back(owner->getArg(StackBackingArgumentIndex(borrowed)));
                }
                return arguments;
            };
            if (!unit.Merged) {
                MarkFlattenClass(*unit.Func, bpf::md::FlattenUnit, flattenClass);
            }
            auto* caseBlock = BasicBlock::Create(Ctx_, unit.Func->getName(), caseFunction);
            IRBuilder<> cb(caseBlock);
            SmallVector<Value*, 4> arguments = functionArguments(caseFunction);
            Value* action = cb.CreateCall(unit.Func, arguments);
            cb.CreateRet(action);
            if (DirectDispatch_) {
                for (auto state : unit.States) {
                    addDispatchCase(state.Pc, caseBlock);
                }
            } else {
                addDispatchCase(dispatchUnit, caseBlock);
            }
        }

        b.SetInsertPoint(trap);
        PublishExit(b, fiber, CAPSULE_ERROR_INVALID_DISPATCH);
        b.CreateRet(ConstantInt::get(I32_, 1));

        if (!Module_.debug_compile_units().empty()) {
            DIBuilder debugBuilder(Module_, false, *Module_.debug_compile_units_begin());
            SmallVector<Metadata*> signature{BtfGetInt(debugBuilder, 32, true)};
            if (borrowed) {
                signature.push_back(BorrowedDebugType_);
            }
            signature.push_back(BtfGetInt(debugBuilder, 32, false));
            uint64_t controlBytes = Module_.getDataLayout().getTypeAllocSize(FiberControlType_);
            signature.push_back(BtfGetByteArrayPointer(debugBuilder, controlBytes));
            if (FixedMemory_) {
                signature.push_back(BtfGetByteArrayPointer(debugBuilder, FiberStackSize_));
            }
            BtfFunctionAddDebugInfo(debugBuilder, *step, signature);
            if (physicalRootMode) {
                SmallVector<Metadata*> outputSignature(signature);
                outputSignature.push_back(BtfGetInt(debugBuilder, 32, false));
                for (Function* output : rootFunctions) {
                    BtfFunctionAddDebugInfo(debugBuilder, *output, outputSignature);
                }
            }
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
        StringRef driverName = borrowed ? bpf::sym::TrampolineCtx : bpf::sym::Trampoline;
        StringRef levelName = borrowed ? bpf::sym::TrampolineCtxL1 : bpf::sym::TrampolineL1;
        StringRef stepName = borrowed ? bpf::sym::TrampolineCtxStep : bpf::sym::TrampolineStep;
        Function* driver0 = Module_.getFunction(driverName);
        Function* level0 = Module_.getFunction(levelName);
        if (!driver0 || driver0->isDeclaration() || !level0 || level0->isDeclaration()) {
            report_fatal_error(Twine("stackify: program-supplied driver requires ") + driverName + " and " + levelName);
        }
        // The program declares this extern; take over the declaration rather
        // than creating a second, differently-named function beside it.
        Function* decl = Module_.getFunction(stepName);
        if (decl && !decl->isDeclaration()) {
            // A single-unit class already took the step symbol over: the
            // unit is the step, and no separate dispatcher is built.
            for (AllocationUnit& unit : Units_) {
                if (unit.Merged && unit.Func == decl) {
                    return driver0;
                }
            }
            report_fatal_error(Twine("stackify: ") + stepName + " already defined");
        }
        if (decl) {
            decl->setName((Twine(stepName) + ".decl").str());
        }

        BuildStepFunction(borrowed, decl);
        return driver0;
    }

    void RemoveStepDriver(bool borrowed) {
        StringRef driverName = borrowed ? bpf::sym::TrampolineCtx : bpf::sym::Trampoline;
        StringRef levelName = borrowed ? bpf::sym::TrampolineCtxL1 : bpf::sym::TrampolineL1;
        StringRef stepName = borrowed ? bpf::sym::TrampolineCtxStep : bpf::sym::TrampolineStep;
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
            if (!unusedDriver->use_empty()) {
                report_fatal_error(Twine("stackify: unused Capsule driver remains reachable: ") + driverName);
            }
            // Removing the top-level body releases its call to the L1 loop.
            unusedDriver->dropAllReferences();
            unusedDriver->eraseFromParent();
            unusedDriver = nullptr;
        }
        if (unusedLevel) {
            unusedLevel->removeDeadConstantUsers();
            if (!unusedLevel->use_empty()) {
                report_fatal_error(Twine("stackify: unused Capsule driver level remains reachable: ") + levelName);
            }
            // Removing L1 releases the declaration (or merged definition) of
            // this verifier-ABI class's step.
            unusedLevel->dropAllReferences();
            unusedLevel->eraseFromParent();
        }
        if (unusedStep) {
            unusedStep->removeDeadConstantUsers();
            // A merged unit carries this class's step name but holds live
            // region code that the other class's step dispatches into; it is
            // never a removable driver leftover.
            bool merged = llvm::any_of(Units_, [&](const AllocationUnit& g) { return g.Merged && g.Func == unusedStep; });
            if (!merged) {
                if (!unusedStep->use_empty()) {
                    report_fatal_error(Twine("stackify: unused Capsule step remains reachable: ") + stepName);
                }
                unusedStep->eraseFromParent();
            }
        }
    }

    bool NeedsScalarDriver() const {
        if (!BorrowedContext_) {
            return true;
        }
        for (const Function& function : Module_) {
            for (const Instruction& instruction : instructions(function)) {
                auto* call = dyn_cast<CallBase>(&instruction);
                std::optional<OperandBundleUse> boundary = call ? call->getOperandBundle(bpf::md::CallBundle) : std::nullopt;
                if (boundary && boundary->Inputs.size() == 1) {
                    return true;
                }
            }
        }
        return false;
    }

    void BuildTrampoline() {
        bool scalarRoot = NeedsScalarDriver();
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
                if (!call->getOperandBundle(bpf::md::CallBundle)) {
                    Function* callee = call->getCalledFunction();
                    report_fatal_error(Twine("stackify: native function ") + func.getName() + " calls Capsule function " +
                        (callee ? callee->getName() : "indirectly") + " without capsule_call");
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
        Function* marker = Module_.getFunction(bpf::sym::CopyReturn);
        if (!marker) {
            if (Module_.getNamedValue(bpf::sym::CopyReturn)) {
                report_fatal_error("stackify: __bpf_capsule_copy_return has the wrong ABI");
            }
            return;
        }
        auto* expected = FunctionType::get(Type::getVoidTy(Ctx_), {I32_, PointerType::get(Ctx_, 0), I64_, I64_}, false);
        if (!marker->isDeclaration() || marker->getFunctionType() != expected) {
            report_fatal_error("stackify: __bpf_capsule_copy_return has the wrong ABI");
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
            if (!size || size > FiberStackSize_ - RootFp_) {
                report_fatal_error("stackify: invalid Capsule return size");
            }

            IRBuilder<> b(call);
            Value* fiber = NormalizeFiber(b, call->getArgOperand(0));
            Value* output = call->getArgOperand(1);
            // The ordinary return path wrote the root's result into its
            // zone at the RootFp_ boundary.
            Value* source = StackPtr(b, ConstantInt::get(I64_, RootFp_), fiber);
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
    // Keep only generated runtime functions and proven nosuspend operations
    // global; every other leftover source function becomes static.
    void InternalizeOrdinaryFunctions() {
        SmallPtrSet<Function*, 8> keepGlobal;
        if (ScalarTrampoline_ && !ScalarTrampoline_->hasFnAttribute(Attribute::AlwaysInline)) {
            keepGlobal.insert(ScalarTrampoline_);
        }
        if (BorrowedTrampoline_ && !BorrowedTrampoline_->hasFnAttribute(Attribute::AlwaysInline)) {
            keepGlobal.insert(BorrowedTrampoline_);
        }
        for (auto&& unit : Units_) {
            keepGlobal.insert(unit.Func);
        }

        for (auto&& func : Module_) {
            if (func.isDeclaration() || bpf::IsEntryProgram(func) || keepGlobal.contains(&func) || func.getMetadata(bpf::md::FlattenRoot) ||
                func.getMetadata(bpf::md::NativeScalar)) {
                continue;
            }
            // Same for the driver: a global subprogram is verified once and
            // not descended into, which is what lets the drive loops call it
            // thousands of times without exhausting the jump budget.
            if (bpf::HasFunctionClass(func, bpf::cls::Trampoline) && !func.hasFnAttribute(Attribute::AlwaysInline)) {
                continue;
            }
            // The heap accessors take and return scalars, so they qualify as
            // global subprograms — checked once each instead of re-walked at
            // every one of their tens of thousands of call sites.
            if (func.getName().starts_with(bpf::sym::HeapPrefix) || func.getName().starts_with(bpf::sym::StackAccessorPrefix)) {
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
            auto* local = debugBuilder.createFunction(sp->getScope(), sp->getName(), sp->getLinkageName(), sp->getFile(), sp->getLine(), sp->getType(),
                sp->getScopeLine(), sp->getFlags(), sp->getSPFlags() | DISubprogram::SPFlagLocalToUnit);
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

        std::optional<OperandBundleUse> boundary = call->getOperandBundle(bpf::md::CallBundle);
        if (!boundary || boundary->Inputs.empty() || boundary->Inputs.size() > 2) {
            report_fatal_error("stackify: Capsule call boundary has an invalid fiber/context ABI");
        }
        Value* fiber = NormalizeFiber(b, boundary->Inputs[0].get());
        bool borrowsContext = boundary->Inputs.size() == 2;
        Value* borrowedContext = borrowsContext ? boundary->Inputs[1].get() : nullptr;

        ManagedFunction* root = ManagedByFunction_.lookup(call->getCalledFunction());
        if (!root || !root->FrameSize) {
            report_fatal_error("stackify: Capsule root has no frame layout");
        }
        // The entry performs the machine call operation for the root: push
        // the linkage and arguments below the module-wide RootFp_ boundary
        // and make both registers that boundary; the root's own prologue
        // claims its frame. Linkage (DONE, 0) makes an ordinary root return
        // complete the computation: pc becomes the sentinel.
        Value* out = StackPtr(b, ConstantInt::get(I64_, RootFp_), fiber);
        Value* rootFp = b.CreatePtrToInt(out, I64_, "root.fp");
        b.CreateStore(ConstantInt::get(I64_, 0), OutcomePtr(b, fiber));
        b.CreateStore(ConstantInt::get(I32_, BPF_CAPSULE_PC_DONE), b.CreateGEP(I8_, out, {ConstantInt::getSigned(I64_, ReturnPcOffset)}, "root.return.pc"));
        b.CreateStore(ConstantInt::get(I64_, 0), b.CreateGEP(I8_, out, {ConstantInt::getSigned(I64_, SavedFpOffset)}, "root.saved.fp"));
        StoreCallArguments(b, out, 0, call);
        b.CreateStore(ConstantInt::get(I32_, root->ReturnSize), ReturnSizePtr(b, fiber));
        b.CreateStore(ConstantInt::get(I32_, root->EntryPc), PcPtr(b, fiber));
        b.CreateStore(rootFp, SpPtr(b, fiber));
        b.CreateStore(rootFp, FpPtr(b, fiber));
        CallInst* drive = nullptr;
        if (borrowsContext) {
            if (!BorrowedTrampoline_) {
                report_fatal_error("stackify: borrowed-context Capsule root has no typed trampoline");
            }
            drive = b.CreateCall(BorrowedTrampoline_, {borrowedContext, fiber});
        } else {
            if (!ScalarTrampoline_) {
                report_fatal_error("stackify: scalar Capsule root has no scalar trampoline");
            }
            drive = b.CreateCall(ScalarTrampoline_, {fiber});
        }

        if (!call->getType()->isVoidTy()) {
            Value* slot = StackPtr(b, ConstantInt::get(I64_, RootFp_), fiber);
            call->replaceAllUsesWith(b.CreateLoad(call->getType(), slot, "root.result"));
        }
        call->eraseFromParent();

        // The entry drives the outer loop itself: folding the one-call L0
        // wrapper into the root deletes a BPF-to-BPF call and its 32-byte
        // native frame from every invocation. L1 stays a separate global
        // subprogram so its bounded loop is verified once.
        InlineFunctionInfo inlineInfo;
        if (!InlineFunction(*drive, inlineInfo).isSuccess()) {
            report_fatal_error("stackify: cannot fold the Capsule driver into its entry");
        }
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
    DenseMap<BasicBlock*, unsigned> ChunkTrips_;
    DenseMap<BasicBlock*, BasicBlock*> ChunkBoundaries_;
    DenseMap<BasicBlock*, BasicBlock*> ChunkResumes_;
    SmallVector<std::pair<Function*, std::unique_ptr<ManagedFunction>>> Managed_;
    DenseMap<Function*, ManagedFunction*> ManagedByFunction_;
    SmallVector<std::unique_ptr<Region>> Regions_;
    SmallVector<AllocationUnit> Units_;
    uint32_t NextPc_ = 1;

    uint64_t FiberStackSize_ = 0;
    uint64_t ReserveFloor_ = 0;
    uint64_t RootFp_ = 0;
    uint64_t ArgSlotSize_ = 8;
    uint64_t ArgumentTopBytes_ = LinkageBytes;
    uint64_t FrameAlignment_ = 16;
    uint64_t StackAlignment_ = 16;
    uint64_t FiberCount_ = 1;
    // Selects the frame-anchor shape (see FramePointer); read from the
    // frozen config's backend field, false when the initializer is opaque
    // (the fixed-tier shape is correct on both tiers).
    bool ArenaTier_ = false;
    GlobalVariable* Stack_ = nullptr;
    GlobalVariable* FiberControls_ = nullptr;
    ArrayType* FiberControlsType_ = nullptr;
    StructType* FiberControlType_ = nullptr;
    GlobalVariable* FiberConfig_ = nullptr;
    GlobalVariable* PcUnitTable_ = nullptr;
    StructType* FiberConfigType_ = nullptr;
    DenseMap<Function*, Value*> NativeFiberControls_;
    Function* ScalarTrampoline_ = nullptr;
    Function* BorrowedTrampoline_ = nullptr;
    Function* CurrentFiber_ = nullptr;
    Function* ActiveFiberCount_ = nullptr;
    Function* YieldMarker_ = nullptr;
    Function* SetjmpMarker_ = nullptr;
    Function* LongjmpMarker_ = nullptr;
    Function* OutcomeAccessor_ = nullptr;
    Function* OutcomeSetter_ = nullptr;
    bool BorrowedContext_ = false;
    Metadata* BorrowedDebugType_ = nullptr;
    Function* BorrowedCurrent_ = nullptr;
    bool YieldError_ = false;
    bool JumpError_ = false;
    bool VerifierPointerError_ = false;
    bool InputError_ = false;
    bool FixedMemory_ = false;
    bool DirectDispatch_ = false;
    bool BoundedDispatch_ = false;
    unsigned PhysicalScalarRoots_ = 0;
    unsigned PhysicalBorrowedRoots_ = 0;
};

} // namespace

PreservedAnalyses Stackify::run(Module& module, ModuleAnalysisManager&) {
    StackifyImpl impl(module, FixedMemory_, DirectDispatch_, BoundedDispatch_);
    if (!impl.run()) {
        // Input diagnostics can be discovered after domain selection has
        // already inlined or erased functions. Be conservative about every
        // analysis whenever the implementation reports failure.
        return PreservedAnalyses::none();
    }
    // Native runtime glue and explicit nosuspend operations survive as BPF
    // subprograms. Their BTF records are checked independently, but -O2 may
    // have dropped the parameter variables and left anonymous arguments that
    // invalidate the whole BTF blob. Rebuild every surviving native signature
    // with named parameters. Global roots use their proven scalar ABI;
    // internal nosuspend callees retain their real pointer types. This is an
    // ABI repair for already-native functions, not an inlining selector. One
    // DIBuilder is finalized once; finalizing one per function corrupts the
    // compile unit.
    if (!module.debug_compile_units().empty()) {
        auto* cu = *module.debug_compile_units_begin();
        DIBuilder db(module, false, cu);
        bool any = false;
        for (auto&& func : module) {
            // The trampoline family carries genuine pointer parameters with
            // deliberate BTF (the step's is built above); flattening them to
            // scalars would make the verifier reject their pointer-passing
            // callers.
            // The reserved __bpf_ namespace is a documented ownership
            // contract (bpf_capsule.h), so membership may be read from the
            // name; which member is a driver may not.
            bool nativeRuntime = func.getName().starts_with(bpf::sym::RuntimePrefix) && !bpf::HasFunctionClass(func, bpf::cls::Trampoline);
            bool needsScalarBtf = nativeRuntime || func.getMetadata(bpf::md::NativeScalar);
            bool needsNoSuspendBtf = func.getMetadata(bpf::md::NoSuspend);
            // Optimizers may discard the original DISubprogram entirely for
            // a small C helper. A nosuspend operation still needs
            // FUNC/FUNC_PROTO records so libbpf can relocate calls to it; the
            // compile unit is sufficient to synthesize those records from the
            // proven ABI.
            if (!needsScalarBtf && !needsNoSuspendBtf) {
                continue;
            }
            auto intFor = [&](Type* t) -> Metadata* {
                if (t->isVoidTy()) {
                    return nullptr;
                }
                return BtfGetInt(db, t->isIntegerTy() ? t->getIntegerBitWidth() : 64, true);
            };
            SmallVector<Metadata*> sigTypes;
            if (needsScalarBtf) {
                sigTypes.push_back(intFor(func.getReturnType()));
                for (auto&& arg : func.args()) {
                    sigTypes.push_back(intFor(arg.getType()));
                }
            } else {
                // The source signature is authoritative for internal native
                // pointers. Only parameter variables were lost by O2.
                DISubprogram* old = func.getSubprogram();
                auto oldTypes = old && old->getType() ? old->getType()->getTypeArray() : DINodeArray();
                if (oldTypes.size() == func.arg_size() + 1) {
                    for (Metadata* type : oldTypes) {
                        sigTypes.push_back(type);
                    }
                } else {
                    auto debugTypeFor = [&](Type* type) -> Metadata* {
                        if (type->isVoidTy()) {
                            return nullptr;
                        }
                        if (type->isPointerTy()) {
                            return db.createPointerType(BtfGetInt(db, 8, false), 64);
                        }
                        return BtfGetInt(db, type->getIntegerBitWidth(), true);
                    };
                    sigTypes.push_back(debugTypeFor(func.getReturnType()));
                    for (Argument& arg : func.args()) {
                        sigTypes.push_back(debugTypeFor(arg.getType()));
                    }
                }
            }
            auto* sig = db.createSubroutineType(db.getOrCreateTypeArray(sigTypes));
            DISubprogram::DISPFlags flags = func.isDeclaration() ? DISubprogram::SPFlagZero : DISubprogram::SPFlagDefinition;
            if (func.hasLocalLinkage()) {
                flags |= DISubprogram::SPFlagLocalToUnit;
            }
            auto* sp = db.createFunction(cu, func.getName(), func.getName(), cu->getFile(), 0, sig, 0, DINode::FlagZero, flags);
            func.setSubprogram(nullptr);
            func.setSubprogram(sp);
            // The names are what BTF was missing; the verifier also needs the
            // argument list to be real, or a routine that reads its second
            // argument is rejected ("R2 !read_ok").
            for (auto&& [i, arg] : enumerate(func.args())) {
                db.createParameterVariable(sp, "a" + Twine(i).str(), i + 1, cu->getFile(), 0, cast<DIType>(sigTypes[i + 1]), true);
            }
            for (auto&& inst : instructions(func)) {
                // The exact argument variables above are the BTF contract.
                // Old source/inlined parameter records belong to the
                // DISubprogram being replaced and can assign several
                // different variables to the same physical argument.
                inst.dropDbgRecords();
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

bool RegisterStackifyPass(StringRef name, ModulePassManager& manager) {
    if (name == "bpf-stackify") {
        manager.addPass(Stackify());
    } else if (name == "bpf-stackify-fixed") {
        manager.addPass(Stackify(StackifyMode::Fixed));
    } else if (name == "bpf-stackify-fixed-v3") {
        manager.addPass(Stackify(StackifyMode::FixedV3));
    } else if (name == "bpf-stackify-direct") {
        manager.addPass(Stackify(StackifyMode::Direct));
    } else {
        return false;
    }
    return true;
}
