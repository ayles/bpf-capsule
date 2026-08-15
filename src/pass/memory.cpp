// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "memory.h"

#include "common.h"
#include "bpf_capsule_abi.h"
#include "target.h"

#include <llvm/ADT/MapVector.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/ReplaceConstant.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/Scalar/InferAddressSpaces.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <unordered_map>

using namespace llvm;

namespace {

constexpr unsigned ArenaAS = 1;

// The memory model is the target's choice: arena where the kernel has one,
// overlapping array-map regions where it does not.
bool FixedMemoryMode() {
    return !bpf::UseArena();
}

// ---------------------------------------------------------------------------
// bpf-memory module pass
// ---------------------------------------------------------------------------

bool IsMovableGlobal(GlobalVariable& g) {
    if (g.getName().starts_with("llvm.")) {
        return false;
    }
    if (g.isDeclaration()) {
        return false;
    }
    // Explicitly-sectioned globals (license, .maps, control block, ksyms) stay.
    if (g.hasSection()) {
        return false;
    }
    if (g.getAddressSpace() == ArenaAS) {
        return false;
    }
    // Native-only C storage keeps the normal libbpf global-data layout. Only
    // Capsule-owned (or compiler-generated, unclassified) objects enter the
    // virtual flat address space.
    if (bpf::IsNativeGlobal(g) && !bpf::IsCapsuleGlobal(g)) {
        return false;
    }
    return true;
}

bool ShouldArenaizeAllocas(Function& func) {
    if (bpf::IsCapsuleFunction(func)) {
        return true;
    }
    StringRef name = func.getName();
    return name.starts_with("bpf_step.") || name.starts_with("bpf_heap_commit_");
}

// Stackify owns every source-level Capsule alloca: ordinary locals become
// fields in its persistent per-fiber frames, while the few compiler-generated
// helper keys that genuinely require verifier stack provenance carry the
// bpf.native.alloca marker. A former late fallback silently moved anything
// else into a second global "shadow stack". That both duplicated the stack
// model and made concurrent fibers share one SP. Keep this boundary exact
// instead: a new transformation that leaks an alloca must fix its ownership at
// the producer, not grow another implicit stack here.
void VerifyStackifyConsumedAllocas(Module& module) {
    for (Function& func : module) {
        if (func.isDeclaration() || !ShouldArenaizeAllocas(func)) {
            continue;
        }
        for (Instruction& inst : instructions(func)) {
            auto* alloca = dyn_cast<AllocaInst>(&inst);
            if (!alloca || alloca->getMetadata("bpf.native.alloca")) {
                continue;
            }
            report_fatal_error(Twine("bpf-memory: stackify left an unowned alloca in ") + func.getName());
        }
    }
}

struct MemoryPass : public PassInfoMixin<MemoryPass> {
    uint64_t HeapBase_ = 0;
    static constexpr unsigned HeapShift = BPF_CAPSULE_MEMORY_REGION_SHIFT;
    // Linux 5.15 permits at most 64 maps in one loaded call graph. Keep the
    // established 32 data-map budget so runtime maps and application maps
    // retain deterministic headroom instead of failing later at load time.
    static constexpr unsigned MaxDirectHeapRegions = BPF_CAPSULE_DIRECT_MEMORY_REGIONS;
    static constexpr unsigned MaxHeapRegions = 1u << (32 - HeapShift);
    SmallVector<GlobalVariable*> Regions_;
    GlobalVariable* HeapArray_ = nullptr;
    unsigned TotalRegions_ = 0;
    SmallVector<std::pair<uint64_t, uint64_t>> Spanning_;
    GlobalVariable* SoftwareStackGlobal_ = nullptr;
    uint64_t SoftwareStackBytes_ = 0;
    uint64_t FiberStackSize_ = 0;
    DenseMap<unsigned, Function*> SoftwareStackAccessors_;
    SmallPtrSet<Instruction*, 32> PromotedStackAccesses_;
    std::unordered_map<Function*, Constant*> FunctionIds_;
    uint64_t NextFunctionId_ = (uint64_t)BPF_CAPSULE_FUNCTION_TOKEN_BASE + BPF_CAPSULE_MANAGED_FUNCTION_TOKEN_LIMIT;

    static constexpr unsigned ConfigHeapBase = BPF_CAPSULE_OBJECT_CONFIG_HEAP_BASE;
    static constexpr unsigned ConfigHeapBytes = BPF_CAPSULE_OBJECT_CONFIG_HEAP_BYTES;
    static constexpr unsigned ConfigStackBase = BPF_CAPSULE_OBJECT_CONFIG_STACK_BASE;
    static constexpr unsigned ConfigMemoryEnd = BPF_CAPSULE_OBJECT_CONFIG_MEMORY_END;
    static constexpr unsigned ConfigFiberCount = BPF_CAPSULE_OBJECT_CONFIG_FIBER_COUNT;
    static constexpr unsigned ConfigStackBytesPerFiber = BPF_CAPSULE_OBJECT_CONFIG_STACK_BYTES_PER_FIBER;
    static constexpr unsigned ConfigMaxFibers = BPF_CAPSULE_OBJECT_CONFIG_MAX_FIBERS;
    static constexpr unsigned ConfigArenaImagePages = BPF_CAPSULE_OBJECT_CONFIG_ARENA_IMAGE_PAGES;
    static constexpr unsigned ConfigUsesArena = BPF_CAPSULE_OBJECT_CONFIG_USES_ARENA;
    static constexpr unsigned ConfigHeapReserved = BPF_CAPSULE_OBJECT_CONFIG_HEAP_RESERVED;
    static constexpr unsigned ConfigAbiMagic = BPF_CAPSULE_OBJECT_CONFIG_ABI_MAGIC;
    static constexpr unsigned ConfigAbiVersion = BPF_CAPSULE_OBJECT_CONFIG_ABI_VERSION;
    static constexpr unsigned ConfigFieldCount = BPF_CAPSULE_OBJECT_CONFIG_FIELD_COUNT;

    enum ArenaControlField : unsigned {
        ArenaReady,
        ArenaReserved,
        ArenaVirtualBase,
        ArenaControlFieldCount,
    };

    GlobalVariable* ObjectConfig(Module& module) {
        auto* config = module.getGlobalVariable("bpf_capsule_config", true);
        auto* type = config ? dyn_cast<StructType>(config->getValueType()) : nullptr;
        if (!config || !config->hasSection() || !type || type->getNumElements() != ConfigFieldCount) {
            report_fatal_error("bpf-memory: runtime must define bpf_capsule_config");
        }
        for (unsigned index = 0; index < ConfigFiberCount; ++index) {
            if (!type->getElementType(index)->isIntegerTy(64)) {
                report_fatal_error("bpf-memory: malformed bpf_capsule_config");
            }
        }
        for (unsigned index = ConfigFiberCount; index < ConfigFieldCount; ++index) {
            if (!type->getElementType(index)->isIntegerTy(32)) {
                report_fatal_error("bpf-memory: malformed bpf_capsule_config");
            }
        }
        return config;
    }

    GlobalVariable* ArenaControl(Module& module) {
        auto* control = module.getGlobalVariable("bpf_capsule_arena_control", true);
        auto* type = control ? dyn_cast<StructType>(control->getValueType()) : nullptr;
        if (!control || !control->hasSection() || !type || type->getNumElements() != ArenaControlFieldCount ||
            !type->getElementType(ArenaReady)->isIntegerTy(32) || !type->getElementType(ArenaReserved)->isIntegerTy(32) ||
            !type->getElementType(ArenaVirtualBase)->isIntegerTy(64)) {
            report_fatal_error("bpf-arena: runtime must define bpf_capsule_arena_control");
        }
        return control;
    }

    static uint64_t ConfigInteger(const Constant* initializer, unsigned index, StringRef field) {
        auto* value = dyn_cast_or_null<ConstantInt>(initializer->getAggregateElement(index));
        if (!value) {
            report_fatal_error(Twine("bpf-memory: non-constant ") + field + " in bpf_capsule_config");
        }
        return value->getZExtValue();
    }

    uint64_t ConfigureObjectLayout(
        Module& module, uint64_t heapBase, uint64_t stackBytesPerFiber, uint64_t maxFibers, uint64_t arenaImagePages, uint64_t usesArena, uint64_t stackFloor,
        uint64_t stackAlignment
    ) {
        GlobalVariable* config = ObjectConfig(module);
        Constant* initial = config->getInitializer();
        uint64_t heapBytes = ConfigInteger(initial, ConfigHeapBytes, "heap size");
        uint64_t fiberCount = ConfigInteger(initial, ConfigFiberCount, "fiber count");
        uint64_t declaredStackBytes = ConfigInteger(initial, ConfigStackBytesPerFiber, "fiber stack size");
        uint64_t declaredMaxFibers = ConfigInteger(initial, ConfigMaxFibers, "fiber ceiling");
        const uint64_t addressLimit = BPF_CAPSULE_FUNCTION_TOKEN_BASE;
        uint64_t abiMagic = ConfigInteger(initial, ConfigAbiMagic, "ABI magic");
        uint64_t abiVersion = ConfigInteger(initial, ConfigAbiVersion, "ABI version");
        if (declaredStackBytes != stackBytesPerFiber || declaredMaxFibers != maxFibers || abiMagic != BPF_CAPSULE_ABI_MAGIC ||
            abiVersion != BPF_CAPSULE_ABI_VERSION) {
            report_fatal_error("bpf-memory: linked runtime fiber ABI disagrees with the compiler stack size or fiber ceiling");
        }
        if (!fiberCount || fiberCount > maxFibers || !stackBytesPerFiber || heapBase > addressLimit || heapBytes > addressLimit - heapBase) {
            report_fatal_error("bpf-memory: invalid default heap or fiber configuration");
        }
        uint64_t heapEnd = heapBase + heapBytes;
        if (!isPowerOf2_64(stackAlignment)) {
            report_fatal_error("bpf-memory: invalid software-stack alignment");
        }
        uint64_t stackBase = alignTo(std::max(heapEnd, stackFloor), stackAlignment);
        if (stackBase > addressLimit || fiberCount > (addressLimit - stackBase) / stackBytesPerFiber) {
            report_fatal_error("bpf-memory: default memory configuration exceeds the 32-bit address domain");
        }
        uint64_t memoryEnd = stackBase + fiberCount * stackBytesPerFiber;
        auto* type = cast<StructType>(config->getValueType());
        LLVMContext& ctx = module.getContext();
        config->setInitializer(
            ConstantStruct::get(
                type,
                {
                    ConstantInt::get(Type::getInt64Ty(ctx), heapBase),
                    ConstantInt::get(Type::getInt64Ty(ctx), heapBytes),
                    ConstantInt::get(Type::getInt64Ty(ctx), stackBase),
                    ConstantInt::get(Type::getInt64Ty(ctx), memoryEnd),
                    ConstantInt::get(Type::getInt32Ty(ctx), fiberCount),
                    ConstantInt::get(Type::getInt32Ty(ctx), stackBytesPerFiber),
                    ConstantInt::get(Type::getInt32Ty(ctx), maxFibers),
                    ConstantInt::get(Type::getInt32Ty(ctx), arenaImagePages),
                    ConstantInt::get(Type::getInt32Ty(ctx), usesArena),
                    ConstantInt::get(Type::getInt32Ty(ctx), 0),
                    ConstantInt::get(Type::getInt32Ty(ctx), BPF_CAPSULE_ABI_MAGIC),
                    ConstantInt::get(Type::getInt32Ty(ctx), BPF_CAPSULE_ABI_VERSION),
                }
            )
        );
        return memoryEnd;
    }

    void LowerHeapIntrinsics(Module& module, GlobalVariable* arenaControl = nullptr) {
        GlobalVariable* config = ObjectConfig(module);
        auto lower = [&](StringRef name, bool returnsPointer) {
            Function* intrinsic = module.getFunction(name);
            if (!intrinsic) {
                return;
            }
            if (!intrinsic->isDeclaration() || intrinsic->isVarArg() || intrinsic->arg_size() ||
                (returnsPointer ? !intrinsic->getReturnType()->isPointerTy() : !intrinsic->getReturnType()->isIntegerTy(64))) {
                report_fatal_error(Twine("bpf-memory: malformed ") + name + " intrinsic");
            }
            SmallVector<CallBase*> calls;
            for (User* user : intrinsic->users()) {
                auto* call = dyn_cast<CallBase>(user);
                if (!call || call->getCalledOperand()->stripPointerCasts() != intrinsic) {
                    report_fatal_error(Twine("bpf-memory: address of ") + name + " escapes");
                }
                calls.push_back(call);
            }
            for (CallBase* call : calls) {
                IRBuilder<> b(call);
                Value* replacement = nullptr;
                // The host-reserved heap prefix is preload configuration in
                // the frozen object record; the allocator pool starts after
                // it, with nothing left to seal at run time.
                Value* reservedSlot = b.CreateStructGEP(config->getValueType(), config, ConfigHeapReserved);
                auto* reserved32 = b.CreateLoad(Type::getInt32Ty(module.getContext()), reservedSlot, "bpf.heap.reserved32");
                reserved32->setVolatile(true);
                Value* reserved = b.CreateZExt(reserved32, Type::getInt64Ty(module.getContext()), "bpf.heap.reserved");
                if (returnsPointer) {
                    Value* address = b.CreateAdd(ConstantInt::get(Type::getInt64Ty(module.getContext()), HeapBase_), reserved, "bpf.heap.offset");
                    if (arenaControl) {
                        Value* baseSlot = b.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaVirtualBase);
                        Value* base = b.CreateLoad(Type::getInt64Ty(module.getContext()), baseSlot, "bpf.arena.base");
                        address = b.CreateAdd(base, address, "bpf.heap.address");
                        Value* arenaPointer = b.CreateIntToPtr(address, PointerType::get(module.getContext(), ArenaAS), "bpf.heap.arena.pointer");
                        replacement = b.CreateAddrSpaceCast(arenaPointer, intrinsic->getReturnType(), "bpf.heap.start");
                    } else {
                        replacement = b.CreateIntToPtr(address, intrinsic->getReturnType(), "bpf.heap.start");
                    }
                } else {
                    Value* slot = b.CreateStructGEP(config->getValueType(), config, ConfigHeapBytes);
                    auto* load = b.CreateLoad(Type::getInt64Ty(module.getContext()), slot, "bpf.heap.size");
                    load->setVolatile(true);
                    // Capsule virtual addresses occupy the low 32-bit
                    // domain, and preload configuration rejects any heap
                    // which cannot leave room for its stack bank. Preserve
                    // the selected value while making that ABI bound visible
                    // to older verifiers; otherwise allocator size arithmetic
                    // begins with an arbitrary u64 and can exhaust path state.
                    Value* available = b.CreateSub(load, reserved, "bpf.heap.available");
                    replacement = b.CreateZExt(
                        b.CreateTrunc(available, Type::getInt32Ty(module.getContext()), "bpf.heap.size32"), Type::getInt64Ty(module.getContext()),
                        "bpf.heap.size.bounded"
                    );
                }
                call->replaceAllUsesWith(replacement);
                call->eraseFromParent();
            }
            intrinsic->eraseFromParent();
        };
        lower("__bpf_capsule_heap_start", true);
        lower("__bpf_capsule_heap_size", false);
    }

    void MaterializeSoftwareStackUses(Module& module, GlobalVariable* arenaControl = nullptr) {
        if (!SoftwareStackGlobal_) {
            return;
        }
        GlobalVariable* config = ObjectConfig(module);
        SmallVector<Constant*> constants{SoftwareStackGlobal_};
        removeFromUsedLists(module, [&](Constant* value) { return value->stripPointerCasts() == SoftwareStackGlobal_; });

        for (Function& function : module) {
            if (function.isDeclaration()) {
                continue;
            }
            convertUsersOfConstantsToInstructions(constants, &function, /*RemoveDeadConstants=*/false);
            SmallVector<Use*> uses;
            for (Use& use : SoftwareStackGlobal_->uses()) {
                auto* instruction = dyn_cast<Instruction>(use.getUser());
                if (instruction && instruction->getFunction() == &function) {
                    uses.push_back(&use);
                }
            }
            if (uses.empty()) {
                continue;
            }
            IRBuilder<> b(EntryPrologueInsertionPoint(function));
            Value* slot = b.CreateStructGEP(config->getValueType(), config, ConfigStackBase);
            auto* offset = b.CreateLoad(Type::getInt64Ty(module.getContext()), slot, "bpf.stack.base.offset");
            offset->setVolatile(true);
            Value* address = offset;
            if (arenaControl) {
                Value* baseSlot = b.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaVirtualBase);
                Value* base = b.CreateLoad(Type::getInt64Ty(module.getContext()), baseSlot, "bpf.arena.base");
                address = b.CreateAdd(base, offset, "bpf.stack.address");
                Value* arenaPointer = b.CreateIntToPtr(address, PointerType::get(module.getContext(), ArenaAS), "bpf.stack.arena.pointer");
                Value* pointer = b.CreateAddrSpaceCast(arenaPointer, SoftwareStackGlobal_->getType(), "bpf.stack.logical.base");
                for (Use* use : uses) {
                    use->set(pointer);
                }
                continue;
            }
            Value* pointer = b.CreateIntToPtr(address, SoftwareStackGlobal_->getType(), "bpf.stack.logical.base");
            for (Use* use : uses) {
                use->set(pointer);
            }
        }

        SoftwareStackGlobal_->removeDeadConstantUsers();
        if (!SoftwareStackGlobal_->use_empty()) {
            report_fatal_error("bpf-memory: software stack still has a constant use");
        }
        SoftwareStackGlobal_->eraseFromParent();
        SoftwareStackGlobal_ = nullptr;
    }

    // LLVM's BPF backend accepts fixed stack allocations only in the entry
    // block.  Arena setup must therefore be inserted after the original
    // alloca/lifetime prefix: splitting the block before an alloca makes that
    // otherwise-static slot look like an unsupported dynamic allocation.
    // Setup still precedes the first real program operation and consequently
    // dominates every arena/global use.
    static Instruction* EntryPrologueInsertionPoint(Function& function) {
        BasicBlock& entry = function.getEntryBlock();
        for (Instruction& instruction : entry) {
            if (isa<PHINode>(instruction) || isa<AllocaInst>(instruction) || isa<DbgInfoIntrinsic>(instruction)) {
                continue;
            }
            if (auto* intrinsic = dyn_cast<IntrinsicInst>(&instruction); intrinsic && intrinsic->isLifetimeStartOrEnd()) {
                continue;
            }
            return &instruction;
        }
        llvm_unreachable("entry block has no terminator");
    }

    Constant* GetFunctionId(Function* f) {
        auto it = FunctionIds_.find(f);
        if (it != FunctionIds_.end()) {
            return it->second;
        }
        if (NextFunctionId_ > UINT32_MAX) {
            report_fatal_error("bpf-memory: function-token range exhausted");
        }
        auto* id = ConstantExpr::getIntToPtr(ConstantInt::get(IntegerType::getInt64Ty(f->getContext()), NextFunctionId_++), f->getType());
        FunctionIds_.emplace(f, id);
        return id;
    }

    // Replace instruction operands that use a function as a VALUE (not as a
    // direct callee) with a small unique integer constant. Together with the
    // same substitution inside initializers this kills function-pointer data:
    // comparisons and dispatch tables become plain integers, no PTR_TO_FUNC,
    // no text relocations in data sections.
    void VirtualizeFunctionAddressesInCode(Module& module) {
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* call = dyn_cast<CallBase>(&inst);
                // A helper taking a callback (bpf_for_each_map_elem and
                // friends) needs a real function pointer, not an id: the
                // verifier checks the argument's type is `func`.
                bool isHelperCall = call && !call->getCalledFunction() && isa<Constant>(call->getCalledOperand());
                for (auto&& use : inst.operands()) {
                    auto* f = dyn_cast<Function>(use.get());
                    if (!f) {
                        continue;
                    }
                    if (call && call->isCallee(&use)) {
                        continue;
                    }
                    if (isHelperCall) {
                        continue;
                    }
                    use.set(GetFunctionId(f));
                }
            }
        }
    }

    // Recursively strip GlobalValue references out of an initializer.
    // Function references become their integer id; other global references are
    // zeroed and recorded as (byte offset, pointer constant) runtime fixups,
    // because libbpf does not apply relocations inside the arena section.
    Constant* SanitizeInitializer(Module& module, Constant* c, uint64_t offset, SmallVectorImpl<std::pair<uint64_t, Constant*>>& fixups) {
        if (c->isNullValue() || isa<UndefValue>(c) || isa<PoisonValue>(c)) {
            return c;
        }
        if (isa<ConstantInt>(c) || isa<ConstantFP>(c) || isa<ConstantDataSequential>(c)) {
            return c;
        }

        if (auto* f = dyn_cast<Function>(c->stripPointerCasts())) {
            return GetFunctionId(f);
        }

        const DataLayout& dl = module.getDataLayout();

        if (auto* cs = dyn_cast<ConstantStruct>(c)) {
            auto* layout = dl.getStructLayout(cs->getType());
            SmallVector<Constant*> elems;
            bool changed = false;
            for (unsigned i = 0; i < cs->getNumOperands(); i++) {
                auto* elem = SanitizeInitializer(module, cs->getOperand(i), offset + layout->getElementOffset(i), fixups);
                changed |= elem != cs->getOperand(i);
                elems.push_back(elem);
            }
            return changed ? ConstantStruct::get(cs->getType(), elems) : c;
        }
        if (auto* ca = dyn_cast<ConstantArray>(c)) {
            uint64_t elemSize = dl.getTypeAllocSize(ca->getType()->getElementType());
            SmallVector<Constant*> elems;
            bool changed = false;
            for (unsigned i = 0; i < ca->getNumOperands(); i++) {
                auto* elem = SanitizeInitializer(module, ca->getOperand(i), offset + i * elemSize, fixups);
                changed |= elem != ca->getOperand(i);
                elems.push_back(elem);
            }
            return changed ? ConstantArray::get(ca->getType(), elems) : c;
        }

        // Leaf constant: does it reference any global?
        bool referencesGlobal = false;
        SmallVector<Constant*> work{c};
        while (!work.empty()) {
            Constant* cur = work.pop_back_val();
            if (isa<GlobalValue>(cur)) {
                referencesGlobal = true;
                break;
            }
            for (auto&& op : cur->operands()) {
                if (auto* opc = dyn_cast<Constant>(op)) {
                    work.push_back(opc);
                }
            }
        }
        if (referencesGlobal) {
            fixups.emplace_back(offset, c);
            return Constant::getNullValue(c->getType());
        }
        return c;
    }

    void AttachGlobalDebugInfo(Module& module, GlobalVariable& g, StringRef name) {
        if (module.debug_compile_units().empty()) {
            return;
        }
        auto* cu = *module.debug_compile_units_begin();
        DIBuilder builder(module, false, cu);
        uint64_t sizeBits = module.getDataLayout().getTypeAllocSizeInBits(g.getValueType());
        auto* charType = builder.createBasicType("char", 8, dwarf::DW_ATE_signed_char);
        auto* arrayType = builder.createArrayType(sizeBits, 8, charType, builder.getOrCreateArray({builder.getOrCreateSubrange(0, sizeBits / 8)}));
        auto* gve = builder.createGlobalVariableExpression(cu, name, name, cu->getFile(), 0, arrayType, /*IsLocalToUnit=*/true, /*isDefined=*/true);
        g.addDebugInfo(gve);
        builder.finalize();
    }

    void SetMapMaxEntries(Module& module, GlobalVariable& map, unsigned count) {
        SmallVector<DIGlobalVariableExpression*> expressions;
        map.getDebugInfo(expressions);
        if (expressions.size() != 1) {
            report_fatal_error("bpf-memory: overflow map has no unique BTF definition");
        }
        auto* mapType = dyn_cast<DICompositeType>(expressions.front()->getVariable()->getType());
        if (!mapType) {
            report_fatal_error("bpf-memory: overflow map BTF is not a struct");
        }

        DIBuilder db(module, false, *module.debug_compile_units_begin());
        SmallVector<Metadata*> members;
        bool replaced = false;
        for (Metadata* metadata : mapType->getElements()) {
            auto* member = dyn_cast<DIDerivedType>(metadata);
            if (!member || member->getName() != "max_entries") {
                members.push_back(metadata);
                continue;
            }
            auto* pointer = dyn_cast<DIDerivedType>(member->getBaseType());
            auto* oldArray = pointer ? dyn_cast<DICompositeType>(pointer->getBaseType()) : nullptr;
            DIType* element = oldArray ? oldArray->getBaseType() : nullptr;
            if (!pointer || !oldArray || !element) {
                report_fatal_error("bpf-memory: malformed max_entries BTF encoding");
            }
            auto* subrange = db.getOrCreateSubrange(0, count);
            auto* array = db.createArrayType(uint64_t(count) * element->getSizeInBits(), element->getAlignInBits(), element, db.getOrCreateArray({subrange}));
            auto* newPointer = db.createPointerType(array, pointer->getSizeInBits(), pointer->getAlignInBits());
            members.push_back(db.createMemberType(
                mapType, member->getName(), member->getFile(), member->getLine(), member->getSizeInBits(), member->getAlignInBits(), member->getOffsetInBits(),
                member->getFlags(), newPointer
            ));
            replaced = true;
        }
        if (!replaced) {
            report_fatal_error("bpf-memory: overflow map has no max_entries BTF member");
        }
        db.replaceArrays(mapType, db.getOrCreateArray(members));
        db.finalize();
    }

    // The fixed-map tier has no address space spanning map values. Generate
    // one directly relocatable data map per logical 2 MiB span after layout,
    // when the exact amount of program storage is known. Each value carries
    // an eight-byte shadow of the next span so an unaligned word crossing a
    // boundary remains one verifier-valid map-value access.
    void CreateHeapRegions(Module& module, unsigned count) {
        if (!Regions_.empty()) {
            report_fatal_error("bpf-memory: invalid generated region count");
        }
        LLVMContext& ctx = module.getContext();
        const uint64_t span = uint64_t(1) << HeapShift;
        auto* type = ArrayType::get(Type::getInt8Ty(ctx), span + 8);
        for (unsigned index = 0; index < count; ++index) {
            std::string name = ("heap" + Twine(index)).str();
            auto* region = new GlobalVariable(module, type, /*isConstant=*/false, GlobalValue::ExternalLinkage, ConstantAggregateZero::get(type), name);
            region->setAlignment(Align(8));
            region->setSection((".bss.heap" + Twine(index)).str());
            AttachGlobalDebugInfo(module, *region, name);
            Regions_.push_back(region);
        }
    }

    // Overlap bytes implement unaligned accesses by valid flat-memory
    // pointers, not coherence between unrelated map values. Layout keeps
    // small objects within one region; only a recorded spanning object can
    // make a boundary observable. Omitting synchronization across gaps is both
    // semantically exact and avoids duplicating a cold branch in every store
    // width merely because a stack bank starts in the following map.
    bool ObjectCrossesBoundary(unsigned nextRegion) const {
        const uint64_t boundary = uint64_t(nextRegion) << HeapShift;
        return llvm::any_of(Spanning_, [&](const auto& range) { return range.first < boundary && range.second > boundary; });
    }

    Value* CreateHeapArrayLookup(IRBuilder<>& b, Value* index, AllocaInst* key) {
        LLVMContext& ctx = b.getContext();
        auto* pointer = PointerType::get(ctx, 0);
        b.CreateStore(index, key);
        auto* type = FunctionType::get(pointer, {pointer, pointer}, false);
        Value* helper = ConstantExpr::getIntToPtr(ConstantInt::get(Type::getInt64Ty(ctx), 1), pointer);
        return b.CreateCall(type, helper, {HeapArray_, key}, "bpf.heap.array.value");
    }

    static bool IsStackAnchor(const CallBase& call) {
        auto* assembly = dyn_cast<InlineAsm>(call.getCalledOperand());
        return assembly && assembly->getAsmString().contains("bpf_capsule_stack_anchor");
    }

    // Resolve the current fiber's physical backing region once at the beginning of the
    // outer Capsule drive. The verifier pointer is then threaded through the
    // bounded trampoline and physical step calls; logical stack pointers stay
    // ordinary offsets in the unified address domain.
    void ResolveFixedStackBacking(Module& module) {
        Function* intrinsic = module.getFunction("__bpf_capsule_stack_region");
        if (!intrinsic) {
            return;
        }
        SmallVector<CallBase*> calls;
        for (User* user : intrinsic->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledFunction() != intrinsic) {
                report_fatal_error("bpf-memory: malformed stack-region intrinsic use");
            }
            calls.push_back(call);
        }
        if (!SoftwareStackGlobal_ || !SoftwareStackBytes_ || !FiberStackSize_) {
            report_fatal_error("bpf-memory: stack-region intrinsic exists without a unified software stack");
        }

        LLVMContext& ctx = module.getContext();
        auto* i32 = Type::getInt32Ty(ctx);
        auto* i64 = Type::getInt64Ty(ctx);
        const uint64_t span = uint64_t(1) << HeapShift;
        if (!isPowerOf2_64(FiberStackSize_) || FiberStackSize_ > span || span % FiberStackSize_ || SoftwareStackBytes_ % FiberStackSize_) {
            report_fatal_error("bpf-memory: software stack is not region-aligned fixed memory");
        }
        const uint64_t fiberCount = SoftwareStackBytes_ / FiberStackSize_;
        if (!HeapArray_) {
            report_fatal_error("bpf-memory: software stack lies outside fixed memory");
        }
        GlobalVariable* config = ObjectConfig(module);
        DenseMap<Function*, AllocaInst*> keys;

        auto keyFor = [&](Function& function) {
            AllocaInst*& key = keys[&function];
            if (key) {
                return key;
            }
            auto insertion = function.getEntryBlock().getFirstInsertionPt();
            key = new AllocaInst(i32, 0, nullptr, Align(4), "bpf.stack.region.key", insertion);
            key->setMetadata("bpf.native.alloca", MDNode::get(ctx, {}));
            return key;
        };

        for (CallBase* call : calls) {
            if (call->arg_size() != 1 || !call->getArgOperand(0)->getType()->isIntegerTy(32) || !call->getType()->isPointerTy()) {
                report_fatal_error("bpf-memory: malformed stack-region intrinsic call");
            }
            Function& function = *call->getFunction();
            IRBuilder<> b(call);
            Value* fiber = call->getArgOperand(0);
            if (isPowerOf2_64(fiberCount)) {
                fiber = b.CreateAnd(fiber, ConstantInt::get(i32, fiberCount - 1), "stack.fiber");
            } else {
                fiber = b.CreateURem(fiber, ConstantInt::get(i32, fiberCount), "stack.fiber");
            }
            Value* stackBaseSlot = b.CreateStructGEP(config->getValueType(), config, ConfigStackBase);
            auto* stackBase = b.CreateLoad(i64, stackBaseSlot, "stack.base");
            stackBase->setVolatile(true);
            Value* stackAddress = b.CreateAdd(stackBase, b.CreateMul(b.CreateZExt(fiber, i64), ConstantInt::get(i64, FiberStackSize_)), "stack.address");
            Value* region = b.CreateTrunc(b.CreateLShr(stackAddress, ConstantInt::get(i64, HeapShift)), i32, "stack.region");
            Value* arrayIndex = b.CreateSub(region, ConstantInt::get(i32, Regions_.size()), "stack.array.index");
            Value* base = CreateHeapArrayLookup(b, arrayIndex, keyFor(function));
            call->replaceAllUsesWith(base);
            call->eraseFromParent();
        }
        intrinsic->eraseFromParent();
    }

    // Complex compiler-stack addresses are uncommon, but large generated
    // programs can contain enough of them that repeating the verifier-visible
    // bounds proof at every access exceeds either BPF's branch range or the
    // kernel's verified-instruction limit. Keep that proof in one global
    // subprogram per width. The outer drive has already resolved stack_base;
    // callers merely pass that cached map-value pointer through.
    Function* SoftwareStackAccessor(Module& module, unsigned bits, bool isStore) {
        const unsigned key = (bits << 1) | unsigned(isStore);
        if (auto found = SoftwareStackAccessors_.find(key); found != SoftwareStackAccessors_.end()) {
            return found->second;
        }
        if (!FiberStackSize_ || !isPowerOf2_64(FiberStackSize_) || FiberStackSize_ > (uint64_t(1) << HeapShift) ||
            ((uint64_t(1) << HeapShift) % FiberStackSize_) || !bits || bits > 64 || (bits & 7)) {
            report_fatal_error("bpf-memory: cannot build software-stack accessor for this layout");
        }

        LLVMContext& ctx = module.getContext();
        auto* pointer = PointerType::get(ctx, 0);
        auto* i8 = Type::getInt8Ty(ctx);
        auto* i32 = Type::getInt32Ty(ctx);
        auto* i64 = Type::getInt64Ty(ctx);
        auto* rawType = IntegerType::get(ctx, bits);
        SmallVector<Type*> params{pointer, i64};
        if (isStore) {
            params.push_back(i64);
        }
        std::string name = (Twine("bpf_stack_") + (isStore ? "store" : "load") + Twine(bits)).str();
        auto* func = Function::Create(FunctionType::get(isStore ? i32 : i64, params, false), GlobalValue::ExternalLinkage, name, module);
        func->setCallingConv(CallingConv::C);
        func->addFnAttr(Attribute::NoInline);
        func->getArg(0)->setName("stack_base");
        func->getArg(0)->addAttr(Attribute::get(ctx, "bpf.capsule.stack.backing"));
        func->getArg(1)->setName("logical_address");
        if (isStore) {
            func->getArg(2)->setName("value");
        }

        const uint64_t width = bits / 8;
        const Align accessWidth(width);
        auto* entry = BasicBlock::Create(ctx, "entry", func);
        auto* bounds = BasicBlock::Create(ctx, "bounds", func);
        auto* access = BasicBlock::Create(ctx, "access", func);
        auto* invalid = BasicBlock::Create(ctx, "invalid", func);

        IRBuilder<> b(entry);
        b.CreateCondBr(b.CreateICmpNE(func->getArg(0), ConstantPointerNull::get(pointer)), bounds, invalid);

        b.SetInsertPoint(bounds);
        auto* i32Barrier = InlineAsm::get(FunctionType::get(i32, {i32}, false), "", "=r,0", /*hasSideEffects=*/true);
        Value* low = b.CreateAnd(b.CreateTrunc(func->getArg(1), i32), ConstantInt::get(i32, FiberStackSize_ - 1), "stack.offset");
        low = b.CreateCall(i32Barrier, {low}, "stack.offset.visible");
        b.CreateCondBr(b.CreateICmpULE(low, ConstantInt::get(i32, FiberStackSize_ - width)), access, invalid);

        b.SetInsertPoint(access);
        Value* address = b.CreateGEP(i8, func->getArg(0), {b.CreateZExt(low, i64)}, "stack.native");
        if (isStore) {
            b.CreateAlignedStore(b.CreateZExtOrTrunc(func->getArg(2), rawType), address, accessWidth);
            b.CreateRet(ConstantInt::get(i32, 0));
        } else {
            Value* value = b.CreateAlignedLoad(rawType, address, accessWidth);
            b.CreateRet(b.CreateZExtOrTrunc(value, i64));
        }

        b.SetInsertPoint(invalid);
        b.CreateRet(ConstantInt::get(isStore ? i32 : i64, 0));

        if (!module.debug_compile_units().empty()) {
            DIBuilder db(module, false, *module.debug_compile_units_begin());
            auto* byteType = db.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
            auto* subrange = db.getOrCreateSubrange(0, FiberStackSize_);
            auto* regionType = db.createArrayType(FiberStackSize_ * 8, 8, byteType, db.getOrCreateArray({subrange}));
            SmallVector<Metadata*> signature{BtfGetInt(db, isStore ? 32 : 64, isStore), db.createPointerType(regionType, 64), BtfGetInt(db, 64, false)};
            if (isStore) {
                signature.push_back(BtfGetInt(db, 64, false));
            }
            BtfFunctionAddDebugInfo(db, *func, signature);
            db.finalize();
        }
        SoftwareStackAccessors_[key] = func;
        return func;
    }

    // Keep map lookup state out of the hot direct-region accessor. If an
    // ARRAY path shares that function, register allocation gives every direct
    // access the helper path's callee-saved registers and native key slot.
    // Outlining makes ordinary shard hits leaf functions again while escaped
    // pointers into overflow (including the logical stack tail) retain the
    // same unified-memory behavior.
    Function* CreateHeapArrayAccessor(Module& module, unsigned bits, bool isStore) {
        LLVMContext& ctx = module.getContext();
        auto* i32 = Type::getInt32Ty(ctx);
        auto* i64 = Type::getInt64Ty(ctx);
        auto* rawType = IntegerType::get(ctx, bits);
        SmallVector<Type*> params{i64};
        if (isStore) {
            params.push_back(i64);
        }
        std::string name = (Twine("bpf_heap_array_") + (isStore ? "store" : "load") + Twine(bits)).str();
        auto* func = Function::Create(FunctionType::get(isStore ? i32 : i64, params, false), GlobalValue::ExternalLinkage, name, module);
        func->setCallingConv(CallingConv::C);
        func->addFnAttr(Attribute::NoInline);
        func->getArg(0)->setName("offset");
        if (isStore) {
            func->getArg(1)->setName("value");
        }

        const uint64_t span = uint64_t(1) << HeapShift;
        const uint64_t width = bits / 8;
        const Align accessWidth(width);
        auto* entry = BasicBlock::Create(ctx, "entry", func);
        auto* lookup = BasicBlock::Create(ctx, "lookup", func);
        auto* access = BasicBlock::Create(ctx, "access", func);
        auto* invalid = BasicBlock::Create(ctx, "invalid", func);
        IRBuilder<> b(entry);
        auto* key = b.CreateAlloca(i32, nullptr, "bpf.heap.array.key");
        key->setAlignment(Align(4));
        key->setMetadata("bpf.native.alloca", MDNode::get(ctx, {}));
        Value* offset = func->getArg(0);
        Value* low = b.CreateAnd(offset, ConstantInt::get(i64, span - 1));
        auto* barrier = InlineAsm::get(FunctionType::get(i64, {i64}, false), "", "=r,0", /*hasSideEffects=*/true);
        low = b.CreateCall(barrier, {low}, "bpf.heap.offset.visible");
        Value* index = b.CreateTrunc(b.CreateLShr(offset, ConstantInt::get(i64, HeapShift)), i32);
        Value* afterDirect = b.CreateICmpUGE(index, ConstantInt::get(i32, Regions_.size()));
        Value* beforeEnd = b.CreateICmpULT(index, ConstantInt::get(i32, TotalRegions_));
        b.CreateCondBr(b.CreateAnd(afterDirect, beforeEnd), lookup, invalid);

        b.SetInsertPoint(lookup);
        Value* arrayIndex = b.CreateSub(index, ConstantInt::get(i32, Regions_.size()));
        Value* base = CreateHeapArrayLookup(b, arrayIndex, key);
        b.CreateCondBr(b.CreateICmpNE(base, ConstantPointerNull::get(cast<PointerType>(base->getType()))), access, invalid);

        b.SetInsertPoint(access);
        Value* address = b.CreateGEP(Type::getInt8Ty(ctx), base, {low});
        if (!isStore) {
            Value* value = b.CreateAlignedLoad(rawType, address, accessWidth);
            b.CreateRet(b.CreateZExtOrTrunc(value, i64));
        } else {
            Value* value = b.CreateZExtOrTrunc(func->getArg(1), rawType);
            b.CreateAlignedStore(value, address, accessWidth);

            if (width > 1) {
                auto* sync = BasicBlock::Create(ctx, "sync.next", func, invalid);
                auto* after = BasicBlock::Create(ctx, "after.next", func, invalid);
                Value* crossed = b.CreateICmpUGT(low, ConstantInt::get(i64, span - width));
                Value* hasNext = b.CreateICmpULT(index, ConstantInt::get(i32, TotalRegions_ - 1));
                b.CreateCondBr(b.CreateAnd(crossed, hasNext), sync, after);

                IRBuilder<> sb(sync);
                Value* shadow = sb.CreateGEP(Type::getInt8Ty(ctx), base, {ConstantInt::get(i64, span)});
                Value* boundary = sb.CreateAlignedLoad(i64, shadow, Align(8));
                Value* next = CreateHeapArrayLookup(sb, sb.CreateAdd(arrayIndex, ConstantInt::get(i32, 1)), key);
                auto* write = BasicBlock::Create(ctx, "sync.next.write", func, invalid);
                sb.CreateCondBr(sb.CreateICmpNE(next, ConstantPointerNull::get(cast<PointerType>(next->getType()))), write, invalid);
                IRBuilder<> wb(write);
                wb.CreateAlignedStore(boundary, next, Align(8));
                wb.CreateBr(after);
                b.SetInsertPoint(after);
            }

            auto* sync = BasicBlock::Create(ctx, "sync.previous", func, invalid);
            auto* done = BasicBlock::Create(ctx, "done", func, invalid);
            Value* touchedPrefix = b.CreateICmpULT(low, ConstantInt::get(i64, 8));
            Value* hasPrevious = b.CreateICmpUGT(index, ConstantInt::get(i32, 0));
            b.CreateCondBr(b.CreateAnd(touchedPrefix, hasPrevious), sync, done);

            IRBuilder<> sb(sync);
            Value* boundary = sb.CreateAlignedLoad(i64, base, Align(8));
            if (!Regions_.empty()) {
                Value* firstArray = sb.CreateICmpEQ(arrayIndex, ConstantInt::get(i32, 0));
                auto* direct = BasicBlock::Create(ctx, "sync.previous.direct", func, invalid);
                auto* paged = BasicBlock::Create(ctx, "sync.previous.paged", func, invalid);
                sb.CreateCondBr(firstArray, direct, paged);
                IRBuilder<> db(direct);
                Value* previousShadow = db.CreateGEP(Type::getInt8Ty(ctx), Regions_.back(), {ConstantInt::get(i64, span)});
                db.CreateAlignedStore(boundary, previousShadow, Align(8));
                db.CreateBr(done);
                sb.SetInsertPoint(paged);
            }
            Value* previous = CreateHeapArrayLookup(sb, sb.CreateSub(arrayIndex, ConstantInt::get(i32, 1)), key);
            auto* write = BasicBlock::Create(ctx, "sync.previous.write", func, invalid);
            sb.CreateCondBr(sb.CreateICmpNE(previous, ConstantPointerNull::get(cast<PointerType>(previous->getType()))), write, invalid);
            IRBuilder<> wb(write);
            Value* previousShadow = wb.CreateGEP(Type::getInt8Ty(ctx), previous, {ConstantInt::get(i64, span)});
            wb.CreateAlignedStore(boundary, previousShadow, Align(8));
            wb.CreateBr(done);

            b.SetInsertPoint(done);
            b.CreateRet(ConstantInt::get(i32, 0));
        }

        b.SetInsertPoint(invalid);
        b.CreateRet(ConstantInt::get(isStore ? i32 : i64, 0));
        if (!module.debug_compile_units().empty()) {
            DIBuilder db(module, false, *module.debug_compile_units_begin());
            SmallVector<Metadata*> signature{BtfGetInt(db, isStore ? 32 : 64, isStore), BtfGetInt(db, 64, false)};
            if (isStore) {
                signature.push_back(BtfGetInt(db, 64, false));
            }
            BtfFunctionAddDebugInfo(db, *func, signature);
            db.finalize();
        }
        return func;
    }

    Function* CreateHeapAccessor(Module& module, unsigned bits, bool isStore) {
        LLVMContext& ctx = module.getContext();
        auto* i32 = Type::getInt32Ty(ctx);
        auto* i64 = Type::getInt64Ty(ctx);
        auto* rawType = IntegerType::get(ctx, bits);
        SmallVector<Type*> params = {i64};
        if (isStore) {
            params.push_back(i64);
        }
        std::string name = (Twine("bpf_heap_") + (isStore ? "store" : "load") + Twine(bits)).str();
        Function* func = module.getFunction(name);
        if (!func) {
            func = Function::Create(FunctionType::get(isStore ? i32 : i64, params, false), GlobalValue::ExternalLinkage, name, module);
        } else if (!func->isDeclaration()) {
            report_fatal_error(Twine("bpf-memory: runtime already defines ") + name);
        }
        func->setLinkage(GlobalValue::ExternalLinkage);
        func->setCallingConv(CallingConv::C);
        func->addFnAttr(Attribute::NoInline);
        func->getArg(0)->setName("offset");
        if (isStore) {
            func->getArg(1)->setName("value");
        }

        const uint64_t span = uint64_t(1) << HeapShift;
        const uint64_t width = bits / 8;
        // This is the width of the BPF memory instruction, not a claim that
        // the virtual C address is aligned. BPF word loads/stores implement
        // unaligned program accesses; Align(1) makes LLVM scalarize them into
        // 2/4/8 byte instructions and is both larger and much slower.
        const Align accessWidth(width);
        auto* entry = BasicBlock::Create(ctx, "entry", func);
        auto* invalid = BasicBlock::Create(ctx, "invalid", func);
        IRBuilder<> b(entry);
        const bool hasArray = HeapArray_ && TotalRegions_ > Regions_.size();
        Function* arrayAccessor = hasArray ? CreateHeapArrayAccessor(module, bits, isStore) : nullptr;
        const bool directArraySync = hasArray && isStore && width > 1 && !Regions_.empty() && ObjectCrossesBoundary(Regions_.size());
        AllocaInst* key = nullptr;
        if (directArraySync) {
            key = b.CreateAlloca(i32, nullptr, "bpf.heap.array.key");
            key->setAlignment(Align(4));
            key->setMetadata("bpf.native.alloca", MDNode::get(ctx, {}));
        }
        Value* offset = func->getArg(0);
        Value* low = b.CreateAnd(offset, ConstantInt::get(i64, span - 1));
        auto* barrier = InlineAsm::get(
            FunctionType::get(i64, {i64}, false), "", "=r,0",
            /*hasSideEffects=*/true
        );
        low = b.CreateCall(barrier, {low}, "bpf.heap.offset.visible");
        Value* index = b.CreateTrunc(b.CreateLShr(offset, ConstantInt::get(i64, HeapShift)), i32);
        auto* overflow = hasArray ? BasicBlock::Create(ctx, "array", func, invalid) : invalid;
        auto* route = b.CreateSwitch(index, overflow, Regions_.size());

        for (unsigned regionIndex = 0; regionIndex < Regions_.size(); ++regionIndex) {
            auto* block = BasicBlock::Create(ctx, "region." + Twine(regionIndex), func, invalid);
            route->addCase(ConstantInt::get(i32, regionIndex), block);
            IRBuilder<> rb(block);
            Value* address = rb.CreateGEP(Type::getInt8Ty(ctx), Regions_[regionIndex], {low});
            if (!isStore) {
                Value* value = rb.CreateAlignedLoad(rawType, address, accessWidth);
                rb.CreateRet(rb.CreateZExtOrTrunc(value, i64));
                continue;
            }

            Value* value = rb.CreateZExtOrTrunc(func->getArg(1), rawType);
            rb.CreateAlignedStore(value, address, accessWidth);

            // If the word crossed into this region's shadow, publish the
            // complete boundary word to the next region's owned prefix. The
            // untouched shadow bytes already mirror that prefix.
            if (width > 1 && regionIndex + 1 < TotalRegions_ && ObjectCrossesBoundary(regionIndex + 1)) {
                auto* sync = BasicBlock::Create(ctx, "region." + Twine(regionIndex) + ".sync.next", func, invalid);
                auto* after = BasicBlock::Create(ctx, "region." + Twine(regionIndex) + ".after.next", func, invalid);
                Value* crossed = rb.CreateICmpUGT(low, ConstantInt::get(i64, span - width));
                rb.CreateCondBr(crossed, sync, after);
                IRBuilder<> sb(sync);
                Value* shadow = sb.CreateGEP(Type::getInt8Ty(ctx), Regions_[regionIndex], {ConstantInt::get(i64, span)});
                Value* boundary = sb.CreateAlignedLoad(i64, shadow, Align(8));
                if (regionIndex + 1 < Regions_.size()) {
                    Value* next = sb.CreateGEP(Type::getInt8Ty(ctx), Regions_[regionIndex + 1], {ConstantInt::get(i64, 0)});
                    sb.CreateAlignedStore(boundary, next, Align(8));
                    sb.CreateBr(after);
                } else {
                    Value* next = CreateHeapArrayLookup(sb, ConstantInt::get(i32, 0), key);
                    Value* present = sb.CreateICmpNE(next, ConstantPointerNull::get(cast<PointerType>(next->getType())));
                    auto* write = BasicBlock::Create(ctx, "region." + Twine(regionIndex) + ".sync.next.write", func, invalid);
                    sb.CreateCondBr(present, write, invalid);
                    IRBuilder<> wb(write);
                    wb.CreateAlignedStore(boundary, next, Align(8));
                    wb.CreateBr(after);
                }
                rb.SetInsertPoint(after);
            }

            // A store into the owned prefix makes the previous region's
            // shadow stale. Copy all eight bytes back after the real store.
            if (regionIndex > 0 && ObjectCrossesBoundary(regionIndex)) {
                auto* sync = BasicBlock::Create(ctx, "region." + Twine(regionIndex) + ".sync.previous", func, invalid);
                auto* done = BasicBlock::Create(ctx, "region." + Twine(regionIndex) + ".done", func, invalid);
                Value* touchedPrefix = rb.CreateICmpULT(low, ConstantInt::get(i64, 8));
                rb.CreateCondBr(touchedPrefix, sync, done);
                IRBuilder<> sb(sync);
                Value* current = sb.CreateGEP(Type::getInt8Ty(ctx), Regions_[regionIndex], {ConstantInt::get(i64, 0)});
                Value* shadow = sb.CreateGEP(Type::getInt8Ty(ctx), Regions_[regionIndex - 1], {ConstantInt::get(i64, span)});
                Value* boundary = sb.CreateAlignedLoad(i64, current, Align(8));
                sb.CreateAlignedStore(boundary, shadow, Align(8));
                sb.CreateBr(done);
                rb.SetInsertPoint(done);
            }
            rb.CreateRet(ConstantInt::get(i32, 0));
        }

        if (hasArray) {
            IRBuilder<> ab(overflow);
            SmallVector<Value*> arguments{func->getArg(0)};
            if (isStore) {
                arguments.push_back(func->getArg(1));
            }
            Value* result = ab.CreateCall(arrayAccessor, arguments);
            ab.CreateRet(result);
        }

        b.SetInsertPoint(invalid);
        b.CreateRet(ConstantInt::get(isStore ? i32 : i64, 0));

        if (!module.debug_compile_units().empty()) {
            DIBuilder db(module, false, *module.debug_compile_units_begin());
            SmallVector<Metadata*> signature = {BtfGetInt(db, isStore ? 32 : 64, isStore), BtfGetInt(db, 64, false)};
            if (isStore) {
                signature.push_back(BtfGetInt(db, 64, false));
            }
            BtfFunctionAddDebugInfo(db, *func, signature);
            db.finalize();
        }
        return func;
    }

    void CreateHeapAccessors(Module& module) {
        for (unsigned bits : {8u, 16u, 32u, 64u}) {
            CreateHeapAccessor(module, bits, /*isStore=*/false);
            CreateHeapAccessor(module, bits, /*isStore=*/true);
        }
    }

    // ---------------------------------------------------------------- heap
    // Lowering for kernels without bpf_arena: a global becomes a constant
    // offset into one big array map, and every access goes through the
    // program's bpf_heap_ptr (mask + inlined lookup). Pointers stored in
    // memory are therefore plain integers, so unlike the arena there is no
    // relocation to fix up at run time — the offsets are known here.

    // Serialize a constant into the heap image. Returns false if it contains
    // something we cannot lay out statically.
    bool EmitConstant(Module& module, Constant* c, std::vector<uint8_t>& image, uint64_t at, const DenseMap<GlobalVariable*, uint64_t>& offsets) {
        const DataLayout& dl = module.getDataLayout();
        uint64_t size = dl.getTypeAllocSize(c->getType());
        if (at + size > image.size()) {
            image.resize(at + size, 0);
        }
        if (isa<ConstantAggregateZero>(c) || isa<UndefValue>(c) || isa<PoisonValue>(c) || c->isNullValue()) {
            return true; // already zero
        }
        if (auto* ci = dyn_cast<ConstantInt>(c)) {
            APInt v = ci->getValue().zextOrTrunc(size * 8);
            for (uint64_t i = 0; i < size; i++) {
                image[at + i] = uint8_t(v.extractBitsAsZExtValue(8, i * 8));
            }
            return true;
        }
        if (auto* cf = dyn_cast<ConstantFP>(c)) {
            APInt v = cf->getValueAPF().bitcastToAPInt().zextOrTrunc(size * 8);
            for (uint64_t i = 0; i < size; i++) {
                image[at + i] = uint8_t(v.extractBitsAsZExtValue(8, i * 8));
            }
            return true;
        }
        if (auto* cds = dyn_cast<ConstantDataSequential>(c)) {
            StringRef raw = cds->getRawDataValues();
            memcpy(image.data() + at, raw.data(), std::min<uint64_t>(raw.size(), size));
            return true;
        }
        if (auto* ca = dyn_cast<ConstantArray>(c)) {
            uint64_t stride = dl.getTypeAllocSize(ca->getType()->getElementType());
            for (unsigned i = 0; i < ca->getNumOperands(); i++) {
                if (!EmitConstant(module, ca->getOperand(i), image, at + i * stride, offsets)) {
                    return false;
                }
            }
            return true;
        }
        if (auto* cs = dyn_cast<ConstantStruct>(c)) {
            auto* layout = dl.getStructLayout(cs->getType());
            for (unsigned i = 0; i < cs->getNumOperands(); i++) {
                if (!EmitConstant(module, cs->getOperand(i), image, at + layout->getElementOffset(i), offsets)) {
                    return false;
                }
            }
            return true;
        }
        // A pointer-shaped constant: resolve it to the integer it has become.
        APInt value(64, 0);
        if (!ResolvePointerConstant(module, c, offsets, value)) {
            return false;
        }
        for (uint64_t i = 0; i < size; i++) {
            image[at + i] = uint8_t(value.extractBitsAsZExtValue(8, i * 8));
        }
        return true;
    }

    bool ResolvePointerConstant(Module& module, Constant* c, const DenseMap<GlobalVariable*, uint64_t>& offsets, APInt& out) {
        if (auto* ci = dyn_cast<ConstantInt>(c)) {
            out = ci->getValue().zextOrTrunc(64);
            return true;
        }
        if (auto* g = dyn_cast<GlobalVariable>(c)) {
            auto it = offsets.find(g);
            if (it == offsets.end()) {
                return false;
            }
            out = APInt(64, it->second);
            return true;
        }
        if (auto* ce = dyn_cast<ConstantExpr>(c)) {
            if (ce->getOpcode() == Instruction::IntToPtr || ce->getOpcode() == Instruction::PtrToInt || ce->getOpcode() == Instruction::BitCast ||
                ce->getOpcode() == Instruction::AddrSpaceCast || ce->getOpcode() == Instruction::Trunc || ce->getOpcode() == Instruction::ZExt ||
                ce->getOpcode() == Instruction::SExt) {
                return ResolvePointerConstant(module, ce->getOperand(0), offsets, out);
            }
            // -O2 rewrites a table of pointers into a table of 32-bit offsets
            // relative to the table itself (the ".rel" globals), so a
            // difference of two addresses is an ordinary shape here. Both
            // sides live in the image, so the difference is just as
            // computable as either address alone.
            if (ce->getOpcode() == Instruction::Sub || ce->getOpcode() == Instruction::Add) {
                APInt lhs(64, 0), rhs(64, 0);
                if (!ResolvePointerConstant(module, ce->getOperand(0), offsets, lhs) || !ResolvePointerConstant(module, ce->getOperand(1), offsets, rhs)) {
                    return false;
                }
                out = ce->getOpcode() == Instruction::Sub ? lhs - rhs : lhs + rhs;
                return true;
            }
            if (auto* gep = dyn_cast<GEPOperator>(ce)) {
                APInt base(64, 0);
                if (!ResolvePointerConstant(module, cast<Constant>(gep->getPointerOperand()), offsets, base)) {
                    return false;
                }
                APInt delta(64, 0);
                if (!gep->accumulateConstantOffset(module.getDataLayout(), delta)) {
                    return false;
                }
                out = base + delta;
                return true;
            }
        }
        return false;
    }

    PreservedAnalyses runFixedMemory(Module& module) {
        LLVMContext& ctx = module.getContext();
        auto* i64 = Type::getInt64Ty(ctx);
        const DataLayout& dl = module.getDataLayout();

        // Value-range facts are invisible to the verifier. -O2 infers `range`
        // return attributes, and the backend then proves a region mask
        // redundant and deletes it (a call known to return [0,255] makes
        // base+index provably in range) — leaving unbounded math into a map
        // that the verifier rejects. Every proof the backend makes has to be
        // one the verifier can re-make, so the facts go away here.
        for (auto&& f : module) {
            f.removeRetAttr(Attribute::Range);
            for (auto&& inst : instructions(f)) {
                if (auto* cb = dyn_cast<CallBase>(&inst)) {
                    cb->removeRetAttr(Attribute::Range);
                } else if (auto* ld = dyn_cast<LoadInst>(&inst)) {
                    ld->setMetadata(LLVMContext::MD_range, nullptr);
                }
            }
        }

        // -O2 also rewrites switch lookup tables into llvm.load.relative over
        // a table of 32-bit self-relative offsets. The intrinsic is a call,
        // so the access rewriting below never sees it, and the backend lowers
        // it to a raw absolute load. Expanded into the IR it means, the load
        // becomes an ordinary access and is rewritten like any other.
        {
            SmallVector<IntrinsicInst*> rels;
            for (auto&& f : module) {
                for (auto&& inst : instructions(f)) {
                    if (auto* ii = dyn_cast<IntrinsicInst>(&inst)) {
                        if (ii->getIntrinsicID() == Intrinsic::load_relative) {
                            rels.push_back(ii);
                        }
                    }
                }
            }
            auto* i8 = Type::getInt8Ty(ctx);
            for (auto* ii : rels) {
                IRBuilder<> b(ii);
                Value* table = ii->getArgOperand(0);
                Value* off = b.CreateSExtOrTrunc(ii->getArgOperand(1), i64);
                auto* rel = b.CreateAlignedLoad(Type::getInt32Ty(ctx), b.CreateGEP(i8, table, {off}), Align(4));
                auto* target = b.CreateGEP(i8, table, {b.CreateSExt(rel, i64)});
                ii->replaceAllUsesWith(target);
                ii->eraseFromParent();
            }
        }

        VirtualizeFunctionAddressesInCode(module);

        VerifyStackifyConsumedAllocas(module);

        SmallVector<GlobalVariable*> movable;
        for (auto&& g : module.globals()) {
            if (IsMovableGlobal(g)) {
                movable.push_back(&g);
                if (g.getName() == "bpf_call_stack") {
                    SoftwareStackGlobal_ = &g;
                }
            }
        }

        // Initialized data first so the image we have to ship stays small.
        // The logical stack bank is the aligned right edge of the ordinary
        // image. This preserves direct regions for shared heap data and lets
        // the loader omit the inactive suffix of the compiled fiber bank.
        llvm::stable_sort(movable, [](GlobalVariable* a, GlobalVariable* b) {
            auto rank = [](GlobalVariable* g) {
                if (!g->getInitializer()->isNullValue()) {
                    return 0;
                }
                return g->getName() == "bpf_call_stack" ? 2 : 1;
            };
            return rank(a) < rank(b);
        });

        const uint64_t span = uint64_t(1) << HeapShift;
        if (SoftwareStackGlobal_) {
            SoftwareStackBytes_ = dl.getTypeAllocSize(SoftwareStackGlobal_->getValueType());
            if (MDNode* metadata = SoftwareStackGlobal_->getMetadata("bpf.fiber.stack.size")) {
                if (auto* value = mdconst::dyn_extract<ConstantInt>(metadata->getOperand(0))) {
                    FiberStackSize_ = value->getZExtValue();
                }
            }
            if (!FiberStackSize_ || !isPowerOf2_64(FiberStackSize_) || FiberStackSize_ > span || SoftwareStackBytes_ % FiberStackSize_) {
                report_fatal_error("bpf-memory: malformed unified fiber stack bank");
            }
        }

        // The first page is left unmapped so a null pointer stays a fault.
        // No global is allowed to straddle a region boundary, which lets an
        // access with a known base resolve its region at compile time.
        uint64_t cursor = BPF_CAPSULE_ARENA_PAGE_SIZE;
        DenseMap<GlobalVariable*, uint64_t> offsets;
        for (auto* g : movable) {
            if (g == SoftwareStackGlobal_) {
                continue;
            }
            uint64_t align = std::max<uint64_t>(g->getAlign().valueOrOne().value(), 8);
            uint64_t size = dl.getTypeAllocSize(g->getValueType());
            cursor = (cursor + align - 1) & ~(align - 1);
            if (size <= (uint64_t(1) << HeapShift) && (cursor >> HeapShift) != ((cursor + size - 1) >> HeapShift)) {
                cursor = ((cursor >> HeapShift) + 1) << HeapShift;
            }
            // An object larger than a region cannot be made to fit in one.
            // It still works through the accessor, which picks the region per
            // access, but an access into it has no compile-time region, so
            // record it and keep the fast path away.
            if (size > (uint64_t(1) << HeapShift)) {
                Spanning_.push_back({cursor, cursor + size});
            }
            offsets[g] = cursor;
            cursor += size;
        }
        HeapBase_ = alignTo(cursor, uint64_t(16));
        // The public heap is one dynamically sized object, not a statically
        // bounded global.  Even when an access still visibly starts at the
        // constant heap base, its offset may select any configured region.
        // Keep it out of the single-region global fast path.
        Spanning_.push_back({HeapBase_, BPF_CAPSULE_FUNCTION_TOKEN_BASE});
        if (std::max<uint64_t>(1, (HeapBase_ + span - 1) / span) > MaxHeapRegions) {
            module.getContext().emitError(
                "bpf-memory: program storage exceeds the 32-bit Capsule "
                "address domain"
            );
            return PreservedAnalyses::none();
        }
        TotalRegions_ = MaxHeapRegions;

        std::vector<uint8_t> image;
        for (auto* g : movable) {
            if (g->getInitializer()->isNullValue()) {
                continue;
            }
            if (!EmitConstant(module, g->getInitializer(), image, offsets[g], offsets)) {
                {
                    std::string what;
                    raw_string_ostream os(what);
                    g->getInitializer()->print(os);
                    report_fatal_error(Twine("bpf-memory: cannot lay out initializer of ") + g->getName() + ": " + what.substr(0, 300));
                }
            }
        }

        // Initialized bytes must remain ordinary ELF data so stock libbpf and
        // bpftool loaders need no Capsule-specific population step. Everything
        // after that compact prefix is zero-filled storage and may live in one
        // multi-entry ARRAY map. ARRAY lookup overhead is substantial on the
        // fixed tier, so the compiler always consumes the proven direct-map
        // budget first and uses the ARRAY only for the remaining capacity.
        unsigned imageRegions = unsigned((image.size() + span - 1) / span);
        if (imageRegions > MaxDirectHeapRegions) {
            module.getContext().emitError(
                "bpf-memory: initialized image exceeds the supported 32-region "
                "direct-map budget; reduce initialized data"
            );
            return PreservedAnalyses::none();
        }
        unsigned directRegions = MaxDirectHeapRegions;
        HeapArray_ = module.getGlobalVariable("bpf_heap_array", true);
        if (!HeapArray_ || !HeapArray_->hasSection()) {
            report_fatal_error("bpf-memory: runtime must define bpf_heap_array");
        }
        if (!SoftwareStackGlobal_) {
            report_fatal_error("bpf-memory: runtime has no unified software stack");
        }
        uint64_t defaultEnd = ConfigureObjectLayout(
            module, HeapBase_, FiberStackSize_, SoftwareStackBytes_ / FiberStackSize_, /*arenaImagePages=*/0, /*usesArena=*/0, uint64_t(directRegions) * span,
            span
        );
        unsigned defaultRegions = unsigned((defaultEnd + span - 1) / span);
        unsigned arrayRegions = defaultRegions - directRegions;
        if (!arrayRegions) {
            report_fatal_error("bpf-memory: configured software stack has no ARRAY backing");
        }
        SetMapMaxEntries(module, *HeapArray_, arrayRegions);
        CreateHeapRegions(module, directRegions);
        CreateHeapAccessors(module);
        bpf::stats() << "bpf-memory: " << directRegions << " direct regions, " << arrayRegions << " ARRAY regions\n";

        // Install the image directly into the region globals, as their
        // initializers, and move those regions from .bss to .data. libbpf then
        // populates them from the ELF at load time like any other global data,
        // which is what lets a program be loaded by stock tooling -- and what
        // keeps a loader from having to know the memory model exists at all.
        // Regions with nothing in them stay in .bss so the object stays small.
        InstallImage(module, image);

        for (auto* g : movable) {
            if (g == SoftwareStackGlobal_) {
                continue;
            }
            g->replaceAllUsesWith(ConstantExpr::getIntToPtr(ConstantInt::get(i64, offsets[g]), g->getType()));
            g->eraseFromParent();
        }

        ResolveFixedStackBacking(module);

        // Direct compiler-frame accesses are specialized while their origin is
        // still explicit. Escaped stack pointers are materialized afterwards
        // and use the same general unified-memory accessors as heap pointers.
        SmallVector<Function*> stackFunctions;
        for (Function& function : module) {
            if (!function.isDeclaration()) {
                stackFunctions.push_back(&function);
            }
        }
        for (Function* function : stackFunctions) {
            PromoteSingleRegionSoftwareStack(*function);
        }
        MaterializeSoftwareStackUses(module);
        LowerHeapIntrinsics(module);

        bpf::stats() << "bpf-memory: " << movable.size() << " globals, " << (HeapBase_ >> 20) << " MiB static prefix, " << (defaultEnd >> 20)
                     << " MiB default configured space, image " << (image.size() >> 10) << " KiB\n";

        for (auto&& func : module) {
            // Not the accessors themselves: their own load and store is the
            // real one, reached through a region select the underlying-object
            // query cannot see past. Routing it would make each accessor call
            // itself, passing a genuine pointer where an offset belongs.
            if (!func.isDeclaration() && !func.getName().starts_with("bpf_heap_") && !func.getName().starts_with("bpf_stack_")) {
                RouteAccessesThroughHeap(func);
            }
        }

        // Leave accessors as calls on purpose. Inlining the general router at every
        // access expands the program past the million-instruction ceiling
        // (~30 instructions each, tens of thousands of sites); as calls the
        // sequence exists once. Register pressure from those calls is handled
        // after allocation by bpf-unified-spills, which moves only scalar spill
        // words that cannot safely remain on the 512-byte native stack.
        unsigned calls = 0;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* call = dyn_cast<CallBase>(&inst);
                if (call && call->getCalledFunction() && call->getCalledFunction()->getName().starts_with("bpf_heap_")) {
                    calls++;
                }
            }
        }
        bpf::stats() << "bpf-memory: " << calls << " accesses through the general accessor\n";

        // Nothing to fix up at run time: a pointer is an offset we computed
        // here, so pointer-valued initializers are already correct in the
        // image. Satisfy the hook if an older or external runtime declared it.
        if (Function* init = module.getFunction("__bpf_capsule_init"); init && init->isDeclaration()) {
            init->setLinkage(GlobalValue::InternalLinkage);
            auto* block = BasicBlock::Create(ctx, "", init);
            IRBuilder<> b(block);
            b.CreateRet(ConstantInt::get(Type::getInt32Ty(ctx), 0));
            if (!module.debug_compile_units().empty()) {
                DIBuilder debugBuilder(module, false, *module.debug_compile_units_begin());
                BtfFunctionAddDebugInfo(debugBuilder, *init, {BtfGetInt(debugBuilder, 32, true)});
                debugBuilder.finalize();
            }
        }

        // The runtime header defines accessors for every width and memory
        // representation so arbitrary input IR needs no generated support
        // source. Small programs normally use only one or two of them, but an
        // externally-linked unused definition still lands in the BPF .text
        // bundle and costs old-verifier/JIT work. Calls are all explicit by
        // this point, so an unused compiler-runtime definition is genuinely
        // unreachable. Iterate because deleting a dead wrapper can make its
        // private dependency dead too.
        unsigned prunedRuntime = 0;
        for (;;) {
            SmallVector<Function*> dead;
            for (Function& func : module) {
                if (!func.isDeclaration() && func.use_empty() && func.getName().starts_with("bpf_heap_")) {
                    dead.push_back(&func);
                }
            }
            if (dead.empty()) {
                break;
            }
            prunedRuntime += dead.size();
            for (Function* func : dead) {
                func->eraseFromParent();
            }
        }
        if (prunedRuntime) {
            bpf::stats() << "bpf-memory: pruned " << prunedRuntime << " unused runtime functions\n";
        }

        if (verifyModule(module, &errs())) {
            report_fatal_error("bpf-memory produced an invalid module");
        }
        return PreservedAnalyses::none();
    }

    // Follow an address back to the constant it was built from. Addresses are
    // plain integers here, so the chain is GEPs, ptrtoint/inttoptr pairs and
    // adds of a dynamic index onto a constant base — the shape stackify emits
    // for a frame slot, and the shape C emits for a global array subscript.
    // The layout guarantees no object straddles a region, so the base's region
    // is the access's region.
    std::optional<unsigned> TraceRegion(Value* v) {
        for (unsigned hops = 0; hops < 16; hops++) {
            if (auto* gep = dyn_cast<GEPOperator>(v)) {
                v = gep->getPointerOperand();
                continue;
            }
            if (auto* op = dyn_cast<Operator>(v);
                op && (op->getOpcode() == Instruction::IntToPtr || op->getOpcode() == Instruction::PtrToInt || op->getOpcode() == Instruction::BitCast)) {
                v = op->getOperand(0);
                continue;
            }
            if (auto* add = dyn_cast<BinaryOperator>(v); add && add->getOpcode() == Instruction::Add) {
                // The constant base is on whichever side is not the index.
                if (isa<ConstantInt>(add->getOperand(1))) {
                    v = add->getOperand(0);
                    continue;
                }
                if (isa<ConstantInt>(add->getOperand(0))) {
                    v = add->getOperand(1);
                    continue;
                }
                if (auto region = TraceRegion(add->getOperand(0))) {
                    return region;
                }
                v = add->getOperand(1);
                continue;
            }
            if (auto* k = dyn_cast<ConstantInt>(v)) {
                uint64_t base = k->getZExtValue();
                for (auto&& [start, end] : Spanning_) {
                    if (base >= start && base < end) {
                        return std::nullopt;
                    }
                }
                unsigned region = unsigned(base >> HeapShift);
                return region < Regions_.size() ? std::optional<unsigned>(region) : std::nullopt;
            }
            break;
        }
        return std::nullopt;
    }

    // Linux 5.15 can keep the pre-ALU32 identity of a global-subprogram
    // return in r0 even after shifts and an AND have established a small
    // unsigned range.  Adding that value to a map pointer is then rejected
    // using the stale identity.  Values copied through memory lose the
    // identity, so follow only SSA arithmetic and PHIs back to an executable
    // call.  Those rare offsets get an explicit verifier-visible range test;
    // ordinary offsets retain the branch-free mask fast path.
    bool DependsOnExecutableCall(Value* root) const {
        SmallVector<Value*, 16> work{root};
        SmallPtrSet<Value*, 32> seen;
        while (!work.empty()) {
            Value* value = work.pop_back_val();
            if (!seen.insert(value).second) {
                continue;
            }
            if (auto* call = dyn_cast<CallBase>(value)) {
                if (!isa<IntrinsicInst>(call) && !isa<InlineAsm>(call->getCalledOperand())) {
                    return true;
                }
            }
            // Memory and function arguments begin a new verifier identity;
            // do not chase the address of a load or a callee's inputs.
            if (isa<LoadInst>(value) || isa<Argument>(value) || isa<AllocaInst>(value) || isa<GlobalValue>(value) || isa<Constant>(value)) {
                continue;
            }
            if (auto* user = dyn_cast<User>(value)) {
                for (Value* operand : user->operands()) {
                    work.push_back(operand);
                }
            }
        }
        return false;
    }

    // The compiler-private stack marker cannot be named by source code. Follow
    // only pointer-building operations so direct descendants can use the
    // drive-cached verifier pointer before the marker is replaced by the
    // load-time-selected logical base.
    bool TracesToSoftwareStack(Value* v, unsigned hops = 0) {
        if (hops == 16) {
            return false;
        }
        if (v == SoftwareStackGlobal_) {
            return true;
        }
        if (auto* gep = dyn_cast<GEPOperator>(v)) {
            return TracesToSoftwareStack(gep->getPointerOperand(), hops + 1);
        }
        if (auto* op = dyn_cast<Operator>(v);
            op && (op->getOpcode() == Instruction::IntToPtr || op->getOpcode() == Instruction::PtrToInt || op->getOpcode() == Instruction::BitCast)) {
            return TracesToSoftwareStack(op->getOperand(0), hops + 1);
        }
        if (auto* add = dyn_cast<BinaryOperator>(v); add && add->getOpcode() == Instruction::Add) {
            for (Value* operand : add->operands()) {
                if (TracesToSoftwareStack(operand, hops + 1)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    bool IsSoftwareStackAddress(Value* ptr) {
        return SoftwareStackGlobal_ && TracesToSoftwareStack(ptr);
    }

    struct SoftwareStackAccess {
        Instruction* Memory;
        int64_t Offset;
        uint64_t Width;
    };

    // Split a compiler frame address into the dynamic frame root stackify
    // created and a constant byte offset from it.  Do not look through a
    // second dynamic GEP: that is a source-level addressable object whose
    // pointer must remain a scalar in Capsule's flat address domain.
    std::optional<std::pair<Value*, int64_t>> DecomposeSoftwareStackAddress(Module& module, Value* ptr) {
        APInt offset(64, 0, true);
        Value* value = ptr;
        for (unsigned hops = 0; hops < 16; hops++) {
            if (auto* gep = dyn_cast<GEPOperator>(value)) {
                APInt part(64, 0, true);
                if (gep->accumulateConstantOffset(module.getDataLayout(), part)) {
                    offset += part;
                    value = gep->getPointerOperand();
                    continue;
                }
                if (!TracesToSoftwareStack(gep->getPointerOperand())) {
                    return std::nullopt;
                }
                if (!offset.isSignedIntN(64)) {
                    return std::nullopt;
                }
                return std::pair<Value*, int64_t>(value, offset.getSExtValue());
            }
            if (auto* op = dyn_cast<Operator>(value); op && (op->getOpcode() == Instruction::BitCast || op->getOpcode() == Instruction::AddrSpaceCast)) {
                value = op->getOperand(0);
                continue;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    // Stackify forms a logical stack root as
    //
    //   bpf_call_stack + fiber * fiber_stack_size + (sp & (size - 1)).
    //
    // Once the fixed backend has the current fiber's native stack base, the
    // fiber term and logical bpf_call_stack base are irrelevant. Recover the
    // already-normalized local term instead of materializing the full logical
    // address merely to mask both parts away again.
    Value* RecoverFiberStackOffset(Value* root) {
        auto* gep = dyn_cast<GetElementPtrInst>(root);
        if (!gep || gep->getNumIndices() != 1 || !SoftwareStackGlobal_) {
            return nullptr;
        }
        if (!TracesToSoftwareStack(gep->getPointerOperand())) {
            return nullptr;
        }
        Value* linear = gep->idx_begin()->get();
        auto isStackOffset = [&](Value* candidate) {
            auto* mask = dyn_cast<BinaryOperator>(candidate);
            auto* constant = mask && mask->getOpcode() == Instruction::And ? dyn_cast<ConstantInt>(mask->getOperand(1)) : nullptr;
            return constant && constant->getValue() == FiberStackSize_ - 1;
        };
        // O2 may fold a constant normalized-fiber term away, leaving only the
        // already-masked local offset instead of the usual add expression.
        if (isStackOffset(linear)) {
            return linear;
        }
        auto* add = dyn_cast<BinaryOperator>(linear);
        if (!add || add->getOpcode() != Instruction::Add) {
            return nullptr;
        }
        for (Value* candidate : add->operands()) {
            if (isStackOffset(candidate)) {
                return candidate;
            }
        }
        return nullptr;
    }

    // Use the backing region resolved by the outer drive at the physical
    // function's compiler anchor, then translate each compiler-created frame
    // root relative to the current fiber's stack base.
    // Constant frame-field accesses share the verifier pointer; source
    // pointers that escape a frame remain scalars in the unified address
    // domain and use the outlined stack accessor below.
    SmallPtrSet<Instruction*, 32> PromoteSingleRegionSoftwareStack(Function& func) {
        SmallPtrSet<Instruction*, 32> promoted;
        if (!SoftwareStackGlobal_ || !FiberStackSize_) {
            return promoted;
        }
        CallBase* anchor = nullptr;
        for (Instruction& instruction : instructions(func)) {
            auto* call = dyn_cast<CallBase>(&instruction);
            if (call && IsStackAnchor(*call)) {
                anchor = call;
                break;
            }
        }
        if (!anchor) {
            return promoted;
        }
        uint64_t stackSpan = FiberStackSize_;
        Module& module = *func.getParent();
        MapVector<Value*, SmallVector<SoftwareStackAccess>> groups;
        for (Instruction& inst : instructions(func)) {
            Value* ptr = nullptr;
            if (auto* load = dyn_cast<LoadInst>(&inst)) {
                ptr = load->getPointerOperand();
            } else if (auto* store = dyn_cast<StoreInst>(&inst)) {
                ptr = store->getPointerOperand();
            } else if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
                ptr = rmw->getPointerOperand();
            } else if (auto* cx = dyn_cast<AtomicCmpXchgInst>(&inst)) {
                ptr = cx->getPointerOperand();
            }
            if (!ptr || !IsSoftwareStackAddress(ptr)) {
                continue;
            }
            auto path = DecomposeSoftwareStackAddress(module, ptr);
            if (!path || !isa<Instruction>(path->first)) {
                continue;
            }
            uint64_t width = module.getDataLayout().getTypeStoreSize(AccessType(&inst)).getFixedValue();
            groups[path->first].push_back({&inst, path->second, width});
        }

        LLVMContext& ctx = module.getContext();
        auto* i8 = Type::getInt8Ty(ctx);
        auto* i32 = Type::getInt32Ty(ctx);
        auto* i64 = Type::getInt64Ty(ctx);
        DominatorTree dominators(func);
        // A select is the cheapest valid-address clamp for ordinary physical
        // steps. In a very large dispatcher, however, Linux 5.15 retains the
        // invalid select state and re-explores thousands of later
        // instructions from it. Terminating that impossible compiler-stack
        // path trades one cold block for verifier scalability. Capture the
        // choice before adding guards so it stays consistent for the whole
        // physical function.
        constexpr unsigned LargePhysicalStepInstructions = 2048;
        const bool terminateInvalidStackPath = func.getInstructionCount() >= LargePhysicalStepInstructions;
        for (auto&& [root, group] : groups) {
            int64_t minimum = std::numeric_limits<int64_t>::max();
            int64_t maximum = std::numeric_limits<int64_t>::min();
            for (const SoftwareStackAccess& access : group) {
                if (access.Width > uint64_t(std::numeric_limits<int64_t>::max()) ||
                    access.Offset > std::numeric_limits<int64_t>::max() - int64_t(access.Width)) {
                    continue;
                }
                minimum = std::min(minimum, access.Offset);
                maximum = std::max(maximum, access.Offset + int64_t(access.Width));
            }
            if (minimum == std::numeric_limits<int64_t>::max() || maximum < minimum || uint64_t(maximum - minimum) > stackSpan) {
                continue;
            }
            uint64_t extent = uint64_t(maximum - minimum);
            if (extent > stackSpan) {
                continue;
            }

            auto* rootInst = cast<Instruction>(root);
            Instruction* insertion = nullptr;
            if (dominators.dominates(rootInst, anchor)) {
                // Stackify creates the current frame root immediately before
                // the anchor in the entry path. Insert after the anchor so its
                // cached native pointer is available without violating SSA.
                insertion = anchor->getNextNode();
            } else if (dominators.dominates(anchor, rootInst)) {
                insertion = rootInst->getNextNode();
            }
            if (!insertion) {
                continue;
            }
            IRBuilder<> b(insertion);
            Value* raw = RecoverFiberStackOffset(root);
            if (raw) {
                raw = b.CreateZExtOrTrunc(raw, i64, "bpf.stack.root.offset");
            } else {
                raw = b.CreatePtrToInt(root, i64);
            }
            if (minimum) {
                raw = b.CreateAdd(raw, ConstantInt::getSigned(i64, minimum));
            }
            auto* barrier = InlineAsm::get(FunctionType::get(i64, {i64}, false), "", "=r,0", /*hasSideEffects=*/true);
            Value* visible = b.CreateCall(barrier, {raw}, "bpf.stack.offset.visible");
            Value* low = b.CreateAnd(b.CreateTrunc(visible, i32), ConstantInt::get(i32, stackSpan - 1));
            auto* lowBarrier = InlineAsm::get(FunctionType::get(i32, {i32}, false), "", "=r,0", /*hasSideEffects=*/true);
            Value* visibleLow = b.CreateCall(lowBarrier, {low}, "bpf.stack.low.visible");
            Value* inRange = b.CreateICmpULE(visibleLow, ConstantInt::get(i32, stackSpan - extent));

            Value* boundedLow = visibleLow;
            if (terminateInvalidStackPath) {
                // A compiler-created current-frame root is either valid or an
                // internal memory fault. Let only the verifier-bounded state
                // enter the remainder of a large physical dispatcher.
                BasicBlock* prefix = b.GetInsertBlock();
                BasicBlock* valid = prefix->splitBasicBlock(insertion, "bpf.stack.valid");
                prefix->getTerminator()->eraseFromParent();
                BasicBlock* invalid = BasicBlock::Create(ctx, "bpf.stack.invalid", &func, valid);
                b.SetInsertPoint(prefix);
                b.CreateCondBr(inRange, valid, invalid);

                if (!func.getReturnType()->isIntegerTy(32) || anchor->arg_size() < 3) {
                    report_fatal_error(Twine("bpf-memory: malformed physical stack anchor in ") + func.getName());
                }
                IRBuilder<> ib(invalid);
                ib.CreateAlignedStore(ConstantInt::get(i64, bpf::ExitWordValue(CAPSULE_ERROR_MEMORY_FAULT)), anchor->getArgOperand(2), Align(8));
                ib.CreateRet(ConstantInt::get(i32, 0));
                b.SetInsertPoint(&*valid->getFirstInsertionPt());
            } else {
                boundedLow = b.CreateSelect(inRange, visibleLow, ConstantInt::get(i32, 0), "bpf.stack.low.bounded");
            }
            Value* nativeRoot = b.CreateGEP(i8, anchor->getArgOperand(0), {b.CreateZExt(boundedLow, i64)}, "bpf.stack.native");

            for (const SoftwareStackAccess& access : group) {
                uint64_t displacement = uint64_t(access.Offset - minimum);
                Value* address = displacement ? b.CreateGEP(i8, nativeRoot, {ConstantInt::get(i64, displacement)}) : nativeRoot;
                if (auto* load = dyn_cast<LoadInst>(access.Memory)) {
                    load->setOperand(LoadInst::getPointerOperandIndex(), address);
                } else if (auto* store = dyn_cast<StoreInst>(access.Memory)) {
                    store->setOperand(StoreInst::getPointerOperandIndex(), address);
                } else if (auto* rmw = dyn_cast<AtomicRMWInst>(access.Memory)) {
                    rmw->setOperand(AtomicRMWInst::getPointerOperandIndex(), address);
                } else {
                    auto* cx = cast<AtomicCmpXchgInst>(access.Memory);
                    cx->setOperand(AtomicCmpXchgInst::getPointerOperandIndex(), address);
                }
                promoted.insert(access.Memory);
                PromotedStackAccesses_.insert(access.Memory);
            }
            if (terminateInvalidStackPath) {
                dominators.recalculate(func);
            }
        }

        // The grouped form above shares one translation across several frame
        // fields, but deliberately stops when a compiler-created stack address
        // contains another dynamic GEP. Such an SSA value still belongs to the
        // current fiber: bpf_call_stack is compiler-private and cannot be named
        // by source code. Translate those remaining direct descendants through
        // outlined accessors using the drive-cached region. A pointer saved to and reloaded
        // from managed memory no longer traces to the stack global and keeps
        // using the generic unified-memory accessor, which is what permits
        // cross-fiber/shared logical pointers.
        SmallVector<Instruction*> fallback;
        for (Instruction& inst : instructions(func)) {
            if (promoted.contains(&inst)) {
                continue;
            }
            Value* ptr = nullptr;
            if (auto* load = dyn_cast<LoadInst>(&inst)) {
                ptr = load->getPointerOperand();
            } else if (auto* store = dyn_cast<StoreInst>(&inst)) {
                ptr = store->getPointerOperand();
            } else if (auto* rmw = dyn_cast<AtomicRMWInst>(&inst)) {
                ptr = rmw->getPointerOperand();
            } else if (auto* cx = dyn_cast<AtomicCmpXchgInst>(&inst)) {
                ptr = cx->getPointerOperand();
            }
            if (ptr && IsSoftwareStackAddress(ptr) && dominators.dominates(anchor, &inst)) {
                fallback.push_back(&inst);
            }
        }

        Argument* stackBase = nullptr;
        for (Argument& arg : func.args()) {
            if (arg.hasAttribute("bpf.capsule.stack.backing")) {
                stackBase = &arg;
                break;
            }
        }
        if (!fallback.empty() && !stackBase) {
            report_fatal_error(Twine("bpf-memory: cached stack access in ") + func.getName() + " has no stack-base argument");
        }

        for (Instruction* memory : fallback) {
            auto* load = dyn_cast<LoadInst>(memory);
            auto* store = dyn_cast<StoreInst>(memory);
            if (!load && !store) {
                // Atomic operations retain their ordinary unified-memory
                // lowering. They are rare, and preserving atomic semantics is
                // more important than specializing the current-fiber case.
                continue;
            }
            Type* type = load ? load->getType() : store->getValueOperand()->getType();
            uint64_t bits = module.getDataLayout().getTypeStoreSizeInBits(type);
            if ((!type->isIntegerTy() && !type->isPointerTy()) || (bits != 8 && bits != 16 && bits != 32 && bits != 64)) {
                continue;
            }
            Value* ptr = load ? load->getPointerOperand() : store->getPointerOperand();
            IRBuilder<> b(memory);
            Value* logical = b.CreatePtrToInt(ptr, i64, "bpf.stack.logical");
            Function* accessor = SoftwareStackAccessor(module, unsigned(bits), store != nullptr);
            DebugLoc loc = memory->getDebugLoc();
            if (!loc && func.getSubprogram()) {
                loc = DILocation::get(ctx, 0, 0, func.getSubprogram());
            }
            if (load) {
                CallInst* raw = b.CreateCall(accessor, {stackBase, logical});
                raw->setDebugLoc(loc);
                Value* value = type->isPointerTy() ? b.CreateIntToPtr(raw, type) : b.CreateZExtOrTrunc(raw, type);
                load->replaceAllUsesWith(value);
                load->eraseFromParent();
            } else {
                Value* value = store->getValueOperand();
                Value* raw = type->isPointerTy() ? b.CreatePtrToInt(value, i64) : b.CreateZExtOrTrunc(value, i64);
                b.CreateCall(accessor, {stackBase, logical, raw})->setDebugLoc(loc);
                store->eraseFromParent();
            }
        }
        return promoted;
    }

    // Rebuild a dynamic address into an explicitly-sectioned BPF global as
    //
    //   global + min(offset, object_size - access_size)
    //
    // (with an out-of-range offset redirected to byte zero). Source-level
    // range checks do not necessarily survive a managed suspension: the
    // scalar index is saved in the continuation frame, and Linux 5.15 then
    // sees an unconstrained scalar being added to a map-value pointer. Keep a
    // verifier-visible check immediately beside the access instead of
    // carrying native pointers through the software ABI.
    //
    // Redirecting an invalid access is permitted here because an out-of-range
    // C pointer dereference is already undefined. Valid accesses retain their
    // exact address. Unlike a power-of-two mask, the upper bound includes the
    // access width, so an unaligned word at the end of a map cannot cross the
    // map-value boundary.
    bool BoundSectionedGlobalAddress(Module& module, IRBuilder<>& b, Value* ptr, GlobalVariable* global, uint64_t accessSize, Value*& result) {
        SmallVector<GEPOperator*> geps;
        Value* cursor = ptr;
        while (cursor != global) {
            if (auto* gep = dyn_cast<GEPOperator>(cursor)) {
                geps.push_back(gep);
                cursor = gep->getPointerOperand();
                continue;
            }
            if (auto* cast = dyn_cast<Operator>(cursor);
                cast && (cast->getOpcode() == Instruction::BitCast || cast->getOpcode() == Instruction::AddrSpaceCast)) {
                cursor = cast->getOperand(0);
                continue;
            }
            return false;
        }

        SmallMapVector<Value*, APInt, 4> variables;
        APInt constant(64, 0);
        for (GEPOperator* gep : geps) {
            SmallMapVector<Value*, APInt, 4> localVariables;
            APInt localConstant(64, 0);
            if (!gep->collectOffset(module.getDataLayout(), 64, localVariables, localConstant)) {
                return false;
            }
            constant += localConstant;
            for (auto&& [value, scale] : localVariables) {
                auto it = variables.find(value);
                if (it == variables.end()) {
                    variables.insert({value, scale});
                } else {
                    it->second += scale;
                }
            }
        }
        if (variables.empty()) {
            return true;
        }

        uint64_t objectSize = module.getDataLayout().getTypeAllocSize(global->getValueType()).getFixedValue();
        if (!accessSize || accessSize > objectSize) {
            return false;
        }

        auto* i64 = Type::getInt64Ty(module.getContext());
        Value* offset = ConstantInt::get(i64, constant);
        for (auto&& [value, scale] : variables) {
            Value* index = b.CreateSExtOrTrunc(value, i64);
            APInt scale64 = scale.sextOrTrunc(64);
            if (!scale64.isOne()) {
                index = b.CreateMul(index, ConstantInt::get(i64, scale64));
            }
            offset = b.CreateAdd(offset, index);
        }

        auto* barrier = InlineAsm::get(
            FunctionType::get(i64, {i64}, false), "", "=r,0",
            /*hasSideEffects=*/true
        );
        Value* visible = b.CreateCall(barrier, {offset}, "bpf.global.offset.visible");
        Value* inRange = b.CreateICmpULE(visible, ConstantInt::get(i64, objectSize - accessSize));
        Value* bounded = b.CreateSelect(inRange, visible, ConstantInt::get(i64, 0), "bpf.global.offset.bounded");
        result = b.CreateGEP(Type::getInt8Ty(module.getContext()), global, {bounded});
        return true;
    }

    Type* AccessType(Instruction* inst) {
        if (auto* load = dyn_cast<LoadInst>(inst)) {
            return load->getType();
        }
        if (auto* store = dyn_cast<StoreInst>(inst)) {
            return store->getValueOperand()->getType();
        }
        if (auto* rmw = dyn_cast<AtomicRMWInst>(inst)) {
            return rmw->getValOperand()->getType();
        }
        return cast<AtomicCmpXchgInst>(inst)->getCompareOperand()->getType();
    }

    void BoundSectionedGlobalAccess(Instruction* inst, Value* ptr, unsigned ptrIdx, GlobalVariable* global) {
        Module& module = *inst->getModule();
        IRBuilder<> b(inst);
        Value* bounded = ptr;
        uint64_t accessSize = module.getDataLayout().getTypeStoreSize(AccessType(inst)).getFixedValue();
        if (!BoundSectionedGlobalAddress(module, b, ptr, global, accessSize, bounded)) {
            report_fatal_error(Twine("bpf-memory: cannot bound dynamic access into sectioned global ") + global->getName());
        }
        inst->setOperand(ptrIdx, bounded);
    }

    bool HasBoundedSectionedBase(Value* ptr) {
        SmallPtrSet<Value*, 8> seen;
        Value* value = ptr;
        while (seen.insert(value).second) {
            if (auto* instruction = dyn_cast<Instruction>(value); instruction && instruction->getMetadata("bpf.capsule.sectioned.bounded")) {
                return true;
            }
            if (auto* gep = dyn_cast<GEPOperator>(value)) {
                value = gep->getPointerOperand();
                continue;
            }
            if (auto* op = dyn_cast<Operator>(value); op && (op->getOpcode() == Instruction::BitCast || op->getOpcode() == Instruction::AddrSpaceCast)) {
                value = op->getOperand(0);
                continue;
            }
            return false;
        }
        return false;
    }

    // Native maps exist on both memory tiers. Keep their verifier pointer ABI
    // independent of whether ordinary C storage lives in fixed maps or an
    // arena: a scalar index reloaded after suspension always needs the same
    // explicit range proof before it is added to a map-value pointer.
    void BoundSectionedGlobalAccesses(Function& func) {
        SmallVector<Instruction*> work;
        for (Instruction& inst : instructions(func)) {
            if (isa<LoadInst>(inst) || isa<StoreInst>(inst) || isa<AtomicRMWInst>(inst) || isa<AtomicCmpXchgInst>(inst)) {
                work.push_back(&inst);
            }
        }
        for (Instruction* inst : work) {
            unsigned ptrIdx;
            Value* ptr;
            if (auto* load = dyn_cast<LoadInst>(inst)) {
                ptr = load->getPointerOperand();
                ptrIdx = LoadInst::getPointerOperandIndex();
            } else if (auto* store = dyn_cast<StoreInst>(inst)) {
                ptr = store->getPointerOperand();
                ptrIdx = StoreInst::getPointerOperandIndex();
            } else if (auto* rmw = dyn_cast<AtomicRMWInst>(inst)) {
                ptr = rmw->getPointerOperand();
                ptrIdx = AtomicRMWInst::getPointerOperandIndex();
            } else {
                auto* cx = cast<AtomicCmpXchgInst>(inst);
                ptr = cx->getPointerOperand();
                ptrIdx = AtomicCmpXchgInst::getPointerOperandIndex();
            }
            auto* global = dyn_cast<GlobalVariable>(getUnderlyingObject(ptr));
            if (!global || !global->hasSection()) {
                continue;
            }
            if (HasBoundedSectionedBase(ptr)) {
                continue;
            }
            BoundSectionedGlobalAccess(inst, ptr, ptrIdx, global);
        }
    }

    // The program supplies one accessor per access width; anything wider or
    // odd (vectors, i128) is left alone and will fail loudly at load time
    // rather than silently reading the wrong bytes.
    Function* Accessor(Module& module, Type* type, bool isStore) {
        uint64_t bits = module.getDataLayout().getTypeStoreSizeInBits(type);
        if (!type->isIntegerTy() && !type->isPointerTy()) {
            return nullptr;
        }
        if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
            return nullptr;
        }
        std::string name = (isStore ? "bpf_heap_store" : "bpf_heap_load") + std::to_string(bits);
        Function* func = module.getFunction(name);
        if (!func || func->isDeclaration()) {
            report_fatal_error(Twine("bpf-memory: the program must define ") + name);
        }
        return func;
    }

    // Slice the flat image across the regions that back it. Each region's map
    // is longer than the range it owns -- the tail shadows the start of the
    // next one -- so the shadow bytes are filled in here too, exactly as the
    // store path would maintain them at run time.
    void InstallImage(Module& module, const std::vector<uint8_t>& image) {
        LLVMContext& ctx = module.getContext();
        const uint64_t span = uint64_t(1) << HeapShift;
        unsigned installed = 0;

        for (unsigned r = 0; r < Regions_.size(); r++) {
            uint64_t begin = uint64_t(r) * span;
            if (begin >= image.size()) {
                break;
            }
            uint64_t size = cast<ArrayType>(Regions_[r]->getValueType())->getNumElements();
            std::vector<uint8_t> content(size, 0);
            uint64_t take = std::min<uint64_t>(size, image.size() - begin);
            std::copy(image.begin() + begin, image.begin() + begin + take, content.begin());

            if (llvm::all_of(content, [](uint8_t b) { return b == 0; })) {
                continue; // nothing to ship: leave it zero-filled in .bss
            }
            Regions_[r]->setInitializer(ConstantDataArray::get(ctx, content));
            Regions_[r]->setSection((".data.heap" + Twine(r)).str());
            installed++;
        }
        bpf::stats() << "bpf-memory: " << installed << " of " << Regions_.size() << " regions carry initialized data\n";
    }

    // Every access that is not provably a local stack slot goes through the
    // program's masked accessor.
    void RouteAccessesThroughHeap(Function& func) {
        Module& module = *func.getParent();
        LLVMContext& ctx = func.getContext();
        auto* i64 = Type::getInt64Ty(ctx);
        SmallPtrSet<Value*, 32> verifierNative;
        bpf::FindVerifierNativeValues(func, verifierNative);

        SmallVector<Instruction*> work;
        for (auto&& inst : instructions(func)) {
            if (isa<LoadInst>(&inst) || isa<StoreInst>(&inst) || isa<AtomicRMWInst>(&inst) || isa<AtomicCmpXchgInst>(&inst)) {
                work.push_back(&inst);
            }
        }

        for (auto* inst : work) {
            if (PromotedStackAccesses_.contains(inst)) {
                continue;
            }
            unsigned ptrIdx;
            Value* ptr;
            if (auto* load = dyn_cast<LoadInst>(inst)) {
                ptr = load->getPointerOperand();
                ptrIdx = LoadInst::getPointerOperandIndex();
            } else if (auto* store = dyn_cast<StoreInst>(inst)) {
                ptr = store->getPointerOperand();
                ptrIdx = StoreInst::getPointerOperandIndex();
            } else if (auto* rmw = dyn_cast<AtomicRMWInst>(inst)) {
                ptr = rmw->getPointerOperand();
                ptrIdx = AtomicRMWInst::getPointerOperandIndex();
            } else {
                auto* cx = cast<AtomicCmpXchgInst>(inst);
                ptr = cx->getPointerOperand();
                ptrIdx = AtomicCmpXchgInst::getPointerOperandIndex();
            }

            Value* base = getUnderlyingObject(ptr);
            if (isa<AllocaInst>(base)) {
                continue; // a real stack slot
            }
            if (auto* g = dyn_cast<GlobalVariable>(base); g && g->hasSection()) {
                if (HasBoundedSectionedBase(ptr)) {
                    continue;
                }
                BoundSectionedGlobalAccess(inst, ptr, ptrIdx, g);
                continue; // control block, maps, license
            }
            // Do this after the direct sectioned-global case: those pointers
            // are native too, but a dynamic index still needs an explicit
            // bound that older verifiers can see. This fallback is for PHIs
            // and selects whose native base is no longer recoverable by
            // getUnderlyingObject().
            if (verifierNative.contains(ptr)) {
                continue;
            }

            DebugLoc loc = inst->getDebugLoc();
            if (!loc) {
                if (auto* sp = func.getSubprogram()) {
                    loc = DILocation::get(ctx, 0, 0, sp);
                }
            }

            IRBuilder<> b(inst);
            auto* offset = b.CreatePtrToInt(ptr, i64);

            // Where the address traces back to a global we laid out, its
            // region is known now, so the access is a mask and an add — no
            // call. That pointer is consumed by this instruction alone and
            // never enters the program's own value space, where everything
            // stays an integer offset. It matters enormously for size: a call
            // at each of ~54,000 accesses is most of the program.
            //
            // The mask carries no width term and assumes nothing about
            // alignment: regions overlap by enough that an access anywhere in
            // [0, region size) is in range whatever its width. Assuming
            // alignment here was a real bug — LLVM derives it from the struct
            // type, while packed binary formats can place fields at offsets
            // aligned only by luck, so the mask quietly cleared offset bits.
            if (std::optional<unsigned> region = TraceRegion(ptr)) {
                bool callDerivedOffset = DependsOnExecutableCall(ptr);
                // The fixed-map memory model needs the AND to reach the BPF
                // instruction stream even when LLVM can prove it redundant.
                // That proof can be stronger than an older verifier's: 5.15,
                // for example, loses the bounds of two known-small values
                // after OR and then rejects the otherwise-safe map addition.
                // Make the input opaque before masking.  The tied empty asm
                // emits no instruction; its only run-time cost is the AND
                // that the verifier actually needs to see.
                auto* barrier = InlineAsm::get(
                    FunctionType::get(i64, {i64}, false), "", "=r,0",
                    /*hasSideEffects=*/true
                );
                Value* visibleOffset = b.CreateCall(barrier, {offset}, "bpf.map.offset.visible");
                // Express the region offset as ALU32, then zero-extend it.
                // Older verifiers can retain a stale signed 64-bit bound from
                // arithmetic that produced `offset` even after a 64-bit AND;
                // using a 32-bit subregister makes the zero upper half and the
                // final map-value bound explicit in BPF ISA semantics.
                Value* narrowOffset = b.CreateTrunc(visibleOffset, Type::getInt32Ty(ctx));
                Value* masked32 = b.CreateAnd(narrowOffset, ConstantInt::get(Type::getInt32Ty(ctx), (1u << HeapShift) - 1));
                Value* bounded32 = masked32;
                if (callDerivedOffset) {
                    auto* maskBarrier =
                        InlineAsm::get(FunctionType::get(Type::getInt32Ty(ctx), {Type::getInt32Ty(ctx)}, false), "", "=r,0", /*hasSideEffects=*/true);
                    Value* visibleMasked = b.CreateCall(maskBarrier, {masked32}, "bpf.map.masked.visible");
                    Value* inRange = b.CreateICmpULT(visibleMasked, ConstantInt::get(Type::getInt32Ty(ctx), 1u << HeapShift));
                    bounded32 = b.CreateSelect(inRange, visibleMasked, ConstantInt::get(Type::getInt32Ty(ctx), 0), "bpf.map.offset.bounded");
                }
                Value* masked = b.CreateZExt(bounded32, i64);
                inst->setOperand(ptrIdx, b.CreateGEP(Type::getInt8Ty(ctx), Regions_[*region], {masked}));
                continue;
            }

            if (auto* load = dyn_cast<LoadInst>(inst)) {
                Type* type = load->getType();
                Function* accessor = Accessor(module, type, /*isStore=*/false);
                if (!accessor) {
                    continue;
                }
                auto* raw = b.CreateCall(accessor, {offset});
                raw->setDebugLoc(loc);
                Value* value = type->isPointerTy() ? b.CreateIntToPtr(raw, type) : b.CreateZExtOrTrunc(raw, type);
                load->replaceAllUsesWith(value);
                load->eraseFromParent();
            } else if (auto* store = dyn_cast<StoreInst>(inst)) {
                Value* value = store->getValueOperand();
                Type* type = value->getType();
                Function* accessor = Accessor(module, type, /*isStore=*/true);
                if (!accessor) {
                    continue;
                }
                Value* raw = type->isPointerTy() ? b.CreatePtrToInt(value, i64) : b.CreateZExtOrTrunc(value, i64);
                b.CreateCall(accessor, {offset, raw})->setDebugLoc(loc);
                store->eraseFromParent();
            }
        }
    }

    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        if (FixedMemoryMode()) {
            return runFixedMemory(module);
        }
        LLVMContext& ctx = module.getContext();
        auto* i64 = Type::getInt64Ty(ctx);

        VirtualizeFunctionAddressesInCode(module);

        // --- Lay out initialized and sparse arena storage ----------------
        //
        // LLVM represents address-space-1 globals in one PROGBITS section.
        // Putting a large zero buffer there makes it literal file data, while
        // placing sparse storage at a constant address next to that section
        // couples the object to libbpf's choice of where the initialized image
        // sits in the arena mapping. Keep only real initialized bytes in the
        // ELF. __bpf_capsule_init asks the kernel for any free page span and
        // records its returned low address; sparse objects are base+offset.
        VerifyStackifyConsumedAllocas(module);

        auto* arenaControl = ArenaControl(module);

        std::vector<GlobalVariable*> movable;
        std::vector<GlobalVariable*> moved;
        std::vector<GlobalVariable*> zeroGlobals;
        for (auto&& g : module.globals()) {
            if (IsMovableGlobal(g)) {
                if (g.getName() == "bpf_call_stack") {
                    SoftwareStackGlobal_ = &g;
                    continue;
                }
                movable.push_back(&g);
            } else if (!g.isDeclaration() && !g.hasSection() && g.getAddressSpace() == ArenaAS && !g.getName().starts_with("llvm.")) {
                // Honor explicit __arena objects too: initialized ones are
                // already in the right section, while null ones must remain
                // sparse just like ordinary globals.
                if (g.getInitializer()->isNullValue()) {
                    zeroGlobals.push_back(&g);
                } else {
                    moved.push_back(&g);
                }
            }
        }

        for (auto* g : movable) {
            if (g->getInitializer()->isNullValue()) {
                zeroGlobals.push_back(g);
                continue;
            }
            auto* ng = new GlobalVariable(
                module, g->getValueType(), g->isConstant(), g->getLinkage(), g->getInitializer(), "", nullptr, GlobalVariable::NotThreadLocal, ArenaAS
            );
            ng->setAlignment(g->getAlign());
            g->replaceAllUsesWith(ConstantExpr::getAddrSpaceCast(ng, g->getType()));
            std::string name = g->getName().str();
            g->eraseFromParent();
            ng->setName(name);
            moved.push_back(ng);
        }

        const DataLayout& dl = module.getDataLayout();
        uint64_t virtualSize = 0;
        ZeroOffsets zeroOffsets;
        for (auto* g : zeroGlobals) {
            uint64_t align = std::max<uint64_t>(g->getAlign().valueOrOne().value(), dl.getABITypeAlign(g->getValueType()).value());
            virtualSize = (virtualSize + align - 1) & ~(align - 1);
            zeroOffsets[g] = virtualSize;
            uint64_t size = dl.getTypeAllocSize(g->getValueType());
            virtualSize += size;
        }
        HeapBase_ = alignTo(virtualSize, uint64_t(16));
        if (!SoftwareStackGlobal_) {
            report_fatal_error("bpf-arena: runtime has no unified software stack");
        }
        SoftwareStackBytes_ = dl.getTypeAllocSize(SoftwareStackGlobal_->getValueType());
        if (MDNode* metadata = SoftwareStackGlobal_->getMetadata("bpf.fiber.stack.size")) {
            if (auto* value = mdconst::dyn_extract<ConstantInt>(metadata->getOperand(0))) {
                FiberStackSize_ = value->getZExtValue();
            }
        }
        if (!FiberStackSize_ || SoftwareStackBytes_ % FiberStackSize_) {
            report_fatal_error("bpf-arena: malformed unified fiber stack bank");
        }

        // Arena-private storage is not a userspace data-map ABI. Keeping its
        // source debug attachment makes bpftool skeletons spell the complete
        // private object graph in the host header (PureDOOM alone exposes
        // dozens of engine types). ELF symbols still drive code relocations;
        // only explicitly sectioned maps retain typed BTF visibility.
        for (auto* global : moved) {
            global->eraseMetadata(ctx.getMDKindID("dbg"));
        }

        // --- Runtime initializer for pointer fields ----------------------
        SmallVector<std::pair<GlobalVariable*, std::pair<uint64_t, Constant*>>> fixups;
        for (auto* ng : moved) {
            SmallVector<std::pair<uint64_t, Constant*>> local;
            auto* sanitized = SanitizeInitializer(module, ng->getInitializer(), 0, local);
            if (sanitized != ng->getInitializer()) {
                ng->setInitializer(sanitized);
            }
            for (auto&& f : local) {
                fixups.emplace_back(ng, f);
            }
        }

        // The kernel permits an arena to cover one complete 32-bit address
        // window. Generate the requested virtual capacity instead of making
        // every object reserve the old fixed 64 MiB. Initialized globals and
        // the sparse allocation share the arena, so conservatively account
        // for alignment regardless of the backend's eventual symbol order.
        uint64_t initializedBytes = 0;
        for (GlobalVariable* global : moved) {
            uint64_t align = std::max<uint64_t>(global->getAlign().valueOrOne().value(), dl.getABITypeAlign(global->getValueType()).value());
            initializedBytes += align - 1;
            initializedBytes += dl.getTypeAllocSize(global->getValueType());
        }
        uint64_t initializedPages = (initializedBytes + BPF_CAPSULE_ARENA_PAGE_SIZE - 1) >> BPF_CAPSULE_ARENA_PAGE_SHIFT;
        constexpr uint64_t MaxArenaPages = BPF_CAPSULE_MAX_ARENA_PAGES;
        uint64_t defaultEnd = ConfigureObjectLayout(
            module, HeapBase_, FiberStackSize_, SoftwareStackBytes_ / FiberStackSize_, initializedPages, /*usesArena=*/1,
            /*stackFloor=*/0, BPF_CAPSULE_ARENA_PAGE_SIZE
        );
        uint64_t virtualPages = (defaultEnd + BPF_CAPSULE_ARENA_PAGE_SIZE - 1) >> BPF_CAPSULE_ARENA_PAGE_SHIFT;
        if (virtualPages + initializedPages > MaxArenaPages) {
            module.getContext().emitError(
                Twine("bpf-arena: default memory needs ") + Twine(virtualPages + initializedPages) + " pages (32-bit arena limit " + Twine(MaxArenaPages) + ")"
            );
            return PreservedAnalyses::none();
        }
        auto* arena = module.getGlobalVariable("arena", true);
        if (!arena || !arena->hasSection()) {
            report_fatal_error("bpf-arena: runtime must define arena map");
        }
        unsigned arenaPages = unsigned(std::max<uint64_t>(1, virtualPages + initializedPages));
        SetMapMaxEntries(module, *arena, arenaPages);
        ProduceInitGlobalsFunction(module, fixups, arenaControl, zeroOffsets);
        // Constants retained only by the temporary fixup list can keep their
        // source globals alive. The generated instructions no longer need it.
        fixups.clear();

        bpf::stats() << "bpf-arena: " << moved.size() << " initialized globals, " << (HeapBase_ >> 20) << " MiB static zero prefix, " << virtualPages
                     << " default sparse pages (heap and active fiber stacks selected before load)\n";

        // A moved global is represented in ordinary program IR as
        // `addrspacecast (ptr addrspace(1) @global to ptr)`.  LLVM's BPF
        // selector can fold the outer cast away when that constant is one
        // side of an equality comparison, while the dynamic side remains the
        // low-32-bit scalar arena address.  The resulting BPF compares an
        // arena pointer with its scalar offset and can never find an equal
        // address (a backwards scan over a moved array exposed this).
        //
        // Compare both operands in the arena address space whenever a
        // non-null equality is anchored by a value whose underlying object
        // is already arena-typed.  The conversion is injective over the
        // arena's 32-bit address domain, so eq/ne semantics are unchanged.
        CanonicalizeArenaPointerComparisons(module);

        // ptrtoint itself emits no BPF instruction, so a subtraction of two
        // such values can remain PTR_TO_ARENA in the verifier even though the
        // C result is a scalar pointer difference.  Normalize that exact
        // operation before later integer arithmetic sees it.  Do not rewrite
        // arbitrary ptrtoint operations: runtimes such as QuickJS deliberately
        // preserve the complete pointer bit pattern in tagged integer values.
        ScalarizePointerDifferences(module);

        // Replace sparse globals only after no later transformation can refer
        // to their soon-to-be-deleted GlobalVariable objects.
        MaterializeZeroGlobalUses(module, zeroGlobals, zeroOffsets, arenaControl);
        MaterializeSoftwareStackUses(module, arenaControl);
        LowerHeapIntrinsics(module, arenaControl);

        for (auto&& func : module) {
            if (func.isDeclaration() || !func.hasSection()) {
                continue;
            }
            if (func.getName() == "bpf_capsule_init") {
                continue;
            }
            Instruction* first = EntryPrologueInsertionPoint(func);
            IRBuilder<> initBuilder(first);
            Value* initFailed = nullptr;
            Value* initStatus = nullptr;
            if (func.getSection().starts_with("syscall")) {
                // BPF_PROG_TYPE_SYSCALL is sleepable, so it can retain the
                // loader-independent allocation fallback.
                Function* init = module.getFunction("__bpf_capsule_init");
                initStatus = initBuilder.CreateCall(init);
                initFailed = initBuilder.CreateICmpNE(initStatus, ConstantInt::get(initStatus->getType(), 0));
            } else {
                // bpf_arena_alloc_pages is sleepable-only on kernels where
                // non-sleepable program types (notably XDP) can otherwise use
                // an arena. Allocation is already performed by the generated
                // syscall initializer that bpf_capsule_finish_initialization()
                // runs after object load. Keep a real arena-map relocation in
                // this program so the verifier associates the same arena with
                // it, then fail closed until the initializer publishes ready=2.
                auto* associate =
                    InlineAsm::get(FunctionType::get(Type::getVoidTy(module.getContext()), {arena->getType()}, false), "", "r", /*hasSideEffects=*/true);
                initBuilder.CreateCall(associate, {arena});
                Value* ready = initBuilder.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaReady);
                Value* state = initBuilder.CreateLoad(Type::getInt32Ty(module.getContext()), ready, "bpf.arena.ready");
                initFailed = initBuilder.CreateICmpNE(state, ConstantInt::get(Type::getInt32Ty(module.getContext()), 2));
                initStatus = ConstantInt::getSigned(Type::getInt32Ty(module.getContext()), -11);
            }
            Instruction* failTerm = SplitBlockAndInsertIfThen(initFailed, first, false);
            IRBuilder<> failBuilder(failTerm);
            if (func.getReturnType()->isVoidTy()) {
                failBuilder.CreateRetVoid();
            } else if (func.getReturnType()->isIntegerTy()) {
                // Non-syscall program return codes have attach-type-specific
                // meaning; zero is the universally safe failure value (and is
                // XDP_ABORTED for XDP). Syscall entries preserve errno.
                Value* failure = func.getSection().starts_with("syscall") ? initStatus : ConstantInt::get(func.getReturnType(), 0);
                failBuilder.CreateRet(failBuilder.CreateSExtOrTrunc(failure, func.getReturnType()));
            } else {
                failBuilder.CreateRet(Constant::getNullValue(func.getReturnType()));
            }
            failTerm->eraseFromParent();
        }

        // --- Cast every non-stack access into the arena ------------------
        for (auto&& func : module) {
            if (!func.isDeclaration()) {
                BoundSectionedGlobalAccesses(func);
                CastUnsafeAccesses(func);
            }
        }

        if (verifyModule(module, &errs())) {
            report_fatal_error("bpf-arena produced invalid module");
        }

        return PreservedAnalyses::none();
    }

    void CanonicalizeArenaPointerComparisons(Module& module) {
        LLVMContext& ctx = module.getContext();
        auto* arenaPtr = PointerType::get(ctx, ArenaAS);
        SmallVector<ICmpInst*> work;

        auto anchoredInArena = [](Value* value) {
            Value* base = getUnderlyingObject(value);
            return base->getType()->isPointerTy() && base->getType()->getPointerAddressSpace() == ArenaAS;
        };
        auto mayBeProgramPointer = [](Value* value) {
            Value* base = getUnderlyingObject(value);
            if (isa<AllocaInst>(base)) {
                return false;
            }
            if (auto* global = dyn_cast<GlobalVariable>(base)) {
                return !global->hasSection();
            }
            return true;
        };

        for (Function& func : module) {
            if (func.isDeclaration()) {
                continue;
            }
            for (Instruction& inst : instructions(func)) {
                auto* cmp = dyn_cast<ICmpInst>(&inst);
                if (!cmp || !cmp->isEquality() || !cmp->getOperand(0)->getType()->isPointerTy() ||
                    cmp->getOperand(0)->getType()->getPointerAddressSpace() != 0 || isa<ConstantPointerNull>(cmp->getOperand(0)) ||
                    isa<ConstantPointerNull>(cmp->getOperand(1))) {
                    continue;
                }
                if ((anchoredInArena(cmp->getOperand(0)) || anchoredInArena(cmp->getOperand(1))) && mayBeProgramPointer(cmp->getOperand(0)) &&
                    mayBeProgramPointer(cmp->getOperand(1))) {
                    work.push_back(cmp);
                }
            }
        }

        for (ICmpInst* cmp : work) {
            IRBuilder<> b(cmp);
            Value* lhs = b.CreateAddrSpaceCast(cmp->getOperand(0), arenaPtr);
            Value* rhs = b.CreateAddrSpaceCast(cmp->getOperand(1), arenaPtr);
            Value* replacement = b.CreateICmp(cmp->getPredicate(), lhs, rhs, cmp->getName());
            if (auto* inst = dyn_cast<Instruction>(replacement)) {
                inst->setDebugLoc(cmp->getDebugLoc());
            }
            cmp->replaceAllUsesWith(replacement);
            cmp->eraseFromParent();
        }
    }

    using ZeroOffsets = DenseMap<GlobalVariable*, uint64_t>;

    Value* DynamicArenaAddress(IRBuilder<>& b, Value* base, uint64_t offset, PointerType* type) {
        auto* i64 = Type::getInt64Ty(b.getContext());
        Value* address = offset ? b.CreateAdd(base, ConstantInt::get(i64, offset), "bpf.arena.address") : base;
        auto* arenaType = PointerType::get(b.getContext(), ArenaAS);
        Value* arenaPointer = b.CreateIntToPtr(address, arenaType, "bpf.arena.typed");
        if (type->getAddressSpace() == ArenaAS) {
            return arenaPointer;
        }
        // Preserve the source-level address-space-0 type. CastUnsafeAccesses
        // recognizes this exact arena->ordinary wrapper and unwraps it at a
        // dereference, leaving one ordinary->arena conversion rather than a
        // backend-inferred round trip.
        return b.CreateAddrSpaceCast(arenaPointer, type, "bpf.arena.program.pointer");
    }

    bool ReferencesZeroGlobal(Constant* value, const ZeroOffsets& offsets) {
        SmallPtrSet<Constant*, 16> visited;
        SmallVector<Constant*> work{value};
        while (!work.empty()) {
            Constant* current = work.pop_back_val();
            if (!visited.insert(current).second) {
                continue;
            }
            if (auto* global = dyn_cast<GlobalVariable>(current); global && offsets.contains(global)) {
                return true;
            }
            for (Value* operand : current->operands()) {
                if (auto* constant = dyn_cast<Constant>(operand)) {
                    work.push_back(constant);
                }
            }
        }
        return false;
    }

    // Turn a pointer-shaped initializer constant into instructions while
    // substituting dynamically allocated sparse globals. SanitizeInitializer
    // has already split aggregates, so a fixup is normally a global or a
    // ConstantExpr chain rooted in one.
    Value* MaterializeZeroConstant(IRBuilder<>& b, Constant* value, Value* base, const ZeroOffsets& offsets) {
        if (auto* global = dyn_cast<GlobalVariable>(value)) {
            if (auto found = offsets.find(global); found != offsets.end()) {
                return DynamicArenaAddress(b, base, found->second, cast<PointerType>(global->getType()));
            }
        }
        if (!ReferencesZeroGlobal(value, offsets)) {
            return value;
        }
        if (auto* expression = dyn_cast<ConstantExpr>(value)) {
            Instruction* instruction = expression->getAsInstruction();
            for (unsigned i = 0; i < instruction->getNumOperands(); ++i) {
                if (auto* operand = dyn_cast<Constant>(instruction->getOperand(i)); operand && ReferencesZeroGlobal(operand, offsets)) {
                    instruction->setOperand(i, MaterializeZeroConstant(b, operand, base, offsets));
                }
            }
            b.Insert(instruction);
            return instruction;
        }

        std::string description;
        raw_string_ostream out(description);
        value->print(out);
        report_fatal_error(Twine("bpf-arena: cannot materialize sparse initializer ") + out.str());
    }

    void MaterializeZeroGlobalUses(Module& module, ArrayRef<GlobalVariable*> globals, const ZeroOffsets& offsets, GlobalVariable* arenaControl) {
        SmallVector<Constant*> constants;
        constants.reserve(globals.size());
        for (GlobalVariable* global : globals) {
            constants.push_back(global);
        }

        // `used` is a retention request for the original storage object. The
        // replacement addresses are now explicit instructions, so retaining
        // the deleted ELF symbol would only recreate the large zero image.
        SmallPtrSet<GlobalVariable*, 16> zeroSet(globals.begin(), globals.end());
        removeFromUsedLists(module, [&](Constant* value) { return zeroSet.contains(dyn_cast<GlobalVariable>(value->stripPointerCasts())); });

        for (Function& function : module) {
            if (function.isDeclaration()) {
                continue;
            }
            convertUsersOfConstantsToInstructions(constants, &function, /*RemoveDeadConstants=*/false);

            DenseMap<GlobalVariable*, SmallVector<Use*>> uses;
            for (GlobalVariable* global : globals) {
                for (Use& use : global->uses()) {
                    auto* instruction = dyn_cast<Instruction>(use.getUser());
                    if (instruction && instruction->getFunction() == &function) {
                        uses[global].push_back(&use);
                    }
                }
            }
            if (uses.empty()) {
                continue;
            }

            // The arena pass inserts __bpf_capsule_init ahead of this point in
            // every sectioned entry. Non-entry functions are reached only
            // through those entries, so one load dominates all uses and is
            // the only steady-state cost of loader-independent placement.
            Instruction* first = EntryPrologueInsertionPoint(function);
            IRBuilder<> b(first);
            Value* baseSlot = b.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaVirtualBase);
            Value* base = b.CreateLoad(Type::getInt64Ty(module.getContext()), baseSlot, "bpf.arena.base");
            for (auto&& [global, localUses] : uses) {
                Value* address = DynamicArenaAddress(b, base, offsets.lookup(global), cast<PointerType>(global->getType()));
                for (Use* use : localUses) {
                    use->set(address);
                }
            }
        }

        for (GlobalVariable* global : globals) {
            global->removeDeadConstantUsers();
            if (!global->use_empty()) {
                std::string description;
                raw_string_ostream out(description);
                global->print(out);
                report_fatal_error(Twine("bpf-arena: sparse global still has a constant use: ") + out.str());
            }
            global->eraseFromParent();
        }
    }

    void ProduceInitGlobalsFunction(
        Module& module, ArrayRef<std::pair<GlobalVariable*, std::pair<uint64_t, Constant*>>> fixups, GlobalVariable* arenaControl,
        const ZeroOffsets& zeroOffsets
    ) {
        std::string name = "__bpf_capsule_init";
        Function* decl = module.getFunction(name);
        if (decl && !decl->isDeclaration()) {
            report_fatal_error("__bpf_capsule_init already defined");
        }

        LLVMContext& ctx = module.getContext();
        auto* func = Function::Create(FunctionType::get(Type::getInt32Ty(ctx), false), Function::InternalLinkage, name + ".impl", module);
        func->setCallingConv(CallingConv::C);
        func->addFnAttr(Attribute::NoInline);
        // Late physical spill relocation may use lane zero here. The 0->1->2
        // state transition below excludes every managed entry until this
        // function has returned, so it cannot overlap a fiber-zero step.
        func->setMetadata("bpf.capsule.init", MDNode::get(ctx, {}));

        auto* block = BasicBlock::Create(ctx, "entry", func);
        auto* claim = BasicBlock::Create(ctx, "claim", func);
        auto* allocate = BasicBlock::Create(ctx, "allocate", func);
        auto* initialize = BasicBlock::Create(ctx, "initialize", func);
        auto* busy = BasicBlock::Create(ctx, "busy", func);
        auto* failed = BasicBlock::Create(ctx, "failed", func);
        auto* done = BasicBlock::Create(ctx, "done", func);
        IRBuilder<> b(block);

        auto* arena = module.getGlobalVariable("arena", true);
        if (!arena) {
            report_fatal_error("bpf-arena: runtime must define arena");
        }
        Value* ready = b.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaReady);
        Value* virtualBase = b.CreateStructGEP(arenaControl->getValueType(), arenaControl, ArenaVirtualBase);
        auto* readyType = Type::getInt32Ty(ctx);
        auto* allocPages = module.getFunction("bpf_arena_alloc_pages");
        if (!allocPages) {
            auto* ptr = PointerType::get(ctx, 0);
            auto* arenaPtr = PointerType::get(ctx, ArenaAS);
            allocPages = Function::Create(
                FunctionType::get(arenaPtr, {ptr, arenaPtr, Type::getInt32Ty(ctx), Type::getInt32Ty(ctx), Type::getInt64Ty(ctx)}, false),
                Function::ExternalLinkage, "bpf_arena_alloc_pages", module
            );
            allocPages->setCallingConv(CallingConv::C);
            allocPages->setSection(".ksyms");
            if (!module.debug_compile_units().empty()) {
                DIBuilder db(module, false, *module.debug_compile_units_begin());
                auto* voidType = db.createUnspecifiedType("void");
                auto* pointerType = db.createPointerType(voidType, 64);
                BtfFunctionAddDebugInfo(
                    db, *allocPages, {pointerType, pointerType, pointerType, BtfGetInt(db, 32, false), BtfGetInt(db, 32, true), BtfGetInt(db, 64, false)}
                );
                db.finalize();
            }
        }
        Value* isReady = b.CreateICmpEQ(b.CreateLoad(readyType, ready), ConstantInt::get(readyType, 2));
        b.CreateCondBr(isReady, done, claim);

        // Loading an arena object and entering two programs concurrently used
        // to let both allocate a different sparse span and overwrite the
        // shared base. Elect exactly one initializer. A concurrent fallback
        // entry returns -EAGAIN. Applications normally perform this transition
        // explicitly with bpf_capsule_finish_initialization(), before exposing
        // any application entry.
        b.SetInsertPoint(claim);
        auto* claimed = b.CreateAtomicCmpXchg(
            ready, ConstantInt::get(readyType, 0), ConstantInt::get(readyType, 1), Align(4), AtomicOrdering::SequentiallyConsistent,
            AtomicOrdering::SequentiallyConsistent
        );
        claimed->setWeak(false);
        Value* won = b.CreateExtractValue(claimed, 1, "bpf.arena.init.won");
        Value* previous = b.CreateExtractValue(claimed, 0, "bpf.arena.init.previous");
        Value* becameReady = b.CreateICmpEQ(previous, ConstantInt::get(readyType, 2));
        auto* contested = BasicBlock::Create(ctx, "contested", func);
        b.CreateCondBr(won, allocate, contested);

        b.SetInsertPoint(contested);
        b.CreateCondBr(becameReady, done, busy);

        b.SetInsertPoint(allocate);
        GlobalVariable* config = ObjectConfig(module);
        Value* memoryEndSlot = b.CreateStructGEP(config->getValueType(), config, ConfigMemoryEnd);
        auto* memoryEnd = b.CreateLoad(Type::getInt64Ty(ctx), memoryEndSlot, "bpf.memory.end");
        memoryEnd->setVolatile(true);
        Value* selectedPages = b.CreateLShr(
            b.CreateAdd(memoryEnd, ConstantInt::get(Type::getInt64Ty(ctx), BPF_CAPSULE_ARENA_PAGE_SIZE - 1)),
            ConstantInt::get(Type::getInt64Ty(ctx), BPF_CAPSULE_ARENA_PAGE_SHIFT), "bpf.arena.selected.pages"
        );
        Value* pages = b.CreateTrunc(selectedPages, Type::getInt32Ty(ctx));
        Value* allocation = b.CreateCall(
            allocPages,
            {
                arena,
                ConstantPointerNull::get(PointerType::get(ctx, ArenaAS)),
                pages,
                ConstantInt::getSigned(Type::getInt32Ty(ctx), -1),
                ConstantInt::get(Type::getInt64Ty(ctx), 0),
            }
        );
        Value* allocated = b.CreateICmpNE(allocation, Constant::getNullValue(allocation->getType()));
        b.CreateCondBr(allocated, initialize, failed);

        b.SetInsertPoint(initialize);
        // Convert the returned arena pointer to the low scalar address used
        // by ordinary program pointers. Address-space casts restore the arena
        // high bits at each memory access.
        Value* allocationScalar =
            b.CreatePtrToInt(b.CreateAddrSpaceCast(allocation, PointerType::get(ctx, 0), "bpf.arena.low.pointer"), Type::getInt64Ty(ctx), "bpf.arena.low");
        b.CreateStore(allocationScalar, virtualBase);
        for (auto&& [g, fix] : fixups) {
            auto&& [offset, value] = fix;
            auto* slot = b.CreatePtrAdd(g, ConstantInt::get(Type::getInt64Ty(ctx), offset));
            b.CreateStore(MaterializeZeroConstant(b, value, allocationScalar, zeroOffsets), slot);
        }
        b.CreateAtomicRMW(AtomicRMWInst::Xchg, ready, ConstantInt::get(readyType, 2), Align(4), AtomicOrdering::SequentiallyConsistent);
        b.CreateBr(done);

        b.SetInsertPoint(busy);
        b.CreateRet(ConstantInt::getSigned(Type::getInt32Ty(ctx), -11));

        b.SetInsertPoint(failed);
        // Allocation failures are retryable. Publish the failure only through
        // this invocation's return value and leave the object uninitialized.
        b.CreateAtomicRMW(AtomicRMWInst::Xchg, ready, ConstantInt::get(readyType, 0), Align(4), AtomicOrdering::SequentiallyConsistent);
        b.CreateRet(ConstantInt::getSigned(Type::getInt32Ty(ctx), -12));

        b.SetInsertPoint(done);
        b.CreateRet(ConstantInt::get(Type::getInt32Ty(ctx), 0));

        if (!module.debug_compile_units().empty()) {
            DIBuilder debugBuilder(module, false, *module.debug_compile_units_begin());
            BtfFunctionAddDebugInfo(debugBuilder, *func, {BtfGetInt(debugBuilder, 32, true)});
            debugBuilder.finalize();
        }

        if (decl) {
            decl->replaceAllUsesWith(func);
            decl->eraseFromParent();
        }
        func->setName(name);

        // libbpf has no global-constructor hook for an arena object. Expose a
        // tiny test-run program so the host wrapper can complete allocation
        // and pointer fixups before returning the loaded object. Entry
        // prologues retain the same call as a stock-loader fallback.
        if (module.getFunction("bpf_capsule_init")) {
            report_fatal_error("bpf_capsule_init already defined");
        }
        auto* entry = Function::Create(FunctionType::get(Type::getInt32Ty(ctx), false), Function::ExternalLinkage, "bpf_capsule_init", module);
        entry->setCallingConv(CallingConv::C);
        entry->setSection("syscall");
        entry->addFnAttr(Attribute::NoInline);
        auto* entryBlock = BasicBlock::Create(ctx, "entry", entry);
        IRBuilder<> entryBuilder(entryBlock);
        entryBuilder.CreateRet(entryBuilder.CreateCall(func));
        if (!module.debug_compile_units().empty()) {
            DIBuilder debugBuilder(module, false, *module.debug_compile_units_begin());
            BtfFunctionAddDebugInfo(debugBuilder, *entry, {BtfGetInt(debugBuilder, 32, true)});
            debugBuilder.finalize();
        }
    }

    void ScalarizePointerDifferences(Module& module) {
        LLVMContext& ctx = module.getContext();
        auto* arenaPtr = PointerType::get(ctx, ArenaAS);
        SmallVector<BinaryOperator*> work;

        // ptrtoint may be either an instruction (the dynamic operand) or a
        // ConstantExpr (typically the address of a moved global).  Treat both
        // uniformly: requiring PtrToIntInst on both sides missed ordinary
        // expressions such as `dynamic_ptr - global_array`.
        auto pointerOperand = [](Value* value) -> Value* {
            auto* op = dyn_cast<Operator>(value);
            return op && op->getOpcode() == Instruction::PtrToInt ? op->getOperand(0) : nullptr;
        };

        for (Function& func : module) {
            if (func.isDeclaration()) {
                continue;
            }
            for (Instruction& inst : instructions(func)) {
                auto* sub = dyn_cast<BinaryOperator>(&inst);
                if (!sub || sub->getOpcode() != Instruction::Sub) {
                    continue;
                }
                Value* lhs = pointerOperand(sub->getOperand(0));
                Value* rhs = pointerOperand(sub->getOperand(1));
                if (!lhs || !rhs || cast<PointerType>(lhs->getType())->getAddressSpace() == ArenaAS ||
                    cast<PointerType>(rhs->getType())->getAddressSpace() == ArenaAS) {
                    continue;
                }

                auto isArenaProgramPointer = [](Value* pointer) {
                    Value* base = getUnderlyingObject(pointer);
                    if (isa<AllocaInst>(base)) {
                        return false;
                    }
                    auto* global = dyn_cast<GlobalVariable>(base);
                    return !global || !global->hasSection();
                };
                if (!isArenaProgramPointer(lhs) || !isArenaProgramPointer(rhs)) {
                    continue;
                }
                work.push_back(sub);
            }
        }

        for (BinaryOperator* sub : work) {
            Value* lhs = pointerOperand(sub->getOperand(0));
            Value* rhs = pointerOperand(sub->getOperand(1));
            IRBuilder<> b(sub);
            Value* lhsScalar = b.CreatePtrToInt(b.CreateAddrSpaceCast(lhs, arenaPtr), sub->getType());
            Value* rhsScalar = b.CreatePtrToInt(b.CreateAddrSpaceCast(rhs, arenaPtr), sub->getType());
            // An addrspacecast may reconstruct the kernel's high arena bits.
            // The BPF backend does not always reconstruct both operands
            // symmetrically, so subtract their unsigned low-32 addresses as
            // i64 scalars. The arena cannot cross a 32-bit boundary; this
            // therefore preserves both forward differences above 2 GiB and
            // negative backward differences without a modulo/sign ambiguity.
            auto* i32 = Type::getInt32Ty(ctx);
            Value* lhsLow = b.CreateZExt(b.CreateTrunc(lhsScalar, i32), Type::getInt64Ty(ctx));
            Value* rhsLow = b.CreateZExt(b.CreateTrunc(rhsScalar, i32), Type::getInt64Ty(ctx));
            Value* rawDifference = b.CreateSub(lhsLow, rhsLow, sub->getName() + ".raw");
            Value* replacement =
                sub->getType() == i32 ? b.CreateTrunc(rawDifference, i32, sub->getName()) : b.CreateSExtOrTrunc(rawDifference, sub->getType(), sub->getName());
            if (auto* inst = dyn_cast<Instruction>(replacement)) {
                inst->setDebugLoc(sub->getDebugLoc());
            }
            sub->replaceAllUsesWith(replacement);
            sub->eraseFromParent();
        }
    }

    void CastUnsafeAccesses(Function& func) {
        LLVMContext& ctx = func.getContext();
        auto* ptrAs1 = PointerType::get(ctx, ArenaAS);
        DominatorTree dt(func);
        LoopInfo loops(dt);

        SmallPtrSet<Value*, 32> verifierNative;
        bpf::FindVerifierNativeValues(func, verifierNative);

        auto needsCast = [&](Value* ptr) {
            if (ptr->getType()->getPointerAddressSpace() == ArenaAS) {
                return false; // already arena-typed; backend handles casts
            }
            if (verifierNative.contains(ptr)) {
                return false; // borrowed ctx/packet pointer keeps provenance
            }
            Value* base = getUnderlyingObject(ptr);
            if (isa<AllocaInst>(base)) {
                return false; // surviving allocas are provably local
            }
            if (auto* g = dyn_cast<GlobalVariable>(base); g && g->hasSection()) {
                return false; // control block etc: direct map access
            }
            return true;
        };

        // Cast a shared address expression once per basic block, then rebuild
        // its GEP suffix in the arena address space.  Casting the final pointer
        // independently at every access is semantically correct, but the ARM64
        // BPF JIT expands each cast into arena-base reconstruction.  A common
        // three-byte codec copy consequently paid that sequence six times per
        // iteration.  Only do this inside an actual native loop and when at
        // least two accesses share a root: rebuilding an acyclic or one-use
        // GEP duplicates static code without enough runtime amortization.
        // Stopping at PHIs/selects keeps the rewrite local and dominance-
        // trivial; the cast still applies the arena's required low-32-bit
        // canonicalization once before any derived address is dereferenced.
        DenseMap<BasicBlock*, DenseMap<Value*, Value*>> arenaByBlock;
        auto arenaPointer = [&](auto&& self, Value* ptr, Instruction* before) -> Value* {
            if (ptr->getType()->getPointerAddressSpace() == ArenaAS) {
                return ptr;
            }
            auto& cache = arenaByBlock[before->getParent()];
            if (Value* cached = cache.lookup(ptr)) {
                return cached;
            }

            IRBuilder<> b(before);
            Value* converted = nullptr;
            if (auto* cast = dyn_cast<AddrSpaceCastOperator>(ptr); cast && cast->getPointerOperand()->getType()->getPointerAddressSpace() == ArenaAS) {
                converted = cast->getPointerOperand();
            } else if (auto* gep = dyn_cast<GetElementPtrInst>(ptr)) {
                Value* base = self(self, gep->getPointerOperand(), before);
                SmallVector<Value*, 4> indices(gep->idx_begin(), gep->idx_end());
                auto* rebuilt = GetElementPtrInst::Create(gep->getSourceElementType(), base, indices, gep->getName() + ".arena", before->getIterator());
                rebuilt->setNoWrapFlags(gep->getNoWrapFlags());
                rebuilt->setDebugLoc(gep->getDebugLoc());
                converted = rebuilt;
            } else {
                converted = b.CreateAddrSpaceCast(ptr, ptrAs1, ptr->getName() + ".arena");
                if (auto* cast = dyn_cast<Instruction>(converted)) {
                    cast->setDebugLoc(before->getDebugLoc());
                }
            }
            cache[ptr] = converted;
            return converted;
        };

        SmallVector<Instruction*> work;
        for (auto&& inst : instructions(func)) {
            if (isa<LoadInst>(&inst) || isa<StoreInst>(&inst) || isa<AtomicRMWInst>(&inst) || isa<AtomicCmpXchgInst>(&inst)) {
                work.push_back(&inst);
            }
        }

        auto pointerOperand = [](Instruction* inst) {
            if (auto* load = dyn_cast<LoadInst>(inst)) {
                return std::pair<Value*, unsigned>{load->getPointerOperand(), LoadInst::getPointerOperandIndex()};
            }
            if (auto* store = dyn_cast<StoreInst>(inst)) {
                return std::pair<Value*, unsigned>{store->getPointerOperand(), StoreInst::getPointerOperandIndex()};
            }
            if (auto* rmw = dyn_cast<AtomicRMWInst>(inst)) {
                return std::pair<Value*, unsigned>{rmw->getPointerOperand(), AtomicRMWInst::getPointerOperandIndex()};
            }
            auto* cx = cast<AtomicCmpXchgInst>(inst);
            return std::pair<Value*, unsigned>{cx->getPointerOperand(), AtomicCmpXchgInst::getPointerOperandIndex()};
        };
        auto addressRoot = [](Value* ptr) {
            while (auto* gep = dyn_cast<GetElementPtrInst>(ptr)) {
                ptr = gep->getPointerOperand();
            }
            return ptr;
        };
        DenseMap<BasicBlock*, DenseMap<Value*, unsigned>> rootUses;
        for (Instruction* inst : work) {
            auto [ptr, ptrIdx] = pointerOperand(inst);
            if (loops.getLoopFor(inst->getParent()) && needsCast(ptr)) {
                rootUses[inst->getParent()][addressRoot(ptr)]++;
            }
        }

        for (auto* inst : work) {
            auto [ptr, ptrIdx] = pointerOperand(inst);
            if (!needsCast(ptr)) {
                continue;
            }
            if (rootUses[inst->getParent()].lookup(addressRoot(ptr)) >= 2) {
                inst->setOperand(ptrIdx, arenaPointer(arenaPointer, ptr, inst));
                continue;
            }
            IRBuilder<> b(inst);
            Value* casted = b.CreateAddrSpaceCast(ptr, ptrAs1);
            if (auto* cast = dyn_cast<Instruction>(casted)) {
                cast->setDebugLoc(inst->getDebugLoc());
            }
            inst->setOperand(ptrIdx, casted);
        }
    }
};

} // namespace

bool RegisterMemoryPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-memory") {
        return false;
    }
    manager.addPass(MemoryPass());
    return true;
}
