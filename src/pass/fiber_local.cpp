// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-fiber-local: thread-local variables become fiber-local storage.
//
// A fiber is Capsule's thread: it owns a stack, survives across the calls
// made on it, and ends with capsule_reset. Each annotated variable therefore
// gets one slot per fiber in a block laid out like an ELF TLS image, and
// every use is rewritten to address the current fiber's block through the
// fiber index the physical step already carries. capsule_reset restores a
// fiber's block from the initial image through the runtime hook this pass
// defines; ordinary completion leaves the block for the slot's next call.
#include "fiber_local.h"

#include "common.h"
#include "runtime_symbols.h"

#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ReplaceConstant.h>
#include <llvm/Support/ErrorHandling.h>

#include <algorithm>

using namespace llvm;

namespace {

constexpr StringLiteral Annotation{"capsule.fiber_local"};

// Consume this pass's entries of llvm.global.annotations, leaving the rest
// (and the array itself) untouched for later passes.
SmallVector<GlobalVariable*> ConsumeAnnotations(Module& module) {
    SmallVector<GlobalVariable*> locals;
    auto* annotations = module.getGlobalVariable("llvm.global.annotations");
    if (!annotations || !annotations->hasInitializer()) {
        return locals;
    }
    auto* array = dyn_cast<ConstantArray>(annotations->getInitializer());
    if (!array) {
        return locals;
    }
    SmallVector<Constant*> kept;
    for (Use& operand : array->operands()) {
        auto* entry = dyn_cast<ConstantStruct>(operand.get());
        auto* global = entry && entry->getNumOperands() >= 2 ? dyn_cast<GlobalVariable>(entry->getOperand(0)->stripPointerCasts()) : nullptr;
        StringRef text;
        if (global && getConstantStringInfo(entry->getOperand(1)->stripPointerCasts(), text) && text == Annotation) {
            if (!is_contained(locals, global)) {
                locals.push_back(global);
            }
            continue;
        }
        kept.push_back(cast<Constant>(operand.get()));
    }
    if (kept.size() == array->getNumOperands()) {
        return locals;
    }
    annotations->eraseFromParent();
    for (GlobalVariable* global : locals) {
        global->removeDeadConstantUsers();
    }
    if (!kept.empty()) {
        auto* keptType = ArrayType::get(kept.front()->getType(), kept.size());
        auto* rebuilt =
            new GlobalVariable(module, keptType, false, GlobalValue::AppendingLinkage, ConstantArray::get(keptType, kept), "llvm.global.annotations");
        rebuilt->setSection("llvm.metadata");
    }
    return locals;
}

} // namespace

PreservedAnalyses FiberLocalPass::run(Module& module, ModuleAnalysisManager&) {
    SmallVector<GlobalVariable*> locals = ConsumeAnnotations(module);
    // Frontends whose target model permits it (Rust's #[thread_local]) emit
    // genuine thread_local globals; only the BPF backend rejects them.
    for (GlobalVariable& global : module.globals()) {
        if (global.isThreadLocal() && !is_contained(locals, &global)) {
            locals.push_back(&global);
        }
    }
    for (GlobalVariable* local : locals) {
        local->setThreadLocalMode(GlobalValue::NotThreadLocal);
    }
    if (locals.empty()) {
        return PreservedAnalyses::all();
    }
    for (GlobalVariable* local : locals) {
        if (local->isDeclaration()) {
            report_fatal_error(Twine("bpf-fiber-local: thread-local variable ") + local->getName() + " has no definition");
        }
    }

    // The runtime's fiber table fixes the ceiling every per-fiber table shares.
    auto* controls = module.getGlobalVariable(bpf::sym::FiberControls, true);
    auto* controlsType = controls ? dyn_cast<ArrayType>(controls->getValueType()) : nullptr;
    if (!controlsType || !controlsType->getNumElements()) {
        report_fatal_error("bpf-fiber-local: thread-local variables need the Capsule runtime's fiber table");
    }
    uint64_t fibers = controlsType->getNumElements();

    // Lay the block out like a TLS image: strictest alignment first, then by
    // name, so the result does not depend on the input's global order.
    LLVMContext& context = module.getContext();
    const DataLayout& layout = module.getDataLayout();
    auto alignmentOf = [&](const GlobalVariable* global) { return global->getAlign().value_or(layout.getABITypeAlign(global->getValueType())); };
    llvm::stable_sort(locals, [&](const GlobalVariable* a, const GlobalVariable* b) {
        Align alignA = alignmentOf(a), alignB = alignmentOf(b);
        return alignA != alignB ? alignA > alignB : a->getName() < b->getName();
    });
    SmallVector<Type*> fields;
    SmallVector<Constant*> initializers;
    Align blockAlignment(1);
    for (GlobalVariable* local : locals) {
        fields.push_back(local->getValueType());
        initializers.push_back(local->hasInitializer() ? local->getInitializer() : Constant::getNullValue(local->getValueType()));
        blockAlignment = std::max(blockAlignment, alignmentOf(local));
    }
    auto* block = StructType::create(context, fields, "capsule.fiber_local");
    Constant* image = ConstantStruct::get(block, initializers);
    auto* table = ArrayType::get(block, fibers);
    SmallVector<Constant*> copies(fibers, image);
    auto* storage = new GlobalVariable(module, table, false, GlobalValue::InternalLinkage, ConstantArray::get(table, copies), "__bpf_capsule_fiber_locals");
    storage->setAlignment(blockAlignment);
    // The block table is Capsule memory: pointers into it are ordinary data
    // that survive suspension. The native reset hook below reaches it through
    // routed accesses, which the domain check must not mistake for accidental
    // sharing.
    storage->setMetadata(bpf::md::CapsuleOwned, MDNode::get(context, {}));
    auto* initial = new GlobalVariable(module, block, true, GlobalValue::InternalLinkage, image, "__bpf_capsule_fiber_local_image");
    initial->setAlignment(blockAlignment);

    // Every use becomes an address inside the current fiber's block. The
    // index is invariant within one activation, so each function computes its
    // block once, in the entry block, where it dominates every use.
    auto* i32 = Type::getInt32Ty(context);
    auto* i64 = Type::getInt64Ty(context);
    FunctionCallee fiberIndex = module.getOrInsertFunction(bpf::sym::CurrentFiberIndex, FunctionType::get(i32, false));
    SmallVector<Constant*> constants(locals.begin(), locals.end());
    convertUsersOfConstantsToInstructions(constants);
    DenseMap<Function*, Instruction*> blocks;
    DenseMap<std::pair<Function*, unsigned>, Value*> slots;
    unsigned rewritten = 0;
    for (auto [field, local] : enumerate(locals)) {
        for (Use& use : make_early_inc_range(local->uses())) {
            auto* user = dyn_cast<Instruction>(use.getUser());
            if (!user) {
                report_fatal_error(Twine("bpf-fiber-local: the address of thread-local variable ") + local->getName() + " is used outside a function");
            }
            Function* function = user->getFunction();
            Instruction*& blockPointer = blocks[function];
            if (!blockPointer) {
                IRBuilder<> builder(&function->getEntryBlock(), function->getEntryBlock().getFirstNonPHIOrDbgOrAlloca());
                Value* fiber = builder.CreateCall(fiberIndex, {}, "fiber");
                blockPointer = cast<Instruction>(builder.CreateInBoundsGEP(table, storage, {ConstantInt::get(i64, 0), fiber}, "fiber.locals"));
            }
            Value*& slot = slots[{function, static_cast<unsigned>(field)}];
            if (!slot) {
                IRBuilder<> builder(blockPointer->getNextNode());
                slot = builder.CreateStructGEP(block, blockPointer, field, local->getName());
            }
            use.set(slot);
            ++rewritten;
        }
        local->eraseFromParent();
    }

    // capsule_reset restores the cancelled fiber's block from the image. The
    // hook is native runtime code, so it copies with its own bounded loops
    // rather than a memcpy that could be outlined to the C library's, which
    // managed code shares.
    if (Function* reset = module.getFunction(bpf::sym::FiberLocalReset)) {
        reset->deleteBody();
        BasicBlock* entry = BasicBlock::Create(context, "entry", reset);
        IRBuilder<> builder(entry);
        Value* fiber = reset->getArg(0);
        Value* slot = builder.CreateInBoundsGEP(table, storage, {ConstantInt::get(i64, 0), fiber}, "fiber.locals");
        uint64_t size = layout.getTypeAllocSize(block);
        uint64_t offset = 0;
        auto copyRange = [&](Type* element, uint64_t step, uint64_t end, StringRef name) {
            if (offset >= end) {
                return;
            }
            BasicBlock* head = builder.GetInsertBlock();
            BasicBlock* body = BasicBlock::Create(context, name, reset);
            BasicBlock* after = BasicBlock::Create(context, name + ".done", reset);
            builder.CreateBr(body);
            builder.SetInsertPoint(body);
            PHINode* index = builder.CreatePHI(i64, 2, name + ".index");
            index->addIncoming(ConstantInt::get(i64, offset), head);
            Align alignment = std::min(blockAlignment, Align(step));
            Value* value = builder.CreateAlignedLoad(element, builder.CreatePtrAdd(initial, index), alignment);
            builder.CreateAlignedStore(value, builder.CreatePtrAdd(slot, index), alignment);
            Value* next = builder.CreateAdd(index, ConstantInt::get(i64, step));
            index->addIncoming(next, body);
            builder.CreateCondBr(builder.CreateICmpULT(next, ConstantInt::get(i64, end)), body, after);
            builder.SetInsertPoint(after);
            offset = end;
        };
        if (blockAlignment >= Align(8)) {
            copyRange(i64, 8, size - size % 8, "reset.words");
        }
        copyRange(Type::getInt8Ty(context), 1, size, "reset.bytes");
        builder.CreateRetVoid();
    }

    bpf::stats() << "bpf-fiber-local: " << locals.size() << " thread-local variables, " << rewritten << " uses, " << fibers << " fibers, "
                 << layout.getTypeAllocSize(block) << " bytes per fiber\n";
    return PreservedAnalyses::none();
}

bool RegisterFiberLocalPass(StringRef name, ModulePassManager& manager) {
    if (name != "bpf-fiber-local") {
        return false;
    }
    manager.addPass(FiberLocalPass());
    return true;
}
