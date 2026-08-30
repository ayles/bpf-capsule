// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "common.h"
#include "runtime_symbols.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/MathExtras.h>

using namespace llvm;

static cl::opt<bool> CapsuleVerbose("bpf-capsule-verbose", cl::desc("Print per-pass transformation statistics to stderr"), cl::init(false));

bool bpf::verbose() {
    return CapsuleVerbose;
}

raw_ostream& bpf::stats() {
    return verbose() ? errs() : nulls();
}

bool bpf::IsFiberControlLayout(const StructType* control) {
    return control && control->getNumElements() == BPF_CAPSULE_FIBER_CONTROL_FIELD_COUNT &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_STATUS)->isIntegerTy(32) &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_CODE)->isIntegerTy(32) &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_GENERATION)->isIntegerTy(64) &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_SP)->isIntegerTy(64) && control->getElementType(BPF_CAPSULE_FIBER_CONTROL_FP)->isIntegerTy(64) &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_PC)->isIntegerTy(32) &&
        control->getElementType(BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE)->isIntegerTy(32);
}

Value* bpf::BuildVerifierOpaqueIdentity(IRBuilderBase& builder, Value* value, StringRef name) {
    auto* type = FunctionType::get(value->getType(), {value->getType()}, false);
    auto* barrier = InlineAsm::get(type, "", "=r,0", /*hasSideEffects=*/true);
    return builder.CreateCall(barrier, {value}, name);
}

Value* bpf::OutcomePointer(IRBuilderBase& builder, Function& owner) {
    Module& module = *owner.getParent();
    LLVMContext& ctx = module.getContext();
    GlobalVariable* controls = module.getGlobalVariable(bpf::sym::FiberControls, true);
    auto* array = controls ? dyn_cast<ArrayType>(controls->getValueType()) : nullptr;
    auto* control = array ? dyn_cast<StructType>(array->getElementType()) : nullptr;
    if (!control || control->getNumElements() < 2 || !control->getElementType(0)->isIntegerTy(32) || !control->getElementType(1)->isIntegerTy(32)) {
        report_fatal_error("bpf-capsule: runtime is missing the fiber {status, code} pair");
    }
    if (MDNode* physical = owner.getMetadata(bpf::md::AllocationUnit)) {
        auto* index = physical->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(physical->getOperand(0)) : nullptr;
        if (!index || index->getZExtValue() >= owner.arg_size()) {
            report_fatal_error("bpf-capsule: malformed physical fiber metadata");
        }
        Value* fiber = owner.getArg(index->getZExtValue());
        uint64_t count = array->getNumElements();
        fiber = builder.CreateZExtOrTrunc(fiber, Type::getInt32Ty(ctx), "capsule.fiber");
        if (isPowerOf2_64(count)) {
            fiber = builder.CreateAnd(fiber, ConstantInt::get(Type::getInt32Ty(ctx), count - 1), "capsule.fiber.index");
        } else {
            fiber = builder.CreateURem(fiber, ConstantInt::get(Type::getInt32Ty(ctx), count), "capsule.fiber.index");
        }
        Value* state = builder.CreateInBoundsGEP(array, controls, {ConstantInt::get(Type::getInt32Ty(ctx), 0), fiber});
        return builder.CreateStructGEP(control, state, 0, "capsule.outcome.ptr");
    }
    if (IsCapsuleFunction(owner)) {
        FunctionCallee accessor = module.getOrInsertFunction(bpf::sym::OutcomePointer, FunctionType::get(PointerType::get(ctx, 0), false));
        return builder.CreateCall(accessor, {}, "capsule.outcome.ptr");
    }
    report_fatal_error(Twine("bpf-capsule: native function ") + owner.getName() + " has no current fiber for an exit");
}

Value* bpf::BuildOutcomeValue(IRBuilderBase& builder, Value* code) {
    Type* i64 = Type::getInt64Ty(builder.getContext());
    Value* wide = builder.CreateSExtOrTrunc(code, i64);
    return builder.CreateOr(builder.CreateShl(wide, 32), ConstantInt::get(i64, CAPSULE_EXITED));
}

void bpf::TerminateWithOutcome(Instruction& point, Value* word) {
    Function& function = *point.getFunction();
    BasicBlock& block = *point.getParent();

    IRBuilder<> builder(&point);
    StoreInst* store = builder.CreateStore(word, OutcomePointer(builder, function));
    store->setMetadata(md::OutcomeStore, MDNode::get(function.getContext(), {}));

    SmallPtrSet<BasicBlock*, 4> oldSuccessors;
    oldSuccessors.insert_range(successors(&block));
    for (BasicBlock* successor : oldSuccessors) {
        successor->removePredecessor(&block);
    }

    for (Instruction* instruction = &point; instruction;) {
        Instruction* next = instruction->getNextNode();
        if (!instruction->use_empty()) {
            instruction->replaceAllUsesWith(PoisonValue::get(instruction->getType()));
        }
        instruction->eraseFromParent();
        instruction = next;
    }

    function.removeFnAttr(Attribute::NoReturn);
    IRBuilder<> returnBuilder(&block);
    if (function.getReturnType()->isVoidTy()) {
        returnBuilder.CreateRetVoid();
    } else {
        returnBuilder.CreateRet(Constant::getNullValue(function.getReturnType()));
    }
}

SmallVector<CallInst*, 4> bpf::FirstTrapCalls(Function& function) {
    SmallVector<CallInst*, 4> traps;
    for (BasicBlock& block : function) {
        for (Instruction& instruction : block) {
            auto* call = dyn_cast<CallInst>(&instruction);
            if (call && (call->getIntrinsicID() == Intrinsic::trap || call->getIntrinsicID() == Intrinsic::debugtrap)) {
                traps.push_back(call);
                break;
            }
        }
    }
    return traps;
}

bool bpf::IsVerifierCall(const CallBase& call) {
    if (Function* callee = call.getCalledFunction()) {
        return callee->isDeclaration() && callee->getSection() == ".ksyms";
    }
    // Clang represents numbered helpers as calls through a constant inttoptr.
    // Check that exact shape: aliases and constant casts of ordinary functions
    // must not accidentally become verifier calls.
    auto* expression = dyn_cast<ConstantExpr>(call.getCalledOperand());
    return expression && expression->getOpcode() == Instruction::IntToPtr && isa<ConstantInt>(expression->getOperand(0));
}

bool bpf::IsVerifierPointerSource(const CallBase& call) {
    return call.getType()->isPointerTy() && IsVerifierCall(call);
}

void bpf::FindVerifierNativeValues(Function& func, SmallPtrSetImpl<Value*>& native) {
    // Only borrowed context objects have fields whose loads may themselves
    // acquire verifier pointer types (XDP data/data_end are the important
    // example). A map-value or ring-buffer pointer is native, but bytes loaded
    // from the object it names are ordinary program data.
    SmallPtrSet<Value*, 16> pointerProducingMemory;
    for (Argument& arg : func.args()) {
        bool borrowed = arg.hasAttribute(bpf::md::Borrowed) || (IsNativeFunction(func) && arg.getType()->isPointerTy());
        if (borrowed || arg.hasAttribute(bpf::md::StackBacking) || arg.hasAttribute(bpf::md::Control)) {
            native.insert(&arg);
        }
        if (borrowed) {
            pointerProducingMemory.insert(&arg);
        }
    }
    // Explicitly sectioned globals remain kernel map-value pointers in every
    // domain.  Direct accesses can be relocated in each physical region, but
    // a derived pointer must never be serialized as a Capsule address across
    // a managed call or loop boundary.  Partition-owned native globals have
    // the same rule even when their source did not spell a section.
    for (GlobalVariable& global : func.getParent()->globals()) {
        if (global.hasSection() || (IsNativeGlobal(global) && !IsCapsuleGlobal(global))) {
            native.insert(&global);
        }
    }
    for (Instruction& inst : instructions(func)) {
        if (auto* call = dyn_cast<CallBase>(&inst); call && IsVerifierPointerSource(*call)) {
            native.insert(call);
        }
    }

    auto isOrDerivesFrom = [](const SmallPtrSetImpl<Value*>& values, Value* value) {
        SmallPtrSet<Value*, 8> visiting;
        auto derived = [&](auto&& self, Value* current) -> bool {
            if (values.contains(current)) {
                return true;
            }
            auto* expression = dyn_cast<ConstantExpr>(current);
            if (!expression || !visiting.insert(current).second) {
                return false;
            }
            bool result = llvm::any_of(expression->operands(), [&](Value* operand) { return self(self, operand); });
            visiting.erase(current);
            return result;
        };
        return derived(derived, value);
    };
    auto isZero = [](Value* value) {
        if (isa<ConstantPointerNull>(value)) {
            return true;
        }
        auto* integer = dyn_cast<ConstantInt>(value);
        return integer && integer->isZero();
    };
    // First close the set of addresses that still identify the borrowed
    // context object. A load through one of these addresses is only a
    // *candidate*: xdp_md contains both data/data_end pointer handles and
    // ordinary fields such as ingress_ifindex.
    bool changed = true;
    while (changed) {
        changed = false;
        for (Instruction& inst : instructions(func)) {
            bool derived = false;
            if (auto* phi = dyn_cast<PHINode>(&inst)) {
                derived = phi->getNumIncomingValues() != 0 && llvm::all_of(phi->incoming_values(), [&](Value* incoming) {
                    return isOrDerivesFrom(pointerProducingMemory, incoming) || isZero(incoming);
                });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                derived = (isOrDerivesFrom(pointerProducingMemory, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (isOrDerivesFrom(pointerProducingMemory, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<GetElementPtrInst>(&inst) || isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                derived = llvm::any_of(inst.operands(), [&](Value* operand) { return isOrDerivesFrom(pointerProducingMemory, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool leftMemory = isOrDerivesFrom(pointerProducingMemory, binary->getOperand(0));
                bool rightMemory = isOrDerivesFrom(pointerProducingMemory, binary->getOperand(1));
                derived =
                    binary->getOpcode() == Instruction::Add ? leftMemory != rightMemory : binary->getOpcode() == Instruction::Sub && leftMemory && !rightMemory;
            }
            if (derived) {
                changed |= pointerProducingMemory.insert(&inst).second;
            }
        }
    }

    // Follow scalar values loaded from the context without classifying them
    // yet. LLVM represents XDP data/data_end as i32 load -> zext -> inttoptr;
    // only a chain which reaches inttoptr carries verifier pointer provenance.
    SmallPtrSet<Value*, 32> contextCandidates;
    changed = true;
    while (changed) {
        changed = false;
        for (Instruction& inst : instructions(func)) {
            bool candidate = false;
            if (auto* load = dyn_cast<LoadInst>(&inst)) {
                candidate = isOrDerivesFrom(pointerProducingMemory, load->getPointerOperand());
            } else if (auto* phi = dyn_cast<PHINode>(&inst)) {
                candidate = phi->getNumIncomingValues() != 0 &&
                    llvm::all_of(phi->incoming_values(), [&](Value* incoming) { return isOrDerivesFrom(contextCandidates, incoming) || isZero(incoming); });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                candidate = (isOrDerivesFrom(contextCandidates, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (isOrDerivesFrom(contextCandidates, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                candidate = llvm::any_of(inst.operands(), [&](Value* operand) { return isOrDerivesFrom(contextCandidates, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool left = isOrDerivesFrom(contextCandidates, binary->getOperand(0));
                bool right = isOrDerivesFrom(contextCandidates, binary->getOperand(1));
                candidate = binary->getOpcode() == Instruction::Add ? left != right : binary->getOpcode() == Instruction::Sub && left && !right;
            }
            if (candidate) {
                changed |= contextCandidates.insert(&inst).second;
            }
        }
    }

    auto promoteCandidate = [&](auto&& self, Value* value) -> void {
        if (!contextCandidates.contains(value) || !native.insert(value).second) {
            return;
        }
        if (auto* instruction = dyn_cast<Instruction>(value)) {
            for (Value* operand : instruction->operands()) {
                self(self, operand);
            }
        }
    };
    for (Instruction& inst : instructions(func)) {
        auto* cast = dyn_cast<IntToPtrInst>(&inst);
        if (!cast || !contextCandidates.contains(cast->getOperand(0))) {
            continue;
        }
        promoteCandidate(promoteCandidate, cast->getOperand(0));
        native.insert(cast);
    }

    // Now close actual verifier provenance. Pointer subtraction produces an
    // ordinary scalar distance; all other pointer arithmetic remains native.
    changed = true;
    while (changed) {
        changed = false;
        for (Instruction& inst : instructions(func)) {
            bool derived = false;
            if (auto* load = dyn_cast<LoadInst>(&inst)) {
                derived = load->getType()->isPointerTy() && isOrDerivesFrom(pointerProducingMemory, load->getPointerOperand());
            } else if (auto* phi = dyn_cast<PHINode>(&inst)) {
                derived = phi->getNumIncomingValues() != 0 &&
                    llvm::all_of(phi->incoming_values(), [&](Value* incoming) { return isOrDerivesFrom(native, incoming) || isZero(incoming); });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                derived = (isOrDerivesFrom(native, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (isOrDerivesFrom(native, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<GetElementPtrInst>(&inst) || isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                derived = llvm::any_of(inst.operands(), [&](Value* operand) { return isOrDerivesFrom(native, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool left = isOrDerivesFrom(native, binary->getOperand(0));
                bool right = isOrDerivesFrom(native, binary->getOperand(1));
                derived = binary->getOpcode() == Instruction::Add ? left != right : binary->getOpcode() == Instruction::Sub && left && !right;
            } else if (auto* insert = dyn_cast<InsertValueInst>(&inst)) {
                derived = isOrDerivesFrom(native, insert->getAggregateOperand()) || isOrDerivesFrom(native, insert->getInsertedValueOperand());
            } else if (auto* extract = dyn_cast<ExtractValueInst>(&inst)) {
                derived = isOrDerivesFrom(native, extract->getAggregateOperand());
            }
            if (derived) {
                changed |= native.insert(&inst).second;
            }
        }
    }
}

DIType* BtfGetInt(DIBuilder& builder, size_t sizeInBits, bool isSigned) {
    const char* name;
    switch (sizeInBits) {
        case 1:
            name = "_Bool";
            break;
        case 8:
            name = "char";
            break;
        case 16:
            name = "short";
            break;
        case 32:
            name = "int";
            break;
        case 64:
            name = "long long";
            break;
        case 128:
            name = "__int128";
            break;
        default:
            report_fatal_error(Twine("BPF Capsule cannot describe a ") + Twine(sizeInBits) + "-bit integer in BTF");
    }

    return builder.createBasicType(std::string(isSigned || sizeInBits == 1 ? "" : "unsigned ") + name, sizeInBits,
        sizeInBits == 1 ? dwarf::DW_ATE_boolean
            : isSigned  ? dwarf::DW_ATE_signed
                        : dwarf::DW_ATE_unsigned);
}

DIType* BtfGetByteArrayPointer(DIBuilder& builder, uint64_t sizeBytes) {
    auto* byteType = builder.createBasicType("unsigned char", 8, dwarf::DW_ATE_unsigned_char);
    auto* subrange = builder.getOrCreateSubrange(0, sizeBytes);
    auto* arrayType = builder.createArrayType(sizeBytes * 8u, 8, byteType, builder.getOrCreateArray({subrange}));
    return builder.createPointerType(arrayType, 64);
}

void BtfFunctionAddDebugInfo(DIBuilder& debugBuilder, Function& func, ArrayRef<Metadata*> paramTypes) {
    auto debugCU = *func.getParent()->debug_compile_units_begin();
    auto debugType = debugBuilder.createSubroutineType(debugBuilder.getOrCreateTypeArray(paramTypes));
    auto debugFunction = debugBuilder.createFunction(debugCU, func.getName(), func.getName(), debugCU->getFile(), 0, debugType, 0, DINode::FlagZero,
        func.isDeclaration() ? DISubprogram::SPFlagZero : DISubprogram::SPFlagDefinition);
    SmallVector<Metadata*> retainedArguments;
    for (auto&& [i, arg] : enumerate(func.args())) {
        if (i + 1 >= debugFunction->getType()->getTypeArray().size()) {
            break;
        }
        auto* variable = debugBuilder.createParameterVariable(
            debugFunction, arg.getName(), i + 1, debugCU->getFile(), 0, debugFunction->getType()->getTypeArray()[i + 1], true);
        retainedArguments.push_back(variable);
    }
    debugFunction->replaceRetainedNodes(MDNode::get(func.getContext(), retainedArguments));
    func.setSubprogram(debugFunction);

    for (auto&& block : func) {
        for (auto&& inst : block) {
            inst.setDebugLoc(DILocation::get(func.getContext(), 0, 0, func.getSubprogram()));
        }
    }
}

void bpf::MaterializeFunctionClasses(llvm::Module& module) {
    using namespace llvm;
    constexpr StringLiteral flag{"bpf.capsule.classes"};
    if (module.getModuleFlag(flag)) {
        return;
    }
    module.addModuleFlag(Module::ModFlagBehavior::Error, flag, 1);
    auto* annotations = module.getGlobalVariable("llvm.global.annotations");
    if (!annotations || !annotations->hasInitializer()) {
        return;
    }
    auto* array = dyn_cast<ConstantArray>(annotations->getInitializer());
    if (!array) {
        return;
    }
    // Consume the capsule entries: the annotations array holds pointers to
    // the annotated functions, and leaving those references in place pins
    // always-inline glue bodies past DCE (the domain checker then reports
    // them reachable from both worlds).
    SmallVector<Constant*> kept;
    SmallVector<Function*> consumed;
    for (Use& operand : array->operands()) {
        auto* entry = dyn_cast<ConstantStruct>(operand.get());
        auto* function = entry && entry->getNumOperands() >= 2 ? dyn_cast<Function>(entry->getOperand(0)->stripPointerCasts()) : nullptr;
        StringRef text;
        if (function && getConstantStringInfo(entry->getOperand(1)->stripPointerCasts(), text) && text.starts_with("capsule.")) {
            function->addFnAttr(text);
            consumed.push_back(function);
            continue;
        }
        kept.push_back(cast<Constant>(operand.get()));
    }
    if (kept.size() == array->getNumOperands()) {
        return;
    }
    annotations->eraseFromParent();
    // The orphaned initializer constants still hold uses of the consumed
    // functions; purge them or hasAddressTaken keeps reporting the array.
    for (Function* function : consumed) {
        function->removeDeadConstantUsers();
    }
    if (!kept.empty()) {
        auto* keptType = ArrayType::get(kept.front()->getType(), kept.size());
        auto* rebuilt =
            new GlobalVariable(module, keptType, false, GlobalValue::AppendingLinkage, ConstantArray::get(keptType, kept), "llvm.global.annotations");
        rebuilt->setSection("llvm.metadata");
    }
}

bool bpf::HasFunctionClass(const llvm::Function& function, llvm::StringRef cls) {
    return function.hasFnAttribute(cls);
}
