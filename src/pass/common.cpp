// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "common.h"

#include <llvm/IR/InstIterator.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/MathExtras.h>

using namespace llvm;

static cl::opt<bool> CapsuleVerbose("bpf-capsule-verbose", cl::desc("Print per-pass transformation statistics to stderr"), cl::init(false));

raw_ostream& bpf::stats() {
    return CapsuleVerbose ? errs() : nulls();
}

Value* bpf::ExitWordPointer(IRBuilderBase& builder, Function& owner) {
    Module& module = *owner.getParent();
    LLVMContext& ctx = module.getContext();
    GlobalVariable* controls = module.getGlobalVariable("bpf_capsule_fibers", true);
    auto* array = controls ? dyn_cast<ArrayType>(controls->getValueType()) : nullptr;
    auto* control = array ? dyn_cast<StructType>(array->getElementType()) : nullptr;
    if (!control || control->getNumElements() < 1 || !control->getElementType(0)->isIntegerTy(64)) {
        report_fatal_error("bpf-capsule: runtime is missing fiber exit control");
    }
    Value* fiber = ConstantInt::get(Type::getInt32Ty(ctx), 0);
    if (MDNode* physical = owner.getMetadata("bpf.capsule.physical")) {
        auto* index = physical->getNumOperands() == 1 ? mdconst::dyn_extract<ConstantInt>(physical->getOperand(0)) : nullptr;
        if (!index || index->getZExtValue() >= owner.arg_size()) {
            report_fatal_error("bpf-capsule: malformed physical fiber metadata");
        }
        fiber = owner.getArg(index->getZExtValue());
        uint64_t count = array->getNumElements();
        fiber = builder.CreateZExtOrTrunc(fiber, Type::getInt32Ty(ctx), "capsule.fiber");
        if (isPowerOf2_64(count)) {
            fiber = builder.CreateAnd(fiber, ConstantInt::get(Type::getInt32Ty(ctx), count - 1), "capsule.fiber.index");
        } else {
            fiber = builder.CreateURem(fiber, ConstantInt::get(Type::getInt32Ty(ctx), count), "capsule.fiber.index");
        }
    } else if (IsCapsuleFunction(owner)) {
        FunctionCallee accessor = module.getOrInsertFunction("__bpf_capsule_exit_word_ptr", FunctionType::get(PointerType::get(ctx, 0), false));
        return builder.CreateCall(accessor, {}, "capsule.exit.word.ptr");
    }
    Value* state = builder.CreateInBoundsGEP(array, controls, {ConstantInt::get(Type::getInt32Ty(ctx), 0), fiber});
    return builder.CreateStructGEP(control, state, 0, "capsule.exit.word.ptr");
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
        bool borrowed = arg.hasAttribute("bpf.capsule.borrowed") || (IsNativeFunction(func) && arg.getType()->isPointerTy());
        if (borrowed || arg.hasAttribute("bpf.capsule.stack.backing") || arg.hasAttribute("bpf.capsule.control")) {
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

    auto contains = [](const SmallPtrSetImpl<Value*>& values, Value* value) {
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
                derived = phi->getNumIncomingValues() != 0 &&
                    llvm::all_of(phi->incoming_values(), [&](Value* incoming) { return contains(pointerProducingMemory, incoming) || isZero(incoming); });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                derived = (contains(pointerProducingMemory, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (contains(pointerProducingMemory, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<GetElementPtrInst>(&inst) || isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                derived = llvm::any_of(inst.operands(), [&](Value* operand) { return contains(pointerProducingMemory, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool leftMemory = contains(pointerProducingMemory, binary->getOperand(0));
                bool rightMemory = contains(pointerProducingMemory, binary->getOperand(1));
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
                candidate = contains(pointerProducingMemory, load->getPointerOperand());
            } else if (auto* phi = dyn_cast<PHINode>(&inst)) {
                candidate = phi->getNumIncomingValues() != 0 &&
                    llvm::all_of(phi->incoming_values(), [&](Value* incoming) { return contains(contextCandidates, incoming) || isZero(incoming); });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                candidate = (contains(contextCandidates, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (contains(contextCandidates, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                candidate = llvm::any_of(inst.operands(), [&](Value* operand) { return contains(contextCandidates, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool left = contains(contextCandidates, binary->getOperand(0));
                bool right = contains(contextCandidates, binary->getOperand(1));
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
                derived = load->getType()->isPointerTy() && contains(pointerProducingMemory, load->getPointerOperand());
            } else if (auto* phi = dyn_cast<PHINode>(&inst)) {
                derived = phi->getNumIncomingValues() != 0 &&
                    llvm::all_of(phi->incoming_values(), [&](Value* incoming) { return contains(native, incoming) || isZero(incoming); });
            } else if (auto* select = dyn_cast<SelectInst>(&inst)) {
                derived = (contains(native, select->getTrueValue()) || isZero(select->getTrueValue())) &&
                    (contains(native, select->getFalseValue()) || isZero(select->getFalseValue()));
            } else if (isa<GetElementPtrInst>(&inst) || isa<CastInst>(&inst) || isa<FreezeInst>(&inst)) {
                derived = llvm::any_of(inst.operands(), [&](Value* operand) { return contains(native, operand); });
            } else if (auto* binary = dyn_cast<BinaryOperator>(&inst)) {
                bool left = contains(native, binary->getOperand(0));
                bool right = contains(native, binary->getOperand(1));
                derived = binary->getOpcode() == Instruction::Add ? left != right : binary->getOpcode() == Instruction::Sub && left && !right;
            } else if (auto* insert = dyn_cast<InsertValueInst>(&inst)) {
                derived = contains(native, insert->getAggregateOperand()) || contains(native, insert->getInsertedValueOperand());
            } else if (auto* extract = dyn_cast<ExtractValueInst>(&inst)) {
                derived = contains(native, extract->getAggregateOperand());
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

    return builder.createBasicType(
        std::string(isSigned || sizeInBits == 1 ? "" : "unsigned ") + name, sizeInBits,
        sizeInBits == 1 ? dwarf::DW_ATE_boolean
            : isSigned  ? dwarf::DW_ATE_signed
                        : dwarf::DW_ATE_unsigned
    );
}

void BtfFunctionAddDebugInfo(DIBuilder& debugBuilder, Function& func, ArrayRef<Metadata*> paramTypes) {
    auto debugCU = *func.getParent()->debug_compile_units_begin();
    auto debugType = debugBuilder.createSubroutineType(debugBuilder.getOrCreateTypeArray(paramTypes));
    auto debugFunction = debugBuilder.createFunction(
        debugCU, func.getName(), func.getName(), debugCU->getFile(), 0, debugType, 0, DINode::FlagZero,
        func.isDeclaration() ? DISubprogram::SPFlagZero : DISubprogram::SPFlagDefinition
    );
    for (auto&& [i, arg] : enumerate(func.args())) {
        if (i + 1 >= debugFunction->getType()->getTypeArray().size()) {
            break;
        }
        debugBuilder.createParameterVariable(debugFunction, arg.getName(), i + 1, debugCU->getFile(), 0, debugFunction->getType()->getTypeArray()[i + 1], true);
    }
    func.setSubprogram(debugFunction);

    for (auto&& block : func) {
        for (auto&& inst : block) {
            inst.setDebugLoc(DILocation::get(func.getContext(), 0, 0, func.getSubprogram()));
        }
    }
}
