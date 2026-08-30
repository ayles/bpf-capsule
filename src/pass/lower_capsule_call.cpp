// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-lower-capsule-call: turn the C-facing variadic __bpf_capsule_call
// marker into an ordinary, typed direct call of the Capsule root plus the
// inline status read. The typed call carries the "bpf.capsule.call" operand
// bundle that bpf-capsule-domains and bpf-stackify treat as the sole
// native -> Capsule boundary. An operand bundle is deliberately used instead
// of metadata: LLVM metadata may not contain a function-local SSA value,
// while the selected fiber is necessarily dynamic.
#include "lower_capsule_call.h"

#include "common.h"
#include "runtime_symbols.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

using namespace llvm;

namespace {

Function* FunctionOperand(Value* value) {
    return dyn_cast<Function>(value->stripPointerCasts());
}

Value* ConvertArgument(IRBuilder<>& builder, Value* value, Type* type, Function& root, CallBase& boundary) {
    if (value->getType() == type) {
        return value;
    }
    if (value->getType()->isIntegerTy() && type->isIntegerTy()) {
        return builder.CreateIntCast(value, type, /*isSigned=*/false);
    }
    if (value->getType()->isPointerTy() && type->isPointerTy()) {
        return builder.CreatePointerCast(value, type);
    }
    boundary.getContext().emitError(&boundary, Twine("bpf-lower-capsule-call: capsule_call argument type does not match ") + root.getName());
    return nullptr;
}

// A native entry cannot lend its BPF stack to a suspendable Capsule root. For
// an aggregate-returning root, adapt the target to a natural LLVM return here:
// its ordinary internal sret calls are safe once Stackify turns their pointers
// into unified-memory addresses, but the outer result must cross the domain
// boundary as a value.
Function* AdaptSretRoot(Module& module, Function& root) {
    if (!root.arg_size() || !root.getArg(0)->hasStructRetAttr()) {
        return &root;
    }
    Type* resultType = root.getParamStructRetType(0);
    SmallVector<Type*> parameters;
    SmallVector<AttributeSet> parameterAttributes;
    for (unsigned index = 1; index < root.arg_size(); ++index) {
        parameters.push_back(root.getArg(index)->getType());
        parameterAttributes.push_back(root.getAttributes().getParamAttrs(index));
    }
    auto* adapter =
        Function::Create(FunctionType::get(resultType, parameters, false), GlobalValue::InternalLinkage, root.getName() + ".capsule.result", module);
    adapter->setCallingConv(root.getCallingConv());
    adapter->setSubprogram(root.getSubprogram());
    root.setSubprogram(nullptr);
    adapter->setAttributes(AttributeList::get(module.getContext(), root.getAttributes().getFnAttrs(), AttributeSet(), parameterAttributes));

    auto* entry = BasicBlock::Create(module.getContext(), "entry", adapter);
    IRBuilder<> builder(entry);
    auto* result = builder.CreateAlloca(resultType, nullptr, "result");
    if (auto alignment = root.getParamAlign(0)) {
        result->setAlignment(*alignment);
    }
    SmallVector<Value*> arguments{result};
    for (Argument& argument : adapter->args()) {
        arguments.push_back(&argument);
    }
    CallInst* call = builder.CreateCall(root.getFunctionType(), &root, arguments);
    call->setCallingConv(root.getCallingConv());
    call->setAttributes(root.getAttributes());
    builder.CreateRet(builder.CreateLoad(resultType, result));
    return adapter;
}

struct LowerCapsuleCallPass : public PassInfoMixin<LowerCapsuleCallPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        Function* marker = module.getFunction(bpf::sym::CallMarker);
        if (!marker) {
            return PreservedAnalyses::all();
        }

        SmallVector<CallBase*> calls;
        for (User* user : marker->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (!call || call->getCalledOperand()->stripPointerCasts() != marker) {
                module.getContext().emitError(Twine("bpf-lower-capsule-call: address of ") + bpf::sym::CallMarker + " escapes");
                return PreservedAnalyses::all();
            }
            calls.push_back(call);
        }

        LLVMContext& ctx = module.getContext();
        Type* i32 = Type::getInt32Ty(ctx);
        GlobalVariable* controls = module.getGlobalVariable(bpf::sym::FiberControls, true);
        auto* controlsType = controls ? dyn_cast<ArrayType>(controls->getValueType()) : nullptr;
        auto* controlType = controlsType ? dyn_cast<StructType>(controlsType->getElementType()) : nullptr;
        if (!bpf::IsFiberControlLayout(controlType)) {
            report_fatal_error(Twine("bpf-lower-capsule-call: the runtime must define ") + bpf::sym::FiberControls);
        }

        DenseMap<Function*, Function*> adaptedRoots;
        for (CallBase* markerCall : calls) {
            if (markerCall->arg_size() < 5) {
                ctx.emitError(markerCall,
                    "bpf-lower-capsule-call: capsule_call needs a fiber, "
                    "output description, and function");
                return PreservedAnalyses::all();
            }
            Value* fiber = markerCall->getArgOperand(0);
            if (!fiber->getType()->isIntegerTy()) {
                ctx.emitError(markerCall, "bpf-lower-capsule-call: capsule fiber must be an integer");
                return PreservedAnalyses::all();
            }
            Value* output = markerCall->getArgOperand(1);
            auto* outputSize = dyn_cast<ConstantInt>(markerCall->getArgOperand(2));
            auto* outputAlignment = dyn_cast<ConstantInt>(markerCall->getArgOperand(3));
            if (!output->getType()->isPointerTy() || !outputSize || !outputAlignment || !isPowerOf2_64(outputAlignment->getZExtValue())) {
                ctx.emitError(markerCall,
                    "bpf-lower-capsule-call: capsule return storage must have "
                    "a constant size and alignment");
                return PreservedAnalyses::all();
            }
            Function* root = FunctionOperand(markerCall->getArgOperand(4));
            if (!root || root->isDeclaration()) {
                ctx.emitError(markerCall,
                    "bpf-lower-capsule-call: capsule_call target must be a "
                    "defined, statically visible function");
                return PreservedAnalyses::all();
            }
            auto [adapted, inserted] = adaptedRoots.try_emplace(root, nullptr);
            if (inserted) {
                adapted->second = AdaptSretRoot(module, *root);
            }
            root = adapted->second;
            Type* returnType = root->getReturnType();
            uint64_t returnSize = returnType->isVoidTy() ? 0 : module.getDataLayout().getTypeAllocSize(returnType).getFixedValue();
            uint64_t returnAlignment = returnType->isVoidTy() ? 1 : module.getDataLayout().getABITypeAlign(returnType).value();
            if (outputSize->getZExtValue() != returnSize || outputAlignment->getZExtValue() != returnAlignment) {
                ctx.emitError(markerCall, Twine("bpf-lower-capsule-call: capsule return storage does not match ") + root->getName());
                return PreservedAnalyses::all();
            }
            if (returnType->isVoidTy() != isa<ConstantPointerNull>(output)) {
                ctx.emitError(markerCall,
                    Twine("bpf-lower-capsule-call: capsule root ") + root->getName() +
                        (returnType->isVoidTy() ? " is void; use capsule_call_void"
                                                : " returns a value; use capsule_call with output "
                                                  "storage"));
                return PreservedAnalyses::all();
            }
            if (root->isVarArg() || markerCall->arg_size() - 5 != root->arg_size()) {
                ctx.emitError(markerCall,
                    Twine("bpf-lower-capsule-call: capsule_call argument count "
                          "does not match ") +
                        root->getName());
                return PreservedAnalyses::all();
            }

            IRBuilder<> builder(markerCall);
            SmallVector<Value*> arguments;
            for (unsigned index = 0; index < root->arg_size(); ++index) {
                Type* parameter = root->getFunctionType()->getParamType(index);
                if (parameter->isPointerTy()) {
                    // A pointer crossing capsule_call is an entry-owned
                    // verifier capability, not guest memory. Stackify keeps
                    // it native and rematerializes it after each suspension.
                    root->addParamAttr(index, Attribute::get(ctx, bpf::md::Borrowed));
                }
                Value* argument = ConvertArgument(builder, markerCall->getArgOperand(index + 5), parameter, *root, *markerCall);
                if (!argument) {
                    return PreservedAnalyses::all();
                }
                arguments.push_back(argument);
            }
            Value* fiber32 = builder.CreateZExtOrTrunc(fiber, i32, "capsule.fiber");
            SmallVector<Value*, 1> boundaryInputs{fiber32};
            OperandBundleDef boundary(bpf::md::CallBundle.str(), boundaryInputs);
            CallInst* call = builder.CreateCall(root, arguments, {boundary});
            call->setCallingConv(root->getCallingConv());
            call->setDebugLoc(markerCall->getDebugLoc());

            // Status is observed after Stackify has replaced the direct call
            // with a frame push and one bounded drive.  An abort deliberately
            // leaves the stack dirty until capsule_reset(), just like a time
            // limit.
            Value* control = builder.CreateInBoundsGEP(controlsType, controls, {ConstantInt::get(i32, 0), fiber32}, "capsule.control");
            Value* terminal = builder.CreateStructGEP(controlType, control, BPF_CAPSULE_FIBER_CONTROL_STATUS);
            Value* cursor = builder.CreateStructGEP(controlType, control, BPF_CAPSULE_FIBER_CONTROL_PC);
            // The terminal status field; the signed code beside it is read
            // by the runtime, not here.
            Value* tag = builder.CreateLoad(i32, terminal);
            Value* exited = builder.CreateICmpEQ(tag, ConstantInt::get(i32, CAPSULE_EXITED));
            Value* yielded = builder.CreateICmpEQ(tag, ConstantInt::get(i32, CAPSULE_YIELD));
            Value* pending = builder.CreateICmpNE(builder.CreateLoad(i32, cursor), ConstantInt::get(i32, 0));
            Value* status = builder.CreateSelect(exited, ConstantInt::get(i32, CAPSULE_EXITED),
                builder.CreateSelect(yielded, ConstantInt::get(i32, CAPSULE_YIELD),
                    builder.CreateSelect(pending, ConstantInt::get(i32, CAPSULE_PENDING), ConstantInt::get(i32, CAPSULE_OK))));
            if (!returnType->isVoidTy()) {
                Value* completed = builder.CreateICmpEQ(status, ConstantInt::get(i32, CAPSULE_OK));
                Instruction* thenTerminator = SplitBlockAndInsertIfThen(completed, markerCall, false);
                IRBuilder<> completedBuilder(thenTerminator);
                completedBuilder.CreateAlignedStore(call, output, Align(returnAlignment));
            }
            markerCall->replaceAllUsesWith(status);
            markerCall->eraseFromParent();
        }

        if (marker->use_empty()) {
            marker->eraseFromParent();
        }
        if (calls.empty()) {
            return PreservedAnalyses::all();
        }
        bpf::stats() << "bpf-lower-capsule-call: " << calls.size() << " capsule_call boundaries\n";
        if (verifyModule(module, &errs())) {
            module.getContext().emitError("bpf-lower-capsule-call produced an invalid module");
        }
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterLowerCapsuleCallPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-lower-capsule-call") {
        return false;
    }
    manager.addPass(LowerCapsuleCallPass());
    return true;
}
