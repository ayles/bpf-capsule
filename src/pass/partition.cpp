// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "partition.h"

#include "common.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

using namespace llvm;

namespace {

constexpr StringLiteral CallMarker = "__bpf_capsule_call";
constexpr StringLiteral CallMetadata = "bpf.capsule.call";
constexpr StringLiteral SuspendBarrier = "__bpf_capsule_suspend_barrier";
constexpr StringLiteral ExitMarker = "__bpf_capsule_exit";

bool IsEntryProgram(const Function& func) {
    return func.hasSection() && func.getSection() != ".ksyms";
}

bool IsCompilerDriver(const Function& func) {
    StringRef name = func.getName();
    return name == "__bpf_capsule_trampoline" || name == "__bpf_capsule_trampoline_l1" || name == "__bpf_capsule_trampoline_step" ||
        name == "__bpf_capsule_trampoline_ctx" || name == "__bpf_capsule_trampoline_ctx_l1" || name == "__bpf_capsule_trampoline_ctx_step";
}

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
    boundary.getContext().emitError(&boundary, Twine("bpf-partition: capsule_call argument type does not match ") + root.getName());
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

// Turn the C-facing variadic marker into an ordinary, typed direct call.
// Stackify recognizes the operand bundle on that direct call as the sole
// native -> Capsule boundary. An operand bundle is deliberately used instead
// of metadata: LLVM metadata may not contain a function-local SSA value, while
// the selected fiber is necessarily dynamic.
struct LowerCallResult {
    bool Changed = false;
    bool Error = false;
};

LowerCallResult LowerCallMarkers(Module& module) {
    Function* marker = module.getFunction(CallMarker);
    if (!marker) {
        return {};
    }

    SmallVector<CallBase*> calls;
    for (User* user : marker->users()) {
        auto* call = dyn_cast<CallBase>(user);
        if (!call || call->getCalledOperand()->stripPointerCasts() != marker) {
            module.getContext().emitError("bpf-partition: address of __bpf_capsule_call escapes");
            return {.Error = true};
        }
        calls.push_back(call);
    }

    LLVMContext& ctx = module.getContext();
    Type* i32 = Type::getInt32Ty(ctx);
    GlobalVariable* controls = module.getGlobalVariable("bpf_capsule_fibers", true);
    auto* controlsType = controls ? dyn_cast<ArrayType>(controls->getValueType()) : nullptr;
    auto* controlType = controlsType ? dyn_cast<StructType>(controlsType->getElementType()) : nullptr;
    if (!controlType || controlType->getNumElements() != BPF_CAPSULE_FIBER_CONTROL_FIELD_COUNT ||
        !controlType->getElementType(BPF_CAPSULE_FIBER_CONTROL_EXIT_WORD)->isIntegerTy(64) ||
        !controlType->getElementType(BPF_CAPSULE_FIBER_CONTROL_STACK_CURSOR)->isIntegerTy(64) ||
        !controlType->getElementType(BPF_CAPSULE_FIBER_CONTROL_RETURN_SIZE)->isIntegerTy(64) ||
        !controlType->getElementType(BPF_CAPSULE_FIBER_CONTROL_GENERATION)->isIntegerTy(64)) {
        report_fatal_error("bpf-partition: the runtime must define bpf_capsule_fibers");
    }

    DenseMap<Function*, Function*> adaptedRoots;
    for (CallBase* markerCall : calls) {
        if (markerCall->arg_size() < 5) {
            ctx.emitError(
                markerCall,
                "bpf-partition: capsule_call needs a fiber, output "
                "description, and function"
            );
            return {.Error = true};
        }
        Value* fiber = markerCall->getArgOperand(0);
        if (!fiber->getType()->isIntegerTy()) {
            ctx.emitError(markerCall, "bpf-partition: capsule fiber must be an integer");
            return {.Error = true};
        }
        Value* output = markerCall->getArgOperand(1);
        auto* outputSize = dyn_cast<ConstantInt>(markerCall->getArgOperand(2));
        auto* outputAlignment = dyn_cast<ConstantInt>(markerCall->getArgOperand(3));
        if (!output->getType()->isPointerTy() || !outputSize || !outputAlignment || !isPowerOf2_64(outputAlignment->getZExtValue())) {
            ctx.emitError(
                markerCall,
                "bpf-partition: capsule return storage must have a constant "
                "size and alignment"
            );
            return {.Error = true};
        }
        Function* root = FunctionOperand(markerCall->getArgOperand(4));
        if (!root || root->isDeclaration()) {
            ctx.emitError(
                markerCall,
                "bpf-partition: capsule_call target must be a defined, "
                "statically visible function"
            );
            return {.Error = true};
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
            ctx.emitError(markerCall, Twine("bpf-partition: capsule return storage does not match ") + root->getName());
            return {.Error = true};
        }
        if (returnType->isVoidTy() != isa<ConstantPointerNull>(output)) {
            ctx.emitError(
                markerCall,
                Twine("bpf-partition: capsule root ") + root->getName() +
                    (returnType->isVoidTy() ? " is void; use capsule_call_void"
                                            : " returns a value; use capsule_call with output "
                                              "storage")
            );
            return {.Error = true};
        }
        if (root->isVarArg() || markerCall->arg_size() - 5 != root->arg_size()) {
            ctx.emitError(
                markerCall,
                Twine(
                    "bpf-partition: capsule_call argument count does not "
                    "match "
                ) + root->getName()
            );
            return {.Error = true};
        }

        IRBuilder<> builder(markerCall);
        SmallVector<Value*> arguments;
        for (unsigned index = 0; index < root->arg_size(); ++index) {
            Type* parameter = root->getFunctionType()->getParamType(index);
            if (parameter->isPointerTy()) {
                root->addParamAttr(index, Attribute::get(ctx, "bpf.capsule.borrowed"));
            }
            Value* argument = ConvertArgument(builder, markerCall->getArgOperand(index + 5), parameter, *root, *markerCall);
            if (!argument) {
                return {.Error = true};
            }
            arguments.push_back(argument);
        }
        Value* fiber32 = builder.CreateZExtOrTrunc(fiber, i32, "capsule.fiber");
        SmallVector<Value*, 1> boundaryInputs{fiber32};
        OperandBundleDef boundary(CallMetadata.str(), boundaryInputs);
        CallInst* call = builder.CreateCall(root, arguments, {boundary});
        call->setCallingConv(root->getCallingConv());
        call->setDebugLoc(markerCall->getDebugLoc());

        // Status is observed after Stackify has replaced the direct call with
        // a frame push and one bounded drive.  An abort deliberately leaves
        // the stack dirty until capsule_reset(), just like a time limit.
        Value* control = builder.CreateInBoundsGEP(controlsType, controls, {ConstantInt::get(i32, 0), fiber32}, "capsule.control");
        Value* exitWord = builder.CreateStructGEP(controlType, control, BPF_CAPSULE_FIBER_CONTROL_EXIT_WORD);
        Value* cursor = builder.CreateStructGEP(controlType, control, BPF_CAPSULE_FIBER_CONTROL_STACK_CURSOR);
        // The exit word's low half is the terminal tag; the signed code lives
        // in the high half and is read by the runtime, not here.
        Value* tag = builder.CreateTrunc(builder.CreateLoad(Type::getInt64Ty(ctx), exitWord), i32);
        Value* exited = builder.CreateICmpEQ(tag, ConstantInt::get(i32, CAPSULE_EXITED));
        Value* yielded = builder.CreateICmpEQ(tag, ConstantInt::get(i32, CAPSULE_YIELD));
        Value* pending = builder.CreateICmpNE(builder.CreateLoad(Type::getInt64Ty(ctx), cursor), ConstantInt::get(Type::getInt64Ty(ctx), 0));
        Value* status = builder.CreateSelect(
            exited, ConstantInt::get(i32, CAPSULE_EXITED),
            builder.CreateSelect(
                yielded, ConstantInt::get(i32, CAPSULE_YIELD),
                builder.CreateSelect(pending, ConstantInt::get(i32, CAPSULE_PENDING), ConstantInt::get(i32, CAPSULE_OK))
            )
        );
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
    return {.Changed = !calls.empty()};
}

bool IsBoundaryCall(const CallBase& call) {
    return call.getOperandBundle(CallMetadata).has_value();
}

void AddIndirectTargets(Module& module, CallBase& call, SmallVectorImpl<Function*>& work) {
    FunctionType* wanted = call.getFunctionType();
    for (Function& candidate : module) {
        if (candidate.isDeclaration() || IsEntryProgram(candidate) || IsCompilerDriver(candidate) || candidate.getFunctionType() != wanted) {
            continue;
        }
        // A direct-only function cannot be the value in this indirect call.
        if (!candidate.hasAddressTaken(
                nullptr, /*IgnoreCallbackUses=*/false,
                /*IgnoreAssumeLikeCalls=*/true,
                /*IgnoreLLVMUsed=*/true
            )) {
            continue;
        }
        work.push_back(&candidate);
    }
}

void AddReferencedFunctions(Value* value, SmallVectorImpl<Function*>& work, SmallPtrSetImpl<Value*>& seen) {
    if (!seen.insert(value).second) {
        return;
    }
    if (Function* function = FunctionOperand(value)) {
        if (!function->isDeclaration()) {
            work.push_back(function);
        }
        return;
    }
    // Function pointers commonly cross a library API as ordinary callback
    // arguments (QuickJS's job queue is one example), rather than appearing as
    // the callee of an indirect call in the same function. Follow functions
    // nested in constant tables/casts too so the Capsule closure owns the code
    // whose address it exports.
    if (auto* constant = dyn_cast<Constant>(value)) {
        for (Value* operand : constant->operands()) {
            AddReferencedFunctions(operand, work, seen);
        }
    }
}

bool Reach(Module& module, ArrayRef<Function*> roots, bool native, SmallPtrSetImpl<Function*>& reached) {
    SmallVector<Function*> work(roots.begin(), roots.end());
    while (!work.empty()) {
        Function* func = work.pop_back_val();
        if (!func || func->isDeclaration() || !reached.insert(func).second) {
            continue;
        }
        for (Instruction& inst : instructions(*func)) {
            auto* call = dyn_cast<CallBase>(&inst);
            if (call && IsBoundaryCall(*call)) {
                if (!native) {
                    func->getContext().emitError(
                        call,
                        Twine(
                            "bpf-partition: capsule_call inside Capsule "
                            "function "
                        ) + func->getName()
                    );
                    return false;
                }
                // The target and arguments are the other side of this explicit
                // domain edge; do not accidentally pull their function
                // constants back into the native closure.
                continue;
            }
            SmallPtrSet<Value*, 8> seenValues;
            for (Value* operand : inst.operands()) {
                AddReferencedFunctions(operand, work, seenValues);
            }
            if (!call || call->isInlineAsm() || isa<IntrinsicInst>(call)) {
                continue;
            }
            if (Function* callee = call->getCalledFunction()) {
                if (!callee->isDeclaration()) {
                    work.push_back(callee);
                }
            } else if (!isa<Constant>(call->getCalledOperand())) {
                // A numbered BPF helper is represented as a call through a
                // constant inttoptr. It is not an indirect C call and cannot
                // target any address-taken function in this module.
                AddIndirectTargets(module, *call, work);
            }
        }
    }
    return true;
}

void FindGlobalOwners(
    GlobalVariable& global, const SmallPtrSetImpl<Function*>& native, const SmallPtrSetImpl<Function*>& capsule, bool& usedNative, bool& usedCapsule
) {
    SmallVector<User*> work(global.user_begin(), global.user_end());
    SmallPtrSet<User*, 32> seen;
    while (!work.empty()) {
        User* user = work.pop_back_val();
        if (!seen.insert(user).second) {
            continue;
        }
        if (auto* inst = dyn_cast<Instruction>(user)) {
            Function* owner = inst->getFunction();
            usedNative |= native.contains(owner);
            usedCapsule |= capsule.contains(owner);
            continue;
        }
        for (User* next : user->users()) {
            work.push_back(next);
        }
    }
}

// LLVM is normally free to move a pointer-returning BPF helper across a pure
// call. A managed call is also a possible physical return to the trampoline,
// however, and verifier pointer provenance cannot survive that return. During
// the main optimization pipeline make every Capsule callee conservatively
// memory-affecting through an external marker. The second partition pass
// removes the zero-runtime-cost marker after code motion has finished.
void AddSuspendBarriers(Module& module, const SmallPtrSetImpl<Function*>& capsule) {
    Function* barrier = module.getFunction(SuspendBarrier);
    if (barrier && !barrier->isDeclaration()) {
        report_fatal_error(Twine("bpf-partition: reserved function is defined: ") + SuspendBarrier);
    }
    if (!barrier) {
        barrier = Function::Create(FunctionType::get(Type::getVoidTy(module.getContext()), false), GlobalValue::ExternalLinkage, SuspendBarrier, module);
    }
    for (Function* function : capsule) {
        if (function->empty()) {
            continue;
        }
        IRBuilder<> builder(&*function->getEntryBlock().getFirstInsertionPt());
        builder.CreateCall(barrier);
    }
}

bool RemoveSuspendBarriers(Module& module) {
    Function* barrier = module.getFunction(SuspendBarrier);
    if (!barrier) {
        return false;
    }
    SmallVector<CallBase*> calls;
    for (User* user : barrier->users()) {
        auto* call = dyn_cast<CallBase>(user);
        if (!call || call->getCalledOperand()->stripPointerCasts() != barrier) {
            report_fatal_error(Twine("bpf-partition: address of ") + SuspendBarrier + " escapes");
        }
        calls.push_back(call);
    }
    for (CallBase* call : calls) {
        call->eraseFromParent();
    }
    barrier->eraseFromParent();
    return true;
}

void ReturnFromManagedTermination(IRBuilder<>& builder, Function& function) {
    function.removeFnAttr(Attribute::NoReturn);
    if (function.getReturnType()->isVoidTy()) {
        builder.CreateRetVoid();
    } else {
        builder.CreateRet(Constant::getNullValue(function.getReturnType()));
    }
}

// A source language may require its panic/throw routine to have a `noreturn`
// type even though Capsule has to return to the native BPF entry in order to
// report the error. Lower the explicit marker before generic optimization and
// reopen only the direct noreturn wrapper chain above it. Unrelated LLVM
// `unreachable` promises retain their ordinary trap handling later.
LowerCallResult LowerExitMarkers(Module& module, const SmallPtrSetImpl<Function*>& capsule) {
    Function* marker = module.getFunction(ExitMarker);
    if (!marker) {
        return {};
    }
    if (!marker->isDeclaration() || marker->isVarArg() || marker->arg_size() != 1 || !marker->getReturnType()->isVoidTy() ||
        !marker->getArg(0)->getType()->isIntegerTy(32)) {
        module.getContext().emitError("bpf-partition: malformed __bpf_capsule_exit marker");
        return {.Error = true};
    }

    SmallVector<CallInst*> calls;
    for (User* user : marker->users()) {
        auto* call = dyn_cast<CallInst>(user);
        if (!call || call->getCalledOperand()->stripPointerCasts() != marker || !capsule.contains(call->getFunction())) {
            module.getContext().emitError("bpf-partition: __bpf_capsule_exit must be called directly from managed code");
            return {.Error = true};
        }
        calls.push_back(call);
    }

    SmallPtrSet<Function*, 16> terminating;
    for (CallInst* call : calls) {
        Function* owner = call->getFunction();
        bool ownerIsNoReturn = owner->hasFnAttribute(Attribute::NoReturn);
        BasicBlock* block = call->getParent();
        IRBuilder<> builder(call);
        // Encode ((int64_t)code << 32) | CAPSULE_EXITED — the sign-preserving
        // word layout documented in bpf_capsule_abi.h.
        Type* i64 = Type::getInt64Ty(module.getContext());
        Value* wide = builder.CreateSExt(call->getArgOperand(0), i64);
        Value* word = builder.CreateOr(builder.CreateShl(wide, 32), ConstantInt::get(i64, CAPSULE_EXITED));
        StoreInst* store = builder.CreateStore(word, bpf::ExitWordPointer(builder, *owner));
        store->setMetadata("bpf.capsule.exit.store", MDNode::get(module.getContext(), {}));

        // The public marker is normally wrapped by capsule_exit(), whose
        // call is followed by unreachable, but raw IR may legally branch to
        // successors. Removing that terminator must also remove this block's
        // incoming edge from each successor PHI.
        SmallVector<BasicBlock*> successorBlocks;
        for (BasicBlock* successor : successors(block)) {
            successorBlocks.push_back(successor);
        }
        for (BasicBlock* successor : successorBlocks) {
            successor->removePredecessor(block);
        }
        Instruction* instruction = call;
        while (Instruction* next = instruction->getNextNode()) {
            if (!next->use_empty()) {
                next->replaceAllUsesWith(PoisonValue::get(next->getType()));
            }
            next->eraseFromParent();
        }
        call->eraseFromParent();
        // The replacement return belongs to the call's block, which need not
        // be the function's final block.
        IRBuilder<> returnBuilder(block);
        ReturnFromManagedTermination(returnBuilder, *owner);
        if (ownerIsNoReturn) {
            terminating.insert(owner);
        }
    }
    marker->eraseFromParent();

    bool progress;
    do {
        progress = false;
        for (Function* function : capsule) {
            bool functionIsNoReturn = function->hasFnAttribute(Attribute::NoReturn);
            bool rewroteCall = false;
            for (BasicBlock& block : *function) {
                auto* unreachable = dyn_cast<UnreachableInst>(block.getTerminator());
                Instruction* previous = unreachable ? unreachable->getPrevNode() : nullptr;
                while (auto* intrinsic = dyn_cast_or_null<IntrinsicInst>(previous)) {
                    if (!intrinsic->isLifetimeStartOrEnd() && !isa<DbgInfoIntrinsic>(intrinsic)) {
                        break;
                    }
                    previous = previous->getPrevNode();
                }
                auto* call = dyn_cast_or_null<CallBase>(previous);
                Function* callee = call ? call->getCalledFunction() : nullptr;
                if (!callee || !terminating.contains(callee)) {
                    continue;
                }
                call->removeFnAttr(Attribute::NoReturn);
                IRBuilder<> builder(unreachable);
                ReturnFromManagedTermination(builder, *function);
                unreachable->eraseFromParent();
                rewroteCall = true;
                progress = true;
            }
            // Only a source-level noreturn function can extend the wrapper
            // chain. An ordinary function may have several conditional calls
            // to a terminating wrapper and still return on another path; all
            // those call sites need reopening, but its callers must not be
            // treated as non-returning.
            if (rewroteCall && functionIsNoReturn) {
                terminating.insert(function);
            }
        }
    } while (progress);
    return {.Changed = !calls.empty()};
}

} // namespace

PreservedAnalyses CapsulePartitionPass::run(Module& module, ModuleAnalysisManager&) {
    LowerCallResult lowered = LowerCallMarkers(module);
    if (lowered.Error) {
        return PreservedAnalyses::all();
    }
    bool changed = lowered.Changed;

    SmallVector<Function*> nativeRoots;
    SmallVector<Function*> capsuleRoots;
    for (Function& func : module) {
        func.setMetadata("bpf.native", nullptr);
        func.setMetadata("bpf.capsule", nullptr);
        if (IsEntryProgram(func)) {
            nativeRoots.push_back(&func);
        }
        for (Instruction& inst : instructions(func)) {
            auto* call = dyn_cast<CallBase>(&inst);
            if (!call || !IsBoundaryCall(*call)) {
                continue;
            }
            Function* root = call->getCalledFunction();
            if (!root) {
                report_fatal_error("bpf-partition: capsule boundary lost its static target");
            }
            capsuleRoots.push_back(root);
        }
    }

    // The throw marker is itself a managed-only boundary. Its immediate
    // wrapper may be an otherwise-unreferenced libc/language-runtime symbol
    // such as abort(), so ordinary forward reachability need not discover it
    // before GlobalDCE. Seed the direct caller into the Capsule domain. If a
    // native entry actually reaches that caller, the normal domain-overlap
    // diagnostic below rejects the program instead of emitting a native call
    // into managed control state.
    if (Function* marker = module.getFunction(ExitMarker)) {
        for (User* user : marker->users()) {
            auto* call = dyn_cast<CallBase>(user);
            if (call && call->getCalledOperand()->stripPointerCasts() == marker) {
                capsuleRoots.push_back(call->getFunction());
            }
        }
    }

    SmallPtrSet<Function*, 32> native;
    SmallPtrSet<Function*, 32> capsule;
    if (!Reach(module, nativeRoots, /*native=*/true, native)) {
        return PreservedAnalyses::all();
    }

    // A function whose address survives the normal optimizer is part of an
    // opaque callback/table surface. LLVM cannot, in general, recover which
    // indirect load will call it (QuickJS keeps jobs and builtins in such
    // tables). If native reachability did not already claim it, conservatively
    // place it and its forward closure in the Capsule domain. This keeps the
    // partition exact at the native boundary without workload-specific callback
    // discovery.
    for (Function& func : module) {
        if (!func.isDeclaration() && !IsEntryProgram(func) && !IsCompilerDriver(func) &&
            func.hasAddressTaken(
                nullptr, /*IgnoreCallbackUses=*/false,
                /*IgnoreAssumeLikeCalls=*/true,
                /*IgnoreLLVMUsed=*/true
            ) &&
            !native.contains(&func)) {
            capsuleRoots.push_back(&func);
        }
    }
    if (!Reach(module, capsuleRoots, /*native=*/false, capsule)) {
        return PreservedAnalyses::all();
    }

    for (Function* func : capsule) {
        if (native.contains(func)) {
            func->getContext().emitError(
                Twine("bpf-partition: function ") + func->getName() +
                " is reachable from both native code and a "
                "capsule_call; split the shared code explicitly"
            );
            return PreservedAnalyses::all();
        }
    }

    MDNode* empty = MDNode::get(module.getContext(), {});
    for (Function* func : native) {
        func->setMetadata("bpf.native", empty);
    }
    for (Function* func : capsule) {
        func->setMetadata("bpf.capsule", empty);
    }

    LowerCallResult exits = LowerExitMarkers(module, capsule);
    if (exits.Error) {
        return PreservedAnalyses::all();
    }
    changed |= exits.Changed;

    if (changed) {
        AddSuspendBarriers(module, capsule);
    } else {
        changed |= RemoveSuspendBarriers(module);
    }

    for (GlobalVariable& global : module.globals()) {
        global.setMetadata("bpf.native", nullptr);
        global.setMetadata("bpf.capsule", nullptr);
        if (global.isDeclaration() || global.getName().starts_with("llvm.")) {
            continue;
        }
        bool usedNative = false;
        bool usedCapsule = false;
        FindGlobalOwners(global, native, capsule, usedNative, usedCapsule);
        if (usedNative && usedCapsule && !global.hasSection()) {
            global.getContext().emitError(
                Twine("bpf-partition: unsectioned global ") + global.getName() +
                " is shared by native and Capsule code; put "
                "deliberately shared storage in an ELF section"
            );
            return PreservedAnalyses::all();
        }
        if (usedNative) {
            global.setMetadata("bpf.native", empty);
        }
        if (usedCapsule) {
            global.setMetadata("bpf.capsule", empty);
        }
    }

    bpf::stats() << "bpf-partition: " << native.size() << " native, " << capsule.size() << " Capsule functions\n";
    if (verifyModule(module, &errs())) {
        module.getContext().emitError("bpf-partition produced an invalid module");
    }
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
