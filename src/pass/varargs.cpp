// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-expand-varargs: whole-program devariadicization.
//
// BPF has no variadic ABI (arguments travel in r1-r5, nothing spills to a
// stack the callee could walk), and stackify cannot lay out a frame for an
// argument list it cannot see. So variadic functions stop existing before
// either has to care: every defined variadic function gets a fixed signature
// with one extra pointer, every call site packs its variadic arguments into
// 8-byte slots of a local buffer and passes that, and va_arg becomes a
// pointer bump. LLVM's expand-variadics does exactly this for GPU targets
// but has no BPF ABI entry, hence this pass.
//
// The slot convention: every variadic argument occupies 8 bytes at its
// natural value; an i32 is read back as an i32 from the slot base, which is
// correct little-endian and leaves the upper half unread. Integers, pointers,
// and floating point are all accepted here — this pass runs before soft-float,
// so FP values still exist and are packed by bitcasting into the slot.
#include "varargs.h"

#include "common.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

#include <cassert>

using namespace llvm;

namespace {

bool SupportedSlotType(const DataLayout& layout, Type* type) {
    if (!type->isIntegerTy() && !type->isPointerTy() && !type->isFloatingPointTy()) {
        return false;
    }
    TypeSize size = layout.getTypeStoreSize(type);
    return !size.isScalable() && size.getFixedValue() <= 8;
}

bool ValidateVaOps(Function& func, bool hasPack) {
    const DataLayout& layout = func.getParent()->getDataLayout();
    bool invalid = false;
    for (Instruction& inst : instructions(func)) {
        if (isa<VAStartInst>(inst) && !hasPack) {
            func.getContext().emitError(&inst, Twine("bpf-expand-varargs: va_start in non-variadic ") + func.getName());
            invalid = true;
        } else if (auto* va = dyn_cast<VAArgInst>(&inst); va && !SupportedSlotType(layout, va->getType())) {
            func.getContext().emitError(
                va,
                Twine(
                    "bpf-expand-varargs: va_arg wider than the 8-byte BPF "
                    "variadic slot in "
                ) + func.getName()
            );
            invalid = true;
        }
    }
    return !invalid;
}

// Lower the va machinery inside an already-rewritten function: va_start
// points the list at the pack, va_arg loads a slot and bumps, va_end
// disappears.
void LowerVaOps(Function& func, Value* pack) {
    SmallVector<Instruction*> dead;
    for (auto&& inst : instructions(func)) {
        if (auto* start = dyn_cast<VAStartInst>(&inst)) {
            if (!pack) {
                report_fatal_error(
                    Twine(
                        "bpf-expand-varargs: va_start in "
                        "non-variadic "
                    ) +
                    func.getName()
                );
            }
            IRBuilder<> b(start);
            b.CreateStore(pack, start->getArgList());
            dead.push_back(start);
        } else if (auto* end = dyn_cast<VAEndInst>(&inst)) {
            dead.push_back(end);
        } else if (auto* copy = dyn_cast<VACopyInst>(&inst)) {
            IRBuilder<> b(copy);
            b.CreateStore(b.CreateLoad(b.getPtrTy(), copy->getSrc()), copy->getDest());
            dead.push_back(copy);
        }
    }
    for (auto* inst : dead) {
        inst->eraseFromParent();
    }

    SmallVector<VAArgInst*> args;
    for (auto&& inst : instructions(func)) {
        if (auto* va = dyn_cast<VAArgInst>(&inst)) {
            args.push_back(va);
        }
    }
    for (auto* va : args) {
        Type* type = va->getType();
        assert(SupportedSlotType(func.getParent()->getDataLayout(), type) && "variadic slot type must be validated before lowering");
        IRBuilder<> b(va);
        auto* cur = b.CreateLoad(b.getPtrTy(), va->getPointerOperand());
        auto* value = b.CreateLoad(type, cur);
        auto* next = b.CreateGEP(b.getInt8Ty(), cur, b.getInt64(8));
        b.CreateStore(next, va->getPointerOperand());
        va->replaceAllUsesWith(value);
        va->eraseFromParent();
    }
}

} // namespace

PreservedAnalyses ExpandVarargsPass::run(Module& module, ModuleAnalysisManager&) {
    SmallVector<Function*> variadic;
    bool invalid = false;
    for (auto&& func : module) {
        if (func.isVarArg() && !func.isDeclaration()) {
            variadic.push_back(&func);
            continue;
        }
        if (!func.isVarArg() || !func.isDeclaration() || func.use_empty()) {
            continue;
        }
        // This compiler-owned source marker intentionally uses varargs so the
        // public capsule_call macro can carry arbitrary typed arguments. The
        // immediately following partition pass replaces it with a typed direct
        // call; it is not an external BPF ABI.
        if (func.getName() == "__bpf_capsule_call") {
            continue;
        }

        // BPF has no ABI through which an external variadic callee could
        // recover the unnamed arguments. Defined functions are rewritten
        // below; declarations need a fixed-signature wrapper at the source
        // boundary instead of failing much later in stackification/codegen.
        for (Use& use : func.uses()) {
            auto* call = dyn_cast<CallBase>(use.getUser());
            if (!call || !call->isCallee(&use)) {
                // Personality routines and other ABI metadata can reference
                // a variadic declaration without making a BPF call to it.
                continue;
            }
            call->getContext().emitError(
                call, Twine("bpf-expand-varargs: call to declared-only variadic external ") + func.getName() + " is unsupported; use a non-variadic wrapper"
            );
            invalid = true;
        }
    }
    auto& ctx = module.getContext();
    auto* i8 = Type::getInt8Ty(ctx);

    // Reject the unsupported subset before replacing any function. This keeps
    // diagnostics recoverable and prevents a wide value from overwriting the
    // fixed 8-byte slot that the lowered va_arg walk advances by.
    const DataLayout& layout = module.getDataLayout();
    for (Function* func : variadic) {
        invalid |= !ValidateVaOps(*func, /*hasPack=*/true);
        for (Use& use : func->uses()) {
            auto* callBase = dyn_cast<CallBase>(use.getUser());
            if (!callBase || !callBase->isCallee(&use)) {
                ctx.emitError(Twine("bpf-expand-varargs: address of variadic ") + func->getName() + " escapes; cannot rewrite");
                invalid = true;
                continue;
            }
            auto* call = dyn_cast<CallInst>(callBase);
            if (!call) {
                callBase->getContext().emitError(callBase, Twine("bpf-expand-varargs: invoke of variadic ") + func->getName() + " is unsupported");
                invalid = true;
                continue;
            }
            unsigned fixed = func->arg_size();
            for (unsigned index = fixed; index < call->arg_size(); ++index) {
                Type* type = call->getArgOperand(index)->getType();
                if (SupportedSlotType(layout, type)) {
                    continue;
                }
                call->getFunction()->getContext().emitError(
                    call,
                    Twine(
                        "bpf-expand-varargs: argument wider than the 8-byte "
                        "BPF variadic slot calling "
                    ) + func->getName()
                );
                invalid = true;
            }
        }
    }
    for (Function& func : module) {
        if (!func.isDeclaration() && !func.isVarArg()) {
            invalid |= !ValidateVaOps(func, /*hasPack=*/false);
        }
    }
    if (invalid) {
        return PreservedAnalyses::all();
    }
    if (variadic.empty()) {
        return PreservedAnalyses::all();
    }

    for (auto* func : variadic) {
        // The replacement signature: the fixed parameters plus the pack.
        SmallVector<Type*> params(func->getFunctionType()->params());
        params.push_back(PointerType::get(ctx, 0));
        auto* fixedType = FunctionType::get(func->getReturnType(), params, false);

        auto* fixed = Function::Create(fixedType, func->getLinkage(), "", &module);
        fixed->takeName(func);
        fixed->copyAttributesFrom(func);
        fixed->setSubprogram(func->getSubprogram());
        fixed->splice(fixed->begin(), func);
        for (unsigned i = 0; i < func->arg_size(); i++) {
            func->getArg(i)->replaceAllUsesWith(fixed->getArg(i));
            fixed->getArg(i)->takeName(func->getArg(i));
        }
        Value* pack = fixed->getArg(fixed->arg_size() - 1);
        pack->setName("vararg.pack");
        LowerVaOps(*fixed, pack);

        // Rewrite every call site: pack the variadic tail, call the fixed
        // form. Anything but a direct call has no lowering here.
        SmallVector<CallInst*> calls;
        for (auto&& use : func->uses()) {
            auto* call = dyn_cast<CallInst>(use.getUser());
            assert(call && call->isCallee(&use) && "variadic function use must be validated before lowering");
            calls.push_back(call);
        }
        for (auto* call : calls) {
            unsigned nfixed = fixedType->getNumParams() - 1;
            unsigned nvar = call->arg_size() - nfixed;
            IRBuilder<> entry(&*call->getFunction()->getEntryBlock().getFirstInsertionPt());
            auto* packType = ArrayType::get(i8, 8 * std::max(1u, nvar));
            auto* buffer = entry.CreateAlloca(packType, nullptr, "vararg.buffer");
            buffer->setAlignment(Align(8));

            IRBuilder<> b(call);
            SmallVector<Value*> args(call->args().begin(), call->args().begin() + nfixed);
            for (unsigned i = 0; i < nvar; i++) {
                Value* arg = call->getArgOperand(nfixed + i);
                Type* at = arg->getType();
                // A slot holds bytes, so a float travels as its bit pattern
                // and comes back out as one: va_arg reloads with the type the
                // callee asks for. Whether the float can be computed at all
                // is a separate question, and the answer comes later in the
                // pipeline.
                if (at->isFloatingPointTy()) {
                    arg = b.CreateBitCast(arg, IntegerType::get(ctx, at->getPrimitiveSizeInBits()));
                } else {
                    assert(
                        (at->isIntegerTy() || at->isPointerTy()) && SupportedSlotType(module.getDataLayout(), at) &&
                        "variadic argument must be validated before lowering"
                    );
                }
                b.CreateStore(arg, b.CreateGEP(i8, buffer, b.getInt64(8 * i)));
            }
            args.push_back(buffer);
            SmallVector<OperandBundleDef> bundles;
            call->getOperandBundlesAsDefs(bundles);
            auto* replaced = b.CreateCall(fixedType, fixed, args, bundles);
            replaced->setCallingConv(call->getCallingConv());
            replaced->setTailCallKind(call->getTailCallKind());
            SmallVector<AttributeSet> parameterAttributes;
            parameterAttributes.reserve(nfixed + 1);
            for (unsigned i = 0; i < nfixed; ++i) {
                parameterAttributes.push_back(call->getAttributes().getParamAttrs(i));
            }
            parameterAttributes.push_back({});
            replaced->setAttributes(AttributeList::get(ctx, call->getAttributes().getFnAttrs(), call->getAttributes().getRetAttrs(), parameterAttributes));
            replaced->copyMetadata(*call);
            replaced->setDebugLoc(call->getDebugLoc());
            call->replaceAllUsesWith(replaced);
            call->eraseFromParent();
        }
        func->eraseFromParent();
    }

    // va_arg also lives in fixed-arg helpers that walk a passed va_list
    // (printf cores take one as a plain parameter). Every list now points at
    // an 8-byte-slot pack, so the walk lowers the same way everywhere.
    for (auto&& func : module) {
        if (!func.isDeclaration()) {
            LowerVaOps(func, nullptr);
        }
    }

    bpf::stats() << "bpf-expand-varargs: " << variadic.size() << " variadic functions rewritten\n";
    if (verifyModule(module, &errs())) {
        module.getContext().emitError("bpf-expand-varargs produced an invalid module");
    }
    return PreservedAnalyses::none();
}
