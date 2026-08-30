// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "expand_sret.h"

#include "common.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>

using namespace llvm;

namespace {

// bpf-expand-sret: undo the C ABI's hidden-pointer aggregate returns for
// internal, non-address-taken functions, before O2.
//
// Clang has to emit sret. Separate compilation means every signature that
// might be seen from another object must follow the platform psABI, and the
// classification is a language-level decision the backend cannot redo (a
// C++ type with a copy constructor returns indirectly regardless of size),
// so the frontend bakes the hidden pointer into the IR. After the
// whole-program link neither constraint applies to direct internal calls,
// and this pass is the signature surgery no stock O2 pass performs: the
// callee returns a real aggregate value (its sret writes land in a local
// slot loaded at each ret), and every direct call site becomes call+store.
//
// What that buys: the caller's result slot stops being an alloca whose
// address escapes into a call, so SROA/GVN in the O2 run that follows can
// dissolve result-copy chains and keep fields in SSA — the payoff grows
// with how much a workload passes aggregates by value. It deliberately
// changes no final convention — a managed call returns through the
// continuation-frame result area either way, and Stackify accepts
// surviving sret IR as a fallback (address-taken functions keep theirs;
// Capsule roots are adapted at the call-marker boundary instead).
struct ExpandSretPass : public PassInfoMixin<ExpandSretPass> {
    PreservedAnalyses run(Module& module, ModuleAnalysisManager&) {
        SmallVector<Function*> worklist;
        for (auto&& func : module) {
            // Rewriting an address-taken function would also change the ABI
            // expected by an indirect caller which cannot be proven to name
            // only definitions in this module.  Capsule roots are
            // intentionally address-taken by the call marker and are adapted
            // at that boundary instead.  Direct internal calls provide the
            // code-quality win without changing any external ABI.
            if (!func.isDeclaration() && !func.hasAddressTaken() && func.arg_size() > 0 && func.getArg(0)->hasStructRetAttr()) {
                worklist.push_back(&func);
            }
        }
        DenseMap<Function*, Type*> rewritten;
        for (auto* func : worklist) {
            RewriteFunction(module, *func, rewritten);
        }
        // Opaque pointers let the rewritten definition replace the old
        // callee operand while the CallInst retains its original function
        // type and hidden result argument. Rewrite precisely those direct
        // sites; declarations and indirect calls keep their ABI.
        SmallVector<std::pair<CallInst*, Type*>> sites;
        for (auto&& func : module) {
            for (auto&& inst : instructions(func)) {
                auto* call = dyn_cast<CallInst>(&inst);
                if (!call) {
                    continue;
                }
                auto* callee = dyn_cast<Function>(call->getCalledOperand()->stripPointerCasts());
                auto it = callee ? rewritten.find(callee) : rewritten.end();
                if (it == rewritten.end()) {
                    continue;
                }
                if (!call->getFunctionType()->getReturnType()->isVoidTy() || call->arg_size() != callee->arg_size() + 1) {
                    report_fatal_error(Twine("bpf-expand-sret: malformed direct call to ") + callee->getName());
                }
                sites.push_back({call, it->second});
            }
        }
        for (auto&& [call, retType] : sites) {
            RewriteCallSite(*call, retType);
        }
        if (!worklist.empty() || !sites.empty()) {
            bpf::stats() << "bpf-expand-sret: " << worklist.size() << " functions and " << sites.size() << " call sites rewritten\n";
        }
        return worklist.empty() && sites.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
    }

    void RewriteFunction(Module& module, Function& func, DenseMap<Function*, Type*>& rewritten) {
        Type* retType = func.getParamStructRetType(0);
        SmallVector<Type*> params;
        for (unsigned i = 1; i < func.arg_size(); i++) {
            params.push_back(func.getArg(i)->getType());
        }
        auto* newType = FunctionType::get(retType, params, func.isVarArg());
        Function* newFunc = Function::Create(newType, func.getLinkage(), func.getAddressSpace(), "", &module);
        newFunc->takeName(&func);
        newFunc->copyAttributesFrom(&func);
        newFunc->setCallingConv(func.getCallingConv());
        newFunc->setSubprogram(func.getSubprogram());
        SmallVector<AttributeSet> parameterAttributes;
        for (unsigned i = 1; i < func.arg_size(); ++i) {
            parameterAttributes.push_back(func.getAttributes().getParamAttrs(i));
        }
        newFunc->setAttributes(AttributeList::get(module.getContext(), func.getAttributes().getFnAttrs(), AttributeSet(), parameterAttributes));
        newFunc->splice(newFunc->begin(), &func);

        IRBuilder<> builder(&newFunc->getEntryBlock(), newFunc->getEntryBlock().getFirstNonPHIIt());
        auto* slot = builder.CreateAlloca(retType);
        if (auto alignment = func.getParamAlign(0)) {
            slot->setAlignment(*alignment);
        }
        func.getArg(0)->replaceAllUsesWith(slot);
        for (unsigned i = 1; i < func.arg_size(); i++) {
            func.getArg(i)->replaceAllUsesWith(newFunc->getArg(i - 1));
            newFunc->getArg(i - 1)->takeName(func.getArg(i));
        }
        for (auto&& block : *newFunc) {
            auto* ret = dyn_cast<ReturnInst>(block.getTerminator());
            if (!ret) {
                continue;
            }
            IRBuilder<> rb(ret);
            rb.CreateRet(rb.CreateLoad(retType, slot));
            ret->eraseFromParent();
        }
        // Opaque pointers make the old and new function interchangeable as
        // values; direct calls still carry their own sret attribute and are
        // rewritten with the indirect ones.
        func.replaceAllUsesWith(newFunc);
        func.eraseFromParent();
        rewritten[newFunc] = retType;
    }

    void RewriteCallSite(CallInst& call, Type* retType) {
        Value* out = call.getArgOperand(0);
        SmallVector<Value*> args;
        SmallVector<Type*> params;
        SmallVector<AttributeSet> parameterAttributes;
        for (unsigned i = 1; i < call.arg_size(); i++) {
            args.push_back(call.getArgOperand(i));
            params.push_back(call.getArgOperand(i)->getType());
            parameterAttributes.push_back(call.getAttributes().getParamAttrs(i));
        }
        IRBuilder<> builder(&call);
        auto* newType = FunctionType::get(retType, params, call.getFunctionType()->isVarArg());
        SmallVector<OperandBundleDef> bundles;
        call.getOperandBundlesAsDefs(bundles);
        auto* newCall = builder.CreateCall(newType, call.getCalledOperand(), args, bundles);
        // A convention mismatch between call site and callee is UB that the
        // optimizer folds to poison — the grow path of Rust's Vec vanished
        // this way (fastcc callee, default-cc call).
        newCall->setCallingConv(call.getCallingConv());
        newCall->setAttributes(AttributeList::get(call.getContext(), call.getAttributes().getFnAttrs(), AttributeSet(), parameterAttributes));
        newCall->copyMetadata(call);
        newCall->setDebugLoc(call.getDebugLoc());
        StoreInst* store = builder.CreateStore(newCall, out);
        if (auto alignment = call.getParamAlign(0)) {
            store->setAlignment(*alignment);
        }
        call.eraseFromParent();
    }
};

} // namespace

bool RegisterExpandSretPass(llvm::StringRef name, llvm::ModulePassManager& manager) {
    if (name != "bpf-expand-sret") {
        return false;
    }
    manager.addPass(ExpandSretPass());
    return true;
}
