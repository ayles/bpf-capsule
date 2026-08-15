// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-soft-float: floating point, in integers.
//
// BPF has no floating-point registers, and its backend does not merely lack
// the instructions — it refuses to emit libcalls for them ("A call to
// built-in function '__floatdidf' is not supported"). So supplying
// __adddf3 as a symbol does not help: the call never gets made. The
// substitution has to happen while this is still IR.
//
// Two halves, and the second is the reason this is a whole pass rather than
// a peephole:
//   - every floating-point *operation* becomes a call to an integer routine
//     from src/libc/softfloat.c;
//   - every floating-point *value* becomes an integer of the same width,
//     because a surviving f64 is an illegal type for instruction selection
//     no matter what is done to the arithmetic. That means retyping
//     signatures, allocas, loads, stores, phis, selects and constants.
//
// Memory layouts keep their source types. SSA aggregates and function ABIs
// use layout-identical integer shadow types, while scalar loads and stores
// cross the opaque-pointer boundary as raw i32/i64 bits. This avoids mutating
// shared named structs merely because one field is used in arithmetic.
#include "softfloat.h"

#include "common.h"
#include "bpf_capsule_abi.h"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

#include <map>

using namespace llvm;

namespace {

enum class UnsupportedFloatType { None, Narrow, Wide, Vector };

UnsupportedFloatType classifyUnsupportedFloatType(Type* type, SmallPtrSetImpl<Type*>& visited) {
    if (!visited.insert(type).second) {
        return UnsupportedFloatType::None;
    }
    if (type->isHalfTy() || type->isBFloatTy()) {
        return UnsupportedFloatType::Narrow;
    }
    if (type->isX86_FP80Ty() || type->isFP128Ty() || type->isPPC_FP128Ty()) {
        return UnsupportedFloatType::Wide;
    }
    if (auto* vector = dyn_cast<VectorType>(type)) {
        if (vector->getElementType()->isFloatingPointTy()) {
            return UnsupportedFloatType::Vector;
        }
        return classifyUnsupportedFloatType(vector->getElementType(), visited);
    }
    auto merge = [&](Type* element, UnsupportedFloatType& result) {
        UnsupportedFloatType current = classifyUnsupportedFloatType(element, visited);
        if (current != UnsupportedFloatType::None) {
            result = current;
        }
    };
    UnsupportedFloatType result = UnsupportedFloatType::None;
    if (auto* array = dyn_cast<ArrayType>(type)) {
        merge(array->getElementType(), result);
    } else if (auto* structure = dyn_cast<StructType>(type)) {
        for (Type* element : structure->elements()) {
            merge(element, result);
        }
    } else if (auto* function = dyn_cast<FunctionType>(type)) {
        merge(function->getReturnType(), result);
        for (Type* parameter : function->params()) {
            merge(parameter, result);
        }
    }
    return result;
}

UnsupportedFloatType classifyUnsupportedFloatType(Type* type) {
    SmallPtrSet<Type*, 16> visited;
    return classifyUnsupportedFloatType(type, visited);
}

StringRef unsupportedFloatMessage(UnsupportedFloatType unsupported) {
    switch (unsupported) {
        case UnsupportedFloatType::Narrow:
            return "bpf-soft-float: only float and double scalar values are supported";
        case UnsupportedFloatType::Wide:
            return "bpf-soft-float: floating-point values wider than 64 bits are unsupported";
        case UnsupportedFloatType::Vector:
            return "bpf-soft-float: floating-point vectors are unsupported";
        case UnsupportedFloatType::None:
            break;
    }
    llvm_unreachable("unsupportedFloatMessage called for a supported type");
}

struct SoftFloat {
    Module& M;
    LLVMContext& Ctx;
    std::map<Type*, Type*> TypeCache;
    unsigned Ops = 0;

    SoftFloat(Module& m)
        : M(m)
        , Ctx(m.getContext()) {
    }

    // float -> i32, double -> i64, and structurally through aggregates.
    Type* mapType(Type* t) {
        if (auto it = TypeCache.find(t); it != TypeCache.end()) {
            return it->second;
        }
        Type* out = t;
        if (t->isFloatTy()) {
            out = Type::getInt32Ty(Ctx);
        } else if (t->isDoubleTy()) {
            out = Type::getInt64Ty(Ctx);
        } else if (t->isX86_FP80Ty() || t->isFP128Ty() || t->isPPC_FP128Ty()) {
            report_fatal_error("bpf-soft-float: floating-point values wider than 64 bits are unsupported");
        } else if (auto* at = dyn_cast<ArrayType>(t)) {
            out = ArrayType::get(mapType(at->getElementType()), at->getNumElements());
        } else if (auto* st = dyn_cast<StructType>(t)) {
            SmallVector<Type*> elems;
            bool changed = false;
            for (Type* e : st->elements()) {
                Type* mapped = mapType(e);
                changed |= mapped != e;
                elems.push_back(mapped);
            }
            if (changed) {
                if (st->isLiteral()) {
                    out = StructType::get(Ctx, elems, st->isPacked());
                } else {
                    std::string name = st->hasName() ? (st->getName() + ".bpf_bits").str() : "";
                    auto* shadow = StructType::create(Ctx, name);
                    shadow->setBody(elems, st->isPacked());
                    out = shadow;
                }
            }
        } else if (auto* ft = dyn_cast<FunctionType>(t)) {
            SmallVector<Type*> params;
            for (Type* p : ft->params()) {
                params.push_back(mapType(p));
            }
            out = FunctionType::get(mapType(ft->getReturnType()), params, ft->isVarArg());
        } else if (auto* vt = dyn_cast<VectorType>(t)) {
            out = VectorType::get(mapType(vt->getElementType()), vt->getElementCount());
        }
        TypeCache[t] = out;
        return out;
    }

    bool hasFloat(Type* t) {
        return mapType(t) != t;
    }

    FunctionCallee routine(StringRef name, Type* ret, ArrayRef<Type*> args) {
        return M.getOrInsertFunction(name, FunctionType::get(ret, args, false));
    }

    Type* i32() {
        return Type::getInt32Ty(Ctx);
    }
    Type* i64() {
        return Type::getInt64Ty(Ctx);
    }

    // Constants become their bit patterns; everything else is remapped by
    // the instruction walk, so only constants need handling here.
    Constant* mapConstant(Constant* c) {
        Type* nt = mapType(c->getType());
        if (auto* cf = dyn_cast<ConstantFP>(c)) {
            APInt bits = cf->getValueAPF().bitcastToAPInt();
            if (bits.getBitWidth() > nt->getIntegerBitWidth()) {
                bits = bits.trunc(nt->getIntegerBitWidth());
            }
            return ConstantInt::get(nt, bits.getZExtValue());
        }
        if (isa<UndefValue>(c)) {
            return UndefValue::get(nt);
        }
        if (isa<PoisonValue>(c)) {
            return PoisonValue::get(nt);
        }
        if (isa<ConstantAggregateZero>(c)) {
            return Constant::getNullValue(nt);
        }
        if (auto* ca = dyn_cast<ConstantArray>(c)) {
            SmallVector<Constant*> elems;
            bool changed = nt != c->getType();
            for (unsigned i = 0; i < ca->getNumOperands(); i++) {
                Constant* element = mapConstant(ca->getOperand(i));
                changed |= element != ca->getOperand(i);
                elems.push_back(element);
            }
            return changed ? ConstantArray::get(cast<ArrayType>(nt), elems) : c;
        }
        if (auto* cs = dyn_cast<ConstantStruct>(c)) {
            SmallVector<Constant*> elems;
            bool changed = nt != c->getType();
            for (unsigned i = 0; i < cs->getNumOperands(); i++) {
                Constant* element = mapConstant(cs->getOperand(i));
                changed |= element != cs->getOperand(i);
                elems.push_back(element);
            }
            return changed ? ConstantStruct::get(cast<StructType>(nt), elems) : c;
        }
        if (auto* cv = dyn_cast<ConstantVector>(c)) {
            SmallVector<Constant*> elems;
            for (unsigned i = 0; i < cv->getNumOperands(); i++) {
                elems.push_back(mapConstant(cv->getOperand(i)));
            }
            return ConstantVector::get(elems);
        }
        // Literal float/double tables — `static const double pow10[] = {...}`
        // — are ConstantDataArray, a distinct class from ConstantArray. Every
        // interpreter's constant pool arrives this way, so dropping to the
        // fatal case below would reject real programs, and the one thing this
        // function must never do is quietly zero them.
        if (auto* cds = dyn_cast<ConstantDataSequential>(c)) {
            SmallVector<Constant*> elems;
            for (unsigned i = 0; i < cds->getNumElements(); i++) {
                elems.push_back(mapConstant(cds->getElementAsConstant(i)));
            }
            if (isa<ConstantDataVector>(cds)) {
                return ConstantVector::get(elems);
            }
            return ConstantArray::get(cast<ArrayType>(nt), elems);
        }
        if (nt == c->getType()) {
            return c;
        }
        // Anything else (a ConstantExpr over an FP type, a future constant
        // kind) has no correct translation here. Zeroing it would be a silent
        // miscompile; stop the build and name the constant instead.
        std::string desc;
        raw_string_ostream os(desc);
        c->print(os);
        report_fatal_error(Twine("bpf-soft-float: unhandled constant kind: ") + os.str());
    }

    // Replace one floating-point instruction with integer work. Returns the
    // integer replacement, or null when the instruction only needed retyping
    // (handled by the caller).
    Value* lower(Instruction& I, IRBuilder<>& b, function_ref<Value*(Value*)> get) {
        auto isF32 = [&](Value* v) { return v->getType()->isFloatTy(); };
        auto call2 = [&](StringRef n32, StringRef n64, Value* x, Value* y) {
            bool f32 = isF32(x);
            Type* t = f32 ? i32() : i64();
            return b.CreateCall(routine(f32 ? n32 : n64, t, {t, t}), {get(x), get(y)});
        };

        switch (I.getOpcode()) {
            case Instruction::FAdd:
                return call2("__bpf_fadd", "__bpf_dadd", I.getOperand(0), I.getOperand(1));
            case Instruction::FSub:
                return call2("__bpf_fsub", "__bpf_dsub", I.getOperand(0), I.getOperand(1));
            case Instruction::FMul:
                return call2("__bpf_fmul", "__bpf_dmul", I.getOperand(0), I.getOperand(1));
            case Instruction::FDiv:
                return call2("__bpf_fdiv", "__bpf_ddiv", I.getOperand(0), I.getOperand(1));
            case Instruction::FRem:
                return call2("__bpf_frem", "__bpf_drem", I.getOperand(0), I.getOperand(1));
            case Instruction::FNeg: {
                Value* x = get(I.getOperand(0));
                bool f32 = isF32(I.getOperand(0));
                return b.CreateXor(x, ConstantInt::get(f32 ? i32() : i64(), f32 ? 0x80000000ull : (1ull << 63)));
            }
            case Instruction::FCmp: {
                auto& fc = cast<FCmpInst>(I);
                Value* x = fc.getOperand(0);
                bool f32 = isF32(x);
                Type* t = f32 ? i32() : i64();
                Value* c = b.CreateCall(routine(f32 ? "__bpf_fcmp" : "__bpf_dcmp", i32(), {t, t}), {get(fc.getOperand(0)), get(fc.getOperand(1))});
                // The routine answers -1 / 0 / 1, or 2 when either side is NaN.
                Value* zero = ConstantInt::get(i32(), 0);
                Value* two = ConstantInt::get(i32(), 2);
                Value* unord = b.CreateICmpEQ(c, two);
                Value* lt = b.CreateICmpEQ(c, ConstantInt::get(i32(), -1));
                Value* eq = b.CreateICmpEQ(c, zero);
                Value* gt = b.CreateICmpEQ(c, ConstantInt::get(i32(), 1));
                Value* r = nullptr;
                switch (fc.getPredicate()) {
                    case FCmpInst::FCMP_FALSE:
                        r = b.getFalse();
                        break;
                    case FCmpInst::FCMP_TRUE:
                        r = b.getTrue();
                        break;
                    case FCmpInst::FCMP_ORD:
                        r = b.CreateNot(unord);
                        break;
                    case FCmpInst::FCMP_UNO:
                        r = unord;
                        break;
                    case FCmpInst::FCMP_OEQ:
                        r = eq;
                        break;
                    case FCmpInst::FCMP_OGT:
                        r = gt;
                        break;
                    case FCmpInst::FCMP_OGE:
                        r = b.CreateOr(gt, eq);
                        break;
                    case FCmpInst::FCMP_OLT:
                        r = lt;
                        break;
                    case FCmpInst::FCMP_OLE:
                        r = b.CreateOr(lt, eq);
                        break;
                    case FCmpInst::FCMP_ONE:
                        r = b.CreateOr(lt, gt);
                        break;
                    case FCmpInst::FCMP_UEQ:
                        r = b.CreateOr(eq, unord);
                        break;
                    case FCmpInst::FCMP_UGT:
                        r = b.CreateOr(gt, unord);
                        break;
                    case FCmpInst::FCMP_UGE:
                        r = b.CreateOr(b.CreateOr(gt, eq), unord);
                        break;
                    case FCmpInst::FCMP_ULT:
                        r = b.CreateOr(lt, unord);
                        break;
                    case FCmpInst::FCMP_ULE:
                        r = b.CreateOr(b.CreateOr(lt, eq), unord);
                        break;
                    case FCmpInst::FCMP_UNE:
                        r = b.CreateNot(eq);
                        break;
                    default:
                        llvm_unreachable("invalid floating-point comparison predicate");
                }
                return r;
            }
            case Instruction::FPExt: { // float -> double
                Value* x = get(I.getOperand(0));
                return b.CreateCall(routine("__bpf_f2d", i64(), {i32()}), {x});
            }
            case Instruction::FPTrunc: { // double -> float
                Value* x = get(I.getOperand(0));
                return b.CreateCall(routine("__bpf_d2f", i32(), {i64()}), {x});
            }
            case Instruction::SIToFP:
            case Instruction::UIToFP: {
                Value* x = get(I.getOperand(0));
                bool sgn = I.getOpcode() == Instruction::SIToFP;
                x = sgn ? b.CreateSExtOrTrunc(x, i64()) : b.CreateZExtOrTrunc(x, i64());
                bool toF32 = I.getType()->isFloatTy();
                StringRef n = toF32 ? (sgn ? "__bpf_i2f" : "__bpf_u2f") : (sgn ? "__bpf_i2d" : "__bpf_u2d");
                return b.CreateCall(routine(n, toF32 ? i32() : i64(), {i64()}), {x});
            }
            case Instruction::FPToSI:
            case Instruction::FPToUI: {
                Value* x = get(I.getOperand(0));
                bool sgn = I.getOpcode() == Instruction::FPToSI;
                bool fromF32 = I.getOperand(0)->getType()->isFloatTy();
                StringRef n = fromF32 ? (sgn ? "__bpf_f2i" : "__bpf_f2u") : (sgn ? "__bpf_d2i" : "__bpf_d2u");
                Value* r = b.CreateCall(routine(n, i64(), {fromF32 ? i32() : i64()}), {x});
                return b.CreateTruncOrBitCast(r, I.getType());
            }
            default:
                return nullptr;
        }
    }
};

} // namespace

PreservedAnalyses SoftFloatPass::run(Module& module, ModuleAnalysisManager&) {
    // Validate the complete input before mapType mutates named aggregate
    // bodies. Both cases are outside the scalar f32/f64 ABI; diagnosing them
    // here avoids an LLVM fatal error or an incompatible scalar helper call.
    for (GlobalVariable& global : module.globals()) {
        UnsupportedFloatType unsupported = classifyUnsupportedFloatType(global.getValueType());
        if (unsupported != UnsupportedFloatType::None) {
            module.getContext().emitError(unsupportedFloatMessage(unsupported));
            return PreservedAnalyses::all();
        }
    }
    for (Function& function : module) {
        UnsupportedFloatType unsupported = classifyUnsupportedFloatType(function.getFunctionType());
        if (unsupported != UnsupportedFloatType::None) {
            function.getContext().emitError(Twine(unsupportedFloatMessage(unsupported)) + " in " + function.getName());
            return PreservedAnalyses::all();
        }
        if (function.isDeclaration()) {
            continue;
        }
        for (Instruction& instruction : instructions(function)) {
            unsupported = classifyUnsupportedFloatType(instruction.getType());
            for (Value* operand : instruction.operands()) {
                if (unsupported == UnsupportedFloatType::None) {
                    unsupported = classifyUnsupportedFloatType(operand->getType());
                }
            }
            if (unsupported != UnsupportedFloatType::None) {
                instruction.getContext().emitError(&instruction, unsupportedFloatMessage(unsupported));
                return PreservedAnalyses::all();
            }
            // Reject vectors before asking LLVM for an integer bit width:
            // Type::getIntegerBitWidth() is an IntegerType-only accessor, not
            // a scalar-element query for vector conversions.
            if ((isa<SIToFPInst, UIToFPInst>(instruction) && instruction.getOperand(0)->getType()->getIntegerBitWidth() > 64) ||
                (isa<FPToSIInst, FPToUIInst>(instruction) && instruction.getType()->getIntegerBitWidth() > 64)) {
                instruction.getContext().emitError(
                    &instruction, "bpf-soft-float: conversions between floating point and integers wider than 64 bits are unsupported"
                );
                return PreservedAnalyses::all();
            }
        }
    }

    SoftFloat SF(module);

    // Globals and allocas are memory, not SSA values. Preserve their source
    // types and initializers; opaque pointers let the rewritten integer
    // loads/stores access the same layout without casts or memcpy shims.

    // Signatures: a function taking or returning a float becomes one taking
    // or returning the integer that holds it.
    // Intrinsics own their signatures — retyping one produces a module the
    // verifier rejects — so they are expanded at their call sites instead
    // (see the intrinsic handling in the body walk below).
    SmallVector<Function*> retype;
    for (auto&& f : module) {
        if (!f.isIntrinsic() && SF.mapType(f.getFunctionType()) != f.getFunctionType()) {
            retype.push_back(&f);
        }
    }

    // Bodies. Values are rewritten in place: an instruction whose type maps
    // to an integer is replaced by integer work, and everything downstream
    // reads the replacement through the map.
    // Argument mappings outlive their function; instruction mappings must
    // not, because a freed instruction address can be reused by the next
    // function and silently match a stale entry.
    std::map<Value*, Value*> argRepl;

    SmallVector<Function*> husks;
    SmallVector<Function*> retyped;
    for (auto* f : retype) {
        auto* nft = cast<FunctionType>(SF.mapType(f->getFunctionType()));
        auto* nf = Function::Create(nft, f->getLinkage(), f->getAddressSpace(), "", &module);
        nf->takeName(f);
        nf->copyAttributesFrom(f);
        nf->setSubprogram(f->getSubprogram());
        f->setSubprogram(nullptr);
        nf->splice(nf->begin(), f);
        for (unsigned i = 0; i < f->arg_size(); i++) {
            Argument* oldA = f->getArg(i);
            Argument* newA = nf->getArg(i);
            newA->takeName(oldA);
            if (oldA->getType() == newA->getType()) {
                oldA->replaceAllUsesWith(newA);
            } else {
                argRepl[oldA] = newA; // rewritten with the rest of the body
            }
        }
        f->replaceAllUsesWith(nf);
        // The old function keeps its arguments alive: the spliced body still
        // refers to them until the rewrite below swaps them out, so it can
        // only be dropped afterwards.
        husks.push_back(f);
        retyped.push_back(nf);
    }
    std::map<Value*, Value*> repl;
    auto get = [&](Value* v) -> Value* {
        if (auto it = repl.find(v); it != repl.end()) {
            return it->second;
        }
        if (auto it = argRepl.find(v); it != argRepl.end()) {
            return it->second;
        }
        if (auto* c = dyn_cast<Constant>(v)) {
            return SF.mapConstant(c);
        }
        return v;
    };

    unsigned lowered = 0;
    for (auto&& f : module) {
        if (f.isDeclaration()) {
            continue;
        }
        repl.clear();
        SmallVector<Instruction*> dead;
        SmallVector<PHINode*> phis;

        for (auto&& bb : f) {
            for (auto&& I : bb) {
                IRBuilder<> b(&I);
                if (Value* nv = SF.lower(I, b, get)) {
                    repl[&I] = nv;
                    dead.push_back(&I);
                    lowered++;
                    continue;
                }
                // Floating-point intrinsics: the ones with an exact integer
                // equivalent are expanded here. The rest (llvm.sqrt,
                // llvm.floor, the transcendentals — Clang emits these directly
                // for the plain libm calls) have no integer routine, so they
                // publish CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC and yield
                // zero: the host sees a distinct code, never a plausible
                // wrong number.
                if (auto* ii = dyn_cast<IntrinsicInst>(&I)) {
                    if (!SF.hasFloat(ii->getFunctionType())) {
                        continue;
                    }
                    IRBuilder<> ib(ii);
                    bool f32 = ii->getType()->isFloatTy();
                    Type* it = f32 ? SF.i32() : SF.i64();
                    Value* nv = nullptr;
                    switch (ii->getIntrinsicID()) {
                        case Intrinsic::fmuladd:
                        case Intrinsic::fma: {
                            Value* m = ib.CreateCall(
                                SF.routine(f32 ? "__bpf_fmul" : "__bpf_dmul", it, {it, it}), {get(ii->getArgOperand(0)), get(ii->getArgOperand(1))}
                            );
                            nv = ib.CreateCall(SF.routine(f32 ? "__bpf_fadd" : "__bpf_dadd", it, {it, it}), {m, get(ii->getArgOperand(2))});
                            break;
                        }
                        case Intrinsic::fabs:
                            nv = ib.CreateAnd(get(ii->getArgOperand(0)), ConstantInt::get(it, f32 ? 0x7fffffffull : ~(1ull << 63)));
                            break;
                        case Intrinsic::copysign: {
                            uint64_t signBit = f32 ? 0x80000000ull : (1ull << 63);
                            Value* mag = ib.CreateAnd(get(ii->getArgOperand(0)), ConstantInt::get(it, ~signBit));
                            Value* sgn = ib.CreateAnd(get(ii->getArgOperand(1)), ConstantInt::get(it, signBit));
                            nv = ib.CreateOr(mag, sgn);
                            break;
                        }
                        default:
                            ib.CreateStore(
                                ConstantInt::get(
                                    Type::getInt64Ty(module.getContext()),
                                    bpf::ExitWordValue(CAPSULE_ERROR_UNSUPPORTED_FP_INTRINSIC)
                                ), // "float intrinsic"
                                bpf::ExitWordPointer(ib, f)
                            );
                            nv = Constant::getNullValue(it);
                            break;
                    }
                    repl[ii] = nv;
                    dead.push_back(ii);
                    lowered++;
                    continue;
                }
                // A call carries its own copy of the callee's signature, so
                // retyping the function is not enough — the call has to be
                // rebuilt or its result keeps the float type.
                if (auto* call = dyn_cast<CallInst>(&I)) {
                    FunctionType* oft = call->getFunctionType();
                    auto* nft = cast<FunctionType>(SF.mapType(oft));
                    if (nft == oft) {
                        continue;
                    }
                    IRBuilder<> cb(call);
                    SmallVector<Value*> args;
                    for (unsigned i = 0; i < call->arg_size(); i++) {
                        args.push_back(get(call->getArgOperand(i)));
                    }
                    auto* nc = cb.CreateCall(nft, get(call->getCalledOperand()), args);
                    nc->setCallingConv(call->getCallingConv());
                    nc->setTailCallKind(call->getTailCallKind());
                    if (!call->getType()->isVoidTy()) {
                        repl[call] = nc;
                    }
                    dead.push_back(call);
                    continue;
                }
                // Not an FP operation: retype it if it carries an FP type.
                if (auto* alloca = dyn_cast<AllocaInst>(&I)) {
                    continue;
                }
                if (auto* load = dyn_cast<LoadInst>(&I)) {
                    Type* nt = SF.mapType(load->getType());
                    if (nt == load->getType()) {
                        continue;
                    }
                    IRBuilder<> lb(load);
                    auto* nl = lb.CreateAlignedLoad(nt, load->getPointerOperand(), load->getAlign());
                    nl->setVolatile(load->isVolatile());
                    repl[load] = nl;
                    dead.push_back(load);
                    continue;
                }
                if (auto* store = dyn_cast<StoreInst>(&I)) {
                    Value* v = store->getValueOperand();
                    if (!SF.hasFloat(v->getType())) {
                        continue;
                    }
                    IRBuilder<> sb(store);
                    auto* ns = sb.CreateAlignedStore(get(v), store->getPointerOperand(), store->getAlign());
                    ns->setVolatile(store->isVolatile());
                    dead.push_back(store);
                    continue;
                }
                if (auto* phi = dyn_cast<PHINode>(&I)) {
                    Type* nt = SF.mapType(phi->getType());
                    if (nt == phi->getType()) {
                        continue;
                    }
                    IRBuilder<> pb(phi);
                    auto* np = pb.CreatePHI(nt, phi->getNumIncomingValues());
                    repl[phi] = np;
                    phis.push_back(phi);
                    dead.push_back(phi);
                    continue;
                }
                if (auto* sel = dyn_cast<SelectInst>(&I)) {
                    if (!SF.hasFloat(sel->getType())) {
                        continue;
                    }
                    IRBuilder<> b2(sel);
                    auto* ns = b2.CreateSelect(get(sel->getCondition()), get(sel->getTrueValue()), get(sel->getFalseValue()));
                    repl[sel] = ns;
                    dead.push_back(sel);
                    continue;
                }
                if (auto* extract = dyn_cast<ExtractValueInst>(&I)) {
                    Type* nt = SF.mapType(extract->getType());
                    if (nt == extract->getType()) {
                        continue;
                    }
                    IRBuilder<> eb(extract);
                    Value* replacement = eb.CreateExtractValue(get(extract->getAggregateOperand()), extract->getIndices());
                    repl[extract] = replacement;
                    dead.push_back(extract);
                    continue;
                }
                if (auto* insert = dyn_cast<InsertValueInst>(&I)) {
                    Value* aggregate = get(insert->getAggregateOperand());
                    Value* value = get(insert->getInsertedValueOperand());
                    if (aggregate == insert->getAggregateOperand() && value == insert->getInsertedValueOperand()) {
                        continue;
                    }
                    IRBuilder<> ib(insert);
                    Value* replacement = ib.CreateInsertValue(aggregate, value, insert->getIndices());
                    repl[insert] = replacement;
                    dead.push_back(insert);
                    continue;
                }
            }
        }

        // PHI operands only exist once every block has been visited.
        for (auto* phi : phis) {
            auto* np = cast<PHINode>(repl[phi]);
            for (unsigned i = 0; i < phi->getNumIncomingValues(); i++) {
                np->addIncoming(get(phi->getIncomingValue(i)), phi->getIncomingBlock(i));
            }
        }

        // Remaining operand uses: calls, returns, GEPs and the like.
        for (auto&& I : instructions(f)) {
            if (repl.count(&I)) {
                continue;
            }
            for (unsigned i = 0; i < I.getNumOperands(); i++) {
                Value* op = I.getOperand(i);
                Value* nv = get(op);
                if (nv != op) {
                    I.setOperand(i, nv);
                }
            }
        }

        for (auto* I : reverse(dead)) {
            if (auto it = repl.find(I); it != repl.end()) {
                for (User* u : SmallVector<User*>(I->users())) {
                    if (auto* ui = dyn_cast<Instruction>(u)) {
                        for (unsigned k = 0; k < ui->getNumOperands(); k++) {
                            if (ui->getOperand(k) == I) {
                                ui->setOperand(k, it->second);
                            }
                        }
                    }
                }
            }
            I->replaceAllUsesWith(UndefValue::get(I->getType()));
            I->eraseFromParent();
        }
    }

    // Every call this pass created needs a source location: a function that
    // carries debug info may not contain an inlinable call without one, and
    // the module verifier rejects it. They inherit the location of whatever
    // they replaced, or the function's own when that had none.
    for (auto&& f : module) {
        DISubprogram* sp = f.getSubprogram();
        if (!sp) {
            continue;
        }
        for (auto&& inst : instructions(f)) {
            if (inst.getDebugLoc()) {
                continue;
            }
            if (isa<CallBase>(&inst)) {
                inst.setDebugLoc(DILocation::get(f.getContext(), 0, 0, sp));
            }
        }
    }

    // A retyped function's debug info still describes the floats it used to
    // take, so its BTF record contradicts the function itself and the kernel
    // rejects the object ("FUNC __bpf_dadd Invalid arg#1"). Keep the original
    // distinct DISubprogram -- every instruction and loop DILocation already
    // names it -- and replace only its signature. Creating a second
    // DISubprogram would split the function from those existing locations;
    // stripping them fixes the verifier error at the cost of all source
    // locations. Nothing downstream needs the parameter list to be accurate,
    // only consistent. One DIBuilder is finalized once: finalizing per
    // function corrupts the compile unit.
    if (!module.debug_compile_units().empty() && !retyped.empty()) {
        auto* cu = *module.debug_compile_units_begin();
        DIBuilder db(module, false, cu);
        for (auto* nf : retyped) {
            if (!nf->getSubprogram()) {
                continue;
            }
            // Element zero of a subroutine type is the return type (null for
            // void); the rest are parameters. Naming no parameters is what
            // makes the record acceptable -- an empty array is malformed and
            // the kernel reports it as a bad argument.
            Type* rt = nf->getReturnType();
            Metadata* retType = rt->isVoidTy() ? nullptr : static_cast<Metadata*>(BtfGetInt(db, rt->isIntegerTy() ? rt->getIntegerBitWidth() : 64, true));
            auto* sig = db.createSubroutineType(db.getOrCreateTypeArray({retType}));
            nf->getSubprogram()->replaceType(sig);
        }
        db.finalize();
    }

    for (auto* f : husks) {
        f->eraseFromParent();
    }

    if (lowered) {
        bpf::stats() << "bpf-soft-float: " << lowered << " floating-point operations "
                     << "replaced, " << retype.size() << " signatures retyped\n";
    }
    if (verifyModule(module, &errs())) {
        module.getContext().emitError("bpf-soft-float produced an invalid module");
    }
    return lowered || !retype.empty() ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
