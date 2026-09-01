// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "scalarize_agg.h"

#include "common.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Alignment.h>

using namespace llvm;

namespace {

uint64_t elementOffset(const DataLayout& layout, Type* aggregate, unsigned index) {
    if (auto* structure = dyn_cast<StructType>(aggregate)) {
        return layout.getStructLayout(structure)->getElementOffset(index);
    }
    auto* array = cast<ArrayType>(aggregate);
    return layout.getTypeAllocSize(array->getElementType()).getFixedValue() * index;
}

Type* elementType(Type* aggregate, unsigned index) {
    if (auto* structure = dyn_cast<StructType>(aggregate)) {
        return structure->getElementType(index);
    }
    return cast<ArrayType>(aggregate)->getElementType();
}

unsigned elementCount(Type* aggregate) {
    if (auto* structure = dyn_cast<StructType>(aggregate)) {
        return structure->getNumElements();
    }
    return cast<ArrayType>(aggregate)->getNumElements();
}

bool needsScalarMemory(Type* type) {
    return type->isAggregateType() || type->isIntegerTy(128);
}

// Fixed-map memory is routed through scalar width-specific accessors. LLVM
// otherwise leaves stackified by-value structures and late i128 stack loads
// as operations wider than an accessor can represent. Split both after
// stackification; the arena pipeline does not need this because native wide
// memory accesses are legal and cheaper there.
class ScalarizeAggPass : public PassInfoMixin<ScalarizeAggPass> {
public:
    PreservedAnalyses run(Function& function, FunctionAnalysisManager&) {
        SmallVector<Instruction*> work;
        for (Instruction& instruction : instructions(function)) {
            if (auto* load = dyn_cast<LoadInst>(&instruction); load && needsScalarMemory(load->getType())) {
                work.push_back(load);
            } else if (auto* store = dyn_cast<StoreInst>(&instruction); store && needsScalarMemory(store->getValueOperand()->getType())) {
                work.push_back(store);
            }
        }
        if (work.empty()) {
            return PreservedAnalyses::all();
        }

        const DataLayout& layout = function.getParent()->getDataLayout();
        for (size_t cursor = 0; cursor != work.size(); ++cursor) {
            Instruction* instruction = work[cursor];
            IRBuilder<> builder(instruction);
            builder.SetCurrentDebugLocation(instruction->getDebugLoc());

            if (auto* load = dyn_cast<LoadInst>(instruction)) {
                if (load->getType()->isIntegerTy(128)) {
                    Value* words[2] = {};
                    for (unsigned memoryIndex = 0; memoryIndex != 2; ++memoryIndex) {
                        uint64_t offset = memoryIndex * 8;
                        Value* pointer = builder.CreateGEP(builder.getInt8Ty(), load->getPointerOperand(), builder.getInt64(offset));
                        auto* part = builder.CreateLoad(builder.getInt64Ty(), pointer);
                        part->setAlignment(commonAlignment(load->getAlign(), offset));
                        part->setVolatile(load->isVolatile());
                        unsigned valueIndex = layout.isLittleEndian() ? memoryIndex : 1 - memoryIndex;
                        words[valueIndex] = part;
                    }
                    Value* low = builder.CreateZExt(words[0], load->getType());
                    Value* high = builder.CreateShl(builder.CreateZExt(words[1], load->getType()), 64);
                    load->replaceAllUsesWith(builder.CreateOr(low, high));
                    load->eraseFromParent();
                    continue;
                }
                Type* aggregate = load->getType();
                Value* value = PoisonValue::get(aggregate);
                for (unsigned index = 0; index != elementCount(aggregate); ++index) {
                    Type* partType = elementType(aggregate, index);
                    Value* pointer = builder.CreateConstInBoundsGEP2_32(aggregate, load->getPointerOperand(), 0, index);
                    auto* part = builder.CreateLoad(partType, pointer);
                    part->setAlignment(commonAlignment(load->getAlign(), elementOffset(layout, aggregate, index)));
                    part->setVolatile(load->isVolatile());
                    if (needsScalarMemory(partType)) {
                        work.push_back(part);
                    }
                    value = builder.CreateInsertValue(value, part, index);
                }
                load->replaceAllUsesWith(value);
                load->eraseFromParent();
                continue;
            }

            auto* store = cast<StoreInst>(instruction);
            if (store->getValueOperand()->getType()->isIntegerTy(128)) {
                Value* value = store->getValueOperand();
                Value* words[] = {
                    builder.CreateTrunc(value, builder.getInt64Ty()),
                    builder.CreateTrunc(builder.CreateLShr(value, 64), builder.getInt64Ty()),
                };
                for (unsigned memoryIndex = 0; memoryIndex != 2; ++memoryIndex) {
                    uint64_t offset = memoryIndex * 8;
                    Value* pointer = builder.CreateGEP(builder.getInt8Ty(), store->getPointerOperand(), builder.getInt64(offset));
                    unsigned valueIndex = layout.isLittleEndian() ? memoryIndex : 1 - memoryIndex;
                    auto* part = builder.CreateStore(words[valueIndex], pointer);
                    part->setAlignment(commonAlignment(store->getAlign(), offset));
                    part->setVolatile(store->isVolatile());
                }
                store->eraseFromParent();
                continue;
            }
            Type* aggregate = store->getValueOperand()->getType();
            for (unsigned index = 0; index != elementCount(aggregate); ++index) {
                Value* pointer = builder.CreateConstInBoundsGEP2_32(aggregate, store->getPointerOperand(), 0, index);
                Value* value = builder.CreateExtractValue(store->getValueOperand(), index);
                auto* part = builder.CreateStore(value, pointer);
                part->setAlignment(commonAlignment(store->getAlign(), elementOffset(layout, aggregate, index)));
                part->setVolatile(store->isVolatile());
                if (needsScalarMemory(value->getType())) {
                    work.push_back(part);
                }
            }
            store->eraseFromParent();
        }
        bpf::stats() << "bpf-scalarize-agg: " << work.size() << " wide memory operations scalarized\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

bool RegisterScalarizeAggPass(llvm::StringRef name, llvm::FunctionPassManager& manager) {
    if (name != "bpf-scalarize-agg") {
        return false;
    }
    manager.addPass(ScalarizeAggPass());
    return true;
}
