// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>

bool RegisterExpandI128Pass(llvm::StringRef name, llvm::ModulePassManager& manager);
