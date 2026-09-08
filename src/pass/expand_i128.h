// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/PassManager.h>
#include <string>
#include <vector>

std::vector<std::string> RequiredIntegerLibcalls(const llvm::Module& module);

bool RegisterExpandI128Pass(llvm::StringRef name, llvm::ModulePassManager& manager);
