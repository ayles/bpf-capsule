// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#define O_RDONLY 0
int open(const char* path, int flags, ...);
