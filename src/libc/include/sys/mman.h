// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#include <stddef.h>
#define PROT_READ 1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void*)-1)
void* mmap(void* addr, unsigned long len, int prot, int flags, int fd, long off);
int munmap(void* addr, unsigned long len);
