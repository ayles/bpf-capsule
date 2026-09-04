// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <stdio.h>
#include <setjmp.h>
#include <limits.h>
#include <asm/bitsperlong.h>
#include <linux/bpf.h>
#include <sys/mman.h>

_Static_assert(sizeof(jmp_buf) == 4 * sizeof(unsigned long long), "installed sysroot did not select the Capsule setjmp ABI");
_Static_assert(__BITS_PER_LONG == sizeof(long) * CHAR_BIT, "installed UAPI uses the wrong target word size");

int sysroot_contract(FILE* stream, union bpf_attr* attribute) {
    return stream != 0 && attribute != 0 && MAP_ANONYMOUS != 0;
}
