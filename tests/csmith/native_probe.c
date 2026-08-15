// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdint.h>
#include "csmith_include.h"

#include <stdio.h>

int main(void) {
    crc32_context = 0;
    (void)csmith_generated_main();
    printf("%llx\n", (uint64_t)crc32_context);
    return 0;
}
