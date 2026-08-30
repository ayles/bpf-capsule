// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "csmith_include.h"

#include <stdint.h>

uint64_t csmith_native_checksum(void) {
    crc32_context = 0;
    (void)csmith_generated_main();
    return crc32_context;
}
