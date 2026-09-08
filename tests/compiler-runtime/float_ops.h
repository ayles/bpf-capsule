// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once
#include <stdint.h>

enum float_operation {
    DADD,
    DSUB,
    DMUL,
    DDIV,
    DREM,
    DCMP,
    DNEG,
    I2D,
    U2D,
    D2I,
    D2U,
    F2D,
    D2F,
    FADD,
    FSUB,
    FMUL,
    FDIV,
    FREM,
    FCMP,
    FNEG,
    I2F,
    U2F,
    F2I,
    F2U,
    FLOAT_OPERATION_COUNT
};

struct float_case {
    uint64_t a, b, integer;
    uint32_t fa, fb;
    uint64_t result[FLOAT_OPERATION_COUNT];
};

#ifdef __cplusplus
extern "C" {
#endif
void float_evaluate(struct float_case* test);
#ifdef __cplusplus
}
#endif
