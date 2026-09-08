// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#define SMOKE_SEED 23

#ifdef __cplusplus
extern "C" {
#endif

int smoke_seed(void);
int smoke_cpp_mix(int value);

#ifdef __cplusplus
}
#endif
