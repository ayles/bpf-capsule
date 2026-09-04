// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

// Linux architecture headers key this value off architecture macros that the
// generic BPF target deliberately does not define.
#define __BITS_PER_LONG (__CHAR_BIT__ * __SIZEOF_LONG__)
