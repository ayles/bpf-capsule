// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

// eBPF has no hardware floating-point environment. This header intentionally
// provides no fenv API; it keeps otherwise-portable sources that merely include
// <fenv.h> from falling through to incompatible host-libc headers.
