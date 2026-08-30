// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "target.h"

using namespace llvm;

namespace bpf {

uint64_t TransientReserveBytes(uint64_t fiberStackBytes) {
    return fiberStackBytes / 2;
}

} // namespace bpf
