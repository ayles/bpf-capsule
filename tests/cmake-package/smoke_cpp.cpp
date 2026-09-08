// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "smoke_library.h"

#ifndef SMOKE_LIBRARY_PRIVATE
#error "private library definition did not reach the library"
#endif
namespace {

class Mixer {
public:
    constexpr explicit Mixer(int seed)
        : seed_(seed) {
    }

    int apply(int value) const {
        return value * 17 + seed_;
    }

private:
    int seed_;
};

} // namespace

extern "C" __attribute__((noinline)) int smoke_cpp_mix(int value) {
    return Mixer(smoke_seed()).apply(value);
}
