// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

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
    return Mixer(23).apply(value);
}
