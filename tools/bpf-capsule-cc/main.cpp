// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-capsule-cc: optional convenience front end. It is clang with the
// capsule guest flags baked in, nothing more:
//
//   bpf-capsule-cc [--kernel 6.9] -c guest.c -o guest.bc [-I... -D... anything clang takes]
//
// The output is LLVM bitcode for bpf-capsule-ld. Projects with their own
// toolchain (cargo for Rust guests, a build system invoking clang directly)
// can skip this wrapper as long as they produce BPF-target bitcode with
// -O2 -Xclang -disable-llvm-passes and matching capsule defines. C and C++
// toolchains must also force-include bpf_capsule_varargs.h so aggregate
// va_arg retains its size and alignment until stackify.
//
// --kernel must match the value later given to bpf-capsule-ld: this wrapper
// turns it into the BPF_CAPSULE_FEATURE_* defines the runtime and libc
// sources gate on, and the linker turns it into the pass pipeline.
//
// Clang is found through $BPF_CAPSULE_CLANG, then the path baked in at build
// time, then PATH.
#include "tool_config.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

bool executable(const std::string& path) {
    return !path.empty() && access(path.c_str(), X_OK) == 0;
}

std::string findClang() {
    if (const char* env = getenv("BPF_CAPSULE_CLANG"); env && executable(env)) {
        return env;
    }
    if (executable(BPF_CAPSULE_DEFAULT_CLANG)) {
        return BPF_CAPSULE_DEFAULT_CLANG;
    }
    return "clang"; // resolved via PATH by execvp
}

bool containsHeaders(const std::filesystem::path& guest, const std::filesystem::path& internal) {
    return std::filesystem::is_regular_file(guest / "bpf_capsule.h") && std::filesystem::is_regular_file(internal / "bpf_capsule_abi.h");
}

std::pair<std::string, std::string> findIncludeDirs() {
    if (const char* env = getenv("BPF_CAPSULE_INCLUDE_DIR"); env && containsHeaders(env, std::filesystem::path(env) / "internal")) {
        return {env, (std::filesystem::path(env) / "internal").string()};
    }
    if (containsHeaders(BPF_CAPSULE_SOURCE_GUEST_INCLUDE_DIR, BPF_CAPSULE_SOURCE_INTERNAL_INCLUDE_DIR)) {
        return {BPF_CAPSULE_SOURCE_GUEST_INCLUDE_DIR, BPF_CAPSULE_SOURCE_INTERNAL_INCLUDE_DIR};
    }

    std::error_code error;
    std::filesystem::path executablePath = std::filesystem::canonical("/proc/self/exe", error);
    if (!error) {
        std::filesystem::path installed = executablePath.parent_path().parent_path() / "include" / "bpf-capsule";
        if (containsHeaders(installed, installed / "internal")) {
            return {installed.string(), (installed / "internal").string()};
        }
    }
    fprintf(stderr, "bpf-capsule-cc: cannot find runtime headers; set BPF_CAPSULE_INCLUDE_DIR to the installed bpf-capsule include directory\n");
    exit(1);
}

// This tool (with bpf-capsule-ld) is where kernel versions exist. --kernel
// is converted right here into BPF_CAPSULE_FEATURE_* preprocessor defines;
// the C sources gate on features, never on versions.
struct KernelVersion {
    unsigned Major = 0;
    unsigned Minor = 0;
    friend auto operator<=>(const KernelVersion&, const KernelVersion&) = default;
};

constexpr unsigned MaxFiberStackBytes = 2u * 1024u * 1024u;

KernelVersion parseKernel(const char* text) {
    KernelVersion version;
    char trailing;
    if (sscanf(text, "%u.%u%c", &version.Major, &version.Minor, &trailing) != 2 || version.Minor >= 1000 || version < KernelVersion{5, 15}) {
        fprintf(stderr, "bpf-capsule-cc: --kernel must be Linux 5.15 or newer, got '%s'\n", text);
        exit(1);
    }
    return version;
}

unsigned parseFiberStack(const char* text) {
    errno = 0;
    char* end = nullptr;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || end == text || *end || value < 1 || value > MaxFiberStackBytes || (value & (value - 1))) {
        fprintf(stderr, "bpf-capsule-cc: --fiber-stack must be a power of two from 1 to %u, got '%s'\n", MaxFiberStackBytes, text);
        exit(1);
    }
    return (unsigned)value;
}

} // namespace

int main(int argc, char** argv) {
    KernelVersion kernel{6, 9};
    unsigned fiberStack = 262144;
    std::vector<const char*> passthrough;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--kernel")) {
            if (++i == argc) {
                fprintf(stderr, "bpf-capsule-cc: --kernel requires a value\n");
                return 1;
            }
            kernel = parseKernel(argv[i]);
        } else if (!strncmp(argv[i], "--kernel=", 9)) {
            kernel = parseKernel(argv[i] + 9);
        } else if (!strcmp(argv[i], "--fiber-stack")) {
            if (++i == argc) {
                fprintf(stderr, "bpf-capsule-cc: --fiber-stack requires a value\n");
                return 1;
            }
            fiberStack = parseFiberStack(argv[i]);
        } else if (!strncmp(argv[i], "--fiber-stack=", 14)) {
            fiberStack = parseFiberStack(argv[i] + 14);
        } else {
            passthrough.push_back(argv[i]);
        }
    }
    auto [guestInclude, internalInclude] = findIncludeDirs();
    std::vector<std::string> args = {
        findClang(),
        "-target",
        "bpf",
        // cpu selection only affects predefines at the clang stage; the
        // linker owns the real -mcpu at code generation.
        kernel >= KernelVersion{6, 6} ? "-mcpu=v4" : "-mcpu=v3",
        "-DBPF_CAPSULE_FIBER_STACK_BYTES=" + std::to_string(fiberStack),
        "-nostdlib",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fno-unroll-loops",
        "-Wno-option-ignored",
        "-Wno-unused-command-line-argument",
        "-Wno-deprecated-non-prototype",
        // Codegen-quality IR without running the generic pipeline here; all
        // optimization happens whole-program inside bpf-capsule-ld.
        "-O2",
        "-Xclang",
        "-disable-llvm-passes",
        "-mllvm",
        "-bpf-stack-size=512",
        "-emit-llvm",
        // Public guest headers plus private runtime/compiler contracts.
        "-I" + guestInclude,
        "-I" + internalInclude,
        "-include",
        "bpf_capsule_varargs.h",
    };
    if (kernel >= KernelVersion{6, 9}) {
        args.insert(args.begin() + 3, "-DBPF_CAPSULE_FEATURE_ARENA=1");
        args.insert(args.begin() + 3, "-DBPF_CAPSULE_FEATURE_FULL_ATOMICS=1");
    }
    for (const char* arg : passthrough) {
        args.push_back(arg);
    }

    std::vector<char*> execArgs;
    execArgs.reserve(args.size() + 1);
    for (std::string& arg : args) {
        execArgs.push_back(arg.data());
    }
    execArgs.push_back(nullptr);
    execvp(execArgs[0], execArgs.data());
    fprintf(stderr, "bpf-capsule-cc: cannot execute %s: %s\n", execArgs[0], strerror(errno));
    return 1;
}
