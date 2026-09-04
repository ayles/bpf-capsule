// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// bpf-capsule-cc: optional convenience front end. It is clang with the
// capsule guest flags baked in, nothing more:
//
//   bpf-capsule-cc -c guest.c -o guest.bc [-I... -D... anything clang takes]
//
// The output is LLVM bitcode for bpf-capsule-ld. Projects with their own
// toolchain (cargo for Rust guests, a build system invoking clang directly)
// can skip this wrapper as long as they produce BPF-target bitcode with
// -O2 -Xclang -disable-llvm-passes. C and C++ toolchains must also
// force-include bpf_capsule_varargs.h so aggregate va_arg retains its size and
// alignment until stackify.
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

} // namespace

int main(int argc, char** argv) {
    auto [guestInclude, internalInclude] = findIncludeDirs();
    std::vector<std::string> args = {
        findClang(),
        "-target",
        "bpf",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fno-unroll-loops",
        // Codegen-quality IR without running the generic pipeline here; all
        // optimization happens whole-program inside bpf-capsule-ld.
        "-O2",
        "-Xclang",
        "-disable-llvm-passes",
        "-emit-llvm",
        // Public guest headers plus private runtime/compiler contracts.
        "-I" + guestInclude,
        "-I" + internalInclude,
        "-include",
        "bpf_capsule_varargs.h",
    };
    for (int i = 1; i < argc; ++i) {
        args.push_back(argv[i]);
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
