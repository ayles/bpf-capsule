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

bool containsSysroot(const std::filesystem::path& path) {
    return std::filesystem::is_regular_file(path / "usr" / "include" / "picolibc.h");
}

std::filesystem::path findExecutable(const char* argv0) {
    auto resolved = [](const std::filesystem::path& path) {
        std::error_code error;
        std::filesystem::path absolute = std::filesystem::absolute(path, error);
        if (error) {
            return std::filesystem::path{};
        }
        std::filesystem::path canonical = std::filesystem::canonical(absolute, error);
        return error ? absolute : canonical;
    };
    std::filesystem::path proc = resolved("/proc/self/exe");
    if (!proc.empty() && executable(proc.string())) {
        return proc;
    }
    std::filesystem::path candidate(argv0);
    if (candidate.has_parent_path()) {
        return resolved(candidate);
    }
    if (const char* path = getenv("PATH")) {
        std::string paths(path);
        for (size_t begin = 0; begin <= paths.size();) {
            size_t end = paths.find(':', begin);
            std::filesystem::path directory = paths.substr(begin, end - begin);
            candidate = (directory.empty() ? std::filesystem::path(".") : directory) / argv0;
            if (executable(candidate.string())) {
                return resolved(candidate);
            }
            if (end == std::string::npos) {
                break;
            }
            begin = end + 1;
        }
    }
    return {};
}

std::pair<std::string, std::string> findIncludeDirs(const std::filesystem::path& executablePath) {
    if (const char* env = getenv("BPF_CAPSULE_INCLUDE_DIR"); env && containsHeaders(env, std::filesystem::path(env) / "internal")) {
        return {env, (std::filesystem::path(env) / "internal").string()};
    }
    if (!executablePath.empty()) {
        std::filesystem::path installed = executablePath.parent_path().parent_path() / "include" / "bpf-capsule";
        if (containsHeaders(installed, installed / "internal")) {
            return {installed.string(), (installed / "internal").string()};
        }
    }
    if (containsHeaders(BPF_CAPSULE_SOURCE_GUEST_INCLUDE_DIR, BPF_CAPSULE_SOURCE_INTERNAL_INCLUDE_DIR)) {
        return {BPF_CAPSULE_SOURCE_GUEST_INCLUDE_DIR, BPF_CAPSULE_SOURCE_INTERNAL_INCLUDE_DIR};
    }
    fprintf(stderr, "bpf-capsule-cc: cannot find runtime headers; set BPF_CAPSULE_INCLUDE_DIR to the installed bpf-capsule include directory\n");
    exit(1);
}

std::string findSysroot(const std::filesystem::path& executablePath) {
    if (const char* env = getenv("BPF_CAPSULE_SYSROOT"); env && containsSysroot(env)) {
        return env;
    }
    if (!executablePath.empty()) {
        std::filesystem::path installed = executablePath.parent_path().parent_path() / "share" / "bpf-capsule" / "sysroot";
        if (containsSysroot(installed)) {
            return installed.string();
        }
    }
    if (containsSysroot(BPF_CAPSULE_SOURCE_GUEST_SYSROOT)) {
        return BPF_CAPSULE_SOURCE_GUEST_SYSROOT;
    }
    // Building Picolibc itself is the one valid sysroot-free invocation: its
    // build supplies the C library's source and generated include directories.
    return {};
}

} // namespace

int main(int argc, char** argv) {
    std::filesystem::path executablePath = findExecutable(argv[0]);
    auto [guestInclude, internalInclude] = findIncludeDirs(executablePath);
    std::string sysroot = findSysroot(executablePath);
    std::vector<std::string> args = {
        findClang(),
        "-target",
        "bpfel",
        // Capsule programs have a C library, but no hosted implementation.
        // Besides defining __STDC_HOSTED__ correctly, this keeps libc calls
        // as linkable calls instead of letting LLVM duplicate their bodies as
        // builtins before managed-memory lowering.
        "-ffreestanding",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fno-unroll-loops",
        // Picolibc's target headers need these two BPF ABI facts: IEEE words
        // are little-endian and long double has the same binary64 layout as
        // double. Clang's BPF target does not publish either spelling.
        "-D__IEEE_LITTLE_ENDIAN",
        "-D_LDBL_EQ_DBL",
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
    if (!sysroot.empty()) {
        args.push_back("--sysroot=" + sysroot);
        // The generic BPF Clang driver searches its resource headers before
        // a sysroot. In freestanding mode that would select Clang's standalone
        // stdint.h instead of Picolibc's, while inttypes.h still came from
        // Picolibc. Put the C library include directory first, as a normal
        // target-aware cross driver would.
        args.push_back("-isystem" + (std::filesystem::path(sysroot) / "usr" / "include").string());
    }
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
