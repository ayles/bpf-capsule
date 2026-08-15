// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "target.h"

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>

#include <cstdlib>
#include <string>

using namespace llvm;

namespace {

cl::opt<std::string> TargetOpt("bpf-target", cl::desc("Oldest kernel the output must load on, as major.minor (e.g. 5.15)"), cl::init("5.15"));

cl::opt<unsigned> InlineOpt("bpf-inline-max", cl::desc("Largest function (in instructions) folded into its callers"), cl::init(0));

unsigned Choose(cl::opt<unsigned>& option, unsigned derived) {
    return option.getNumOccurrences() > 0 ? option.getValue() : derived;
}

} // namespace

namespace bpf {

unsigned Version() {
    // Parsed once, and loudly: a malformed value silently selecting some
    // default tier is a build failure waiting to happen much later.
    static unsigned cached = [] {
        const std::string& text = TargetOpt;
        char* end = nullptr;
        unsigned long major = std::strtoul(text.c_str(), &end, 10);
        bool ok = end != text.c_str() && *end == '.';
        unsigned long minor = ok ? std::strtoul(end + 1, &end, 10) : 0;
        if (!ok || *end != '\0' || major == 0 || minor >= 1000) {
            report_fatal_error(Twine("bpf-target: expected major.minor, got '") + text + "'");
        }
        unsigned version = unsigned(major * 1000 + minor);
        if (version < 5015) {
            report_fatal_error(Twine("bpf-target: Linux 5.15 is the oldest supported target; got '") + text + "'");
        }
        return version;
    }();
    return cached;
}

// ------------------------------------------------------------- features

bool HasArena() {
    return Version() >= 6009;
}

bool HasCpuV4() {
    return Version() >= 6006;
}

bool HasArenaSignedLoads() {
    // Before 7.0 the verifier rejects BPF_MEMSX from PTR_TO_ARENA on every
    // architecture, even when the JIT supports the instruction in general.
    // Linux 7.0 made this conditional on the target JIT's support.
    return Version() >= 7000;
}

bool HasInsnArrayJumpTables() {
    // LLVM 22 lowers wide switches to .jumptables indirect jumps, which need
    // insn-array-aware verification and libbpf relocation. No kernel/libbpf
    // pair this project targets loads that flow end to end: libbpf emits
    // .jumptables as an ordinary 16-byte data map and the verifier rejects
    // the table walk ("pointer += pointer") up to and including Linux 7.0.
    // Gate on a real version once some pair demonstrably loads it.
    return false;
}

// ------------------------------------------------------------- strategy

bool UseArena() {
    return HasArena();
}

bool LowerSignedDivision() {
    return !HasCpuV4();
}

bool LowerArenaSignedLoads() {
    return UseArena() && !HasArenaSignedLoads();
}

bool UseJumpTables() {
    return HasInsnArrayJumpTables();
}

bool InternalizeEarly() {
    // Not a kernel feature: without the arena every surviving function costs
    // frame space, so dead code has to actually die before -O2 groups things.
    return !UseArena();
}

unsigned MaxStepGroups() {
    // Leave room for the trampoline, heap accessors, soft-float leaves and
    // entry-independent runtime functions.  The 256-function kernel limit is
    // per loaded call graph. Keep enough headroom for workloads whose helper
    // count grows after the physical groups have been formed.
    return 180;
}

unsigned MaxInlinedInstructions() {
    // Stackify only folds single-use helpers, so this cap removes CPS
    // call/return overhead without duplicating IR. Multi-site source inlining
    // is deliberately excluded: it made QuickJS 48% larger and unloadable.
    return Choose(InlineOpt, 100);
}

unsigned DynamicAllocaBytes() {
    return 2048;
}

bool IsUnmanagedRuntime(llvm::StringRef name) {
    // Explicit compiler/runtime critical sections. Stackify validates their
    // complete post-optimization body before allowing an ordinary BPF call;
    // the prefix is internal ABI, not a user-facing name convention.
    if (name.starts_with("__bpf_capsule_nosuspend_")) {
        return true;
    }
    // The hot double ops: branch-light, one flat frame each, verified once as
    // global subprograms. Add/sub/mul/neg/cmp dominate real arithmetic. Kept
    // out: the conversions and the f32 family (each inlines two normalizing
    // compare ladders, which multiply verifier paths when checked against
    // unknown arguments). Division now uses a genuinely branchless borrow
    // mask, so its 56-iteration loop is also linear for the verifier and can
    // avoid a managed suspend/dispatch/resume on every divide. Remainder and
    // the conversion-heavy wrappers stay managed.
    static const char* const kNames[] = {
        "__bpf_dadd",
        "__bpf_dsub",
        "__bpf_dmul",
        "__bpf_ddiv",
        "__bpf_dneg",
        "__bpf_dcmp",
    };
    for (const char* candidate : kNames) {
        if (name == candidate) {
            return true;
        }
    }
    return false;
}

} // namespace bpf
