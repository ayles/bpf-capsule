// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Host-runtime contracts that need no kernel: the drive loop's status/errno
// mapping (through an interposed bpf_prog_test_run_opts), the error/status
// string tables, the capsule_result ABI, and the pre-load configuration
// planner. This binary deliberately never loads BPF, because the interposed
// symbol below preempts the real libbpf entry point for the whole link unit.
#include "capsule_gtest.h"

#include "bpf_capsule_host.h"
#include "bpf_capsule_abi.h"

#include <string.h>

// Private implementation seams exercised only by this contract test. They
// are deliberately absent from the installed loader API.
extern "C" int __bpf_capsule_plan(
    struct __bpf_capsule_object_config* config, size_t config_size, struct bpf_capsule_config requested, uint32_t* backend_entries);
extern "C" int __bpf_capsule_copy_plan(
    const void* config_data, size_t config_size, struct bpf_capsule_config requested, struct __bpf_capsule_object_config* planned, uint32_t* backend_entries);

namespace {

struct scripted_step {
    enum capsule_status status;
    int64_t code;
    int syscall_errno;
    int retval;
};

volatile struct capsule_result g_result;
const scripted_step* g_script;
size_t g_script_size;
size_t g_script_index;

} // namespace

// Interpose the libbpf entry point so capsule_test_drive can be exercised
// against a scripted kernel.
extern "C" int bpf_prog_test_run_opts(int program_fd, struct bpf_test_run_opts* options) {
    (void)program_fd;
    if (g_script_index >= g_script_size) {
        errno = ENODATA;
        return -1;
    }
    const scripted_step* step = &g_script[g_script_index++];
    g_result.status = step->status;
    g_result.code = step->code;
    options->retval = (unsigned int)step->retval;
    if (step->syscall_errno) {
        errno = step->syscall_errno;
        return -1;
    }
    return 0;
}

namespace {

void check_run(const char* name, const scripted_step* steps, size_t count, unsigned long max_drains, int expected_return, int expected_errno,
    unsigned long expected_entries, unsigned long expected_drains, unsigned int expected_status, int64_t expected_code) {
    SCOPED_TRACE(name);
    g_result.status = CAPSULE_OK;
    g_result.code = 0;
    g_result.continuation = 0;
    g_script = steps;
    g_script_size = count;
    g_script_index = 0;
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    unsigned long entries = 0;
    unsigned long drains = 0;
    errno = 0;
    int actual_return = capsule_test_drive(10, 11, &options, max_drains, &entries, &drains, &g_result);
    int actual_errno = errno;
    EXPECT_EQ(actual_return, expected_return);
    EXPECT_EQ(actual_errno, expected_errno);
    EXPECT_EQ(entries, expected_entries);
    EXPECT_EQ(drains, expected_drains);
    EXPECT_EQ(g_script_index, count) << "drive consumed the wrong number of scripted invocations";
    EXPECT_EQ(g_result.status, expected_status);
    EXPECT_EQ(g_result.code, expected_code);
}

TEST(DriveContract, StatusAndErrnoMapping) {
    static const scripted_step ok[] = {{CAPSULE_OK, 0, 0, 0}};
    static const scripted_step pending_ok[] = {{CAPSULE_PENDING, 0, 0, 0}, {CAPSULE_OK, 0, 0, 0}};
    static const scripted_step failed[] = {{CAPSULE_EXITED, CAPSULE_ERROR_TRAP, 0, 0}};
    static const scripted_step pending_failed[] = {{CAPSULE_PENDING, 0, 0, 0}, {CAPSULE_EXITED, CAPSULE_ERROR_MEMORY_FAULT, 0, 0}};
    static const scripted_step yielded[] = {{CAPSULE_YIELD, 0, 0, 0}};
    static const scripted_step exited[] = {{CAPSULE_EXITED, 37, 0, 0}};
    static const scripted_step unknown[] = {{(enum capsule_status)99, 0, 0, 0}};
    static const scripted_step syscall_failed[] = {{CAPSULE_OK, 0, EBADF, 0}};
    static const scripted_step program_failed[] = {{CAPSULE_OK, 0, 0, -E2BIG}};
    static const scripted_step timed_out[] = {{CAPSULE_PENDING, 0, 0, 0}};

    check_run("ok", ok, 1, 1, 0, 0, 1, 0, CAPSULE_OK, 0);
    check_run("pending-ok", pending_ok, 2, 1, 0, 0, 1, 1, CAPSULE_OK, 0);
    check_run("framework-exit", failed, 1, 1, -1, ECANCELED, 1, 0, CAPSULE_EXITED, CAPSULE_ERROR_TRAP);
    check_run("pending-framework-exit", pending_failed, 2, 1, -1, ECANCELED, 1, 1, CAPSULE_EXITED, CAPSULE_ERROR_MEMORY_FAULT);
    check_run("yield", yielded, 1, 1, -1, EINPROGRESS, 1, 0, CAPSULE_YIELD, 0);
    check_run("guest-exit", exited, 1, 1, 0, 0, 1, 0, CAPSULE_EXITED, 37);
    check_run("unknown", unknown, 1, 1, -1, EPROTO, 1, 0, 99, 0);
    check_run("syscall", syscall_failed, 1, 1, -1, EBADF, 1, 0, CAPSULE_OK, 0);
    check_run("program", program_failed, 1, 1, -1, E2BIG, 1, 0, CAPSULE_OK, 0);
    check_run("timeout", timed_out, 1, 0, -1, ETIMEDOUT, 1, 0, CAPSULE_PENDING, 0);
    // Timeout must preserve the pending result rather than clobber it.
    EXPECT_EQ(g_result.status, (unsigned)CAPSULE_PENDING);
}

TEST(DriveContract, InvalidArguments) {
    struct bpf_test_run_opts options = {};
    options.sz = sizeof(options);
    errno = 0;
    EXPECT_EQ(capsule_test_drive(10, 11, nullptr, 1, nullptr, nullptr, &g_result), -1);
    EXPECT_EQ(errno, EINVAL);
    errno = 0;
    EXPECT_EQ(capsule_test_drive(10, 11, &options, 1, nullptr, nullptr, nullptr), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST(ErrorStrings, StatusNames) {
    EXPECT_STREQ(bpf_capsule_status_string(CAPSULE_OK), "ok");
    EXPECT_STREQ(bpf_capsule_status_string(CAPSULE_PENDING), "pending");
    EXPECT_STREQ(bpf_capsule_status_string(CAPSULE_YIELD), "yield");
    EXPECT_STREQ(bpf_capsule_status_string(CAPSULE_EXITED), "exited");
    EXPECT_STREQ(bpf_capsule_status_string(99), "unknown status");
}

TEST(ErrorStrings, CodeNames) {
    struct named_code {
        int64_t value;
        const char* name;
    };
    static const named_code codes[] = {
        {CAPSULE_ERROR_POOL_EXHAUSTED, "fiber pool exhausted"},
        {CAPSULE_ERROR_INVALID_CONTINUATION, "invalid continuation"},
        {CAPSULE_ERROR_STALE_CONTINUATION, "stale continuation"},
        {CAPSULE_ERROR_NOT_PENDING, "continuation is not pending"},
        {CAPSULE_ERROR_POOL_CORRUPT, "fiber pool corrupt"},
        {CAPSULE_ERROR_RETURN_MISMATCH, "return value layout mismatch"},
        {CAPSULE_ERROR_STACK_OVERFLOW, "fiber stack overflow"},
        {CAPSULE_ERROR_MEMORY_FAULT, "capsule memory fault"},
        {CAPSULE_ERROR_INVALID_DISPATCH, "invalid managed dispatch"},
        {CAPSULE_ERROR_INTRINSIC_GUARD, "unlowered compiler intrinsic"},
        {CAPSULE_ERROR_UNREACHABLE, "unreachable code executed"},
        {CAPSULE_ERROR_TRAP, "trap executed"},
        {CAPSULE_ERROR_ALLOCATOR_CORRUPT, "allocator state corrupt"},
        {CAPSULE_ERROR_BAD_PLAN, "loader applied an incomplete configuration plan"},
        // Non-negative codes are the guest's own exit statuses.
        {0, "guest exit status"},
        {1, "guest exit status"},
        {255, "guest exit status"},
        {0x123456789abcdefll, "guest exit status"},
        // Negative codes outside the defined set are unknown framework codes.
        {-9999, "unknown framework code"},
        {(int64_t)0x8000000000000000ull, "unknown framework code"},
    };
    for (const named_code& code : codes) {
        EXPECT_STREQ(bpf_capsule_error_string(code.value), code.name) << "code " << code.value;
    }
}

TEST(HostAbi, CapsuleResultLayout) {
    struct capsule_result exited = {};
    exited.code = -37;
    exited.status = CAPSULE_EXITED;
    exited.continuation = BPF_CAPSULE_NO_CONTINUATION;
    EXPECT_EQ(exited.code, -37);
    EXPECT_EQ(exited.continuation, BPF_CAPSULE_NO_CONTINUATION);
    EXPECT_EQ(sizeof(exited), 16u);
}

TEST(HostLifetime, EmptyAndRepeatedRelease) {
    struct bpf_capsule capsule = {};
    EXPECT_EQ(bpf_capsule_release(&capsule), 0);
    EXPECT_EQ(bpf_capsule_release(&capsule), 0);

    errno = 0;
    EXPECT_EQ(bpf_capsule_initialize(&capsule), -1);
    EXPECT_EQ(errno, EINVAL);
    unsigned char byte = 0;
    errno = 0;
    EXPECT_EQ(bpf_capsule_memcpy(&capsule, &byte, &byte, 1), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(bpf_capsule_memory_start(&capsule), nullptr);
    EXPECT_EQ(bpf_capsule_memory_size(&capsule), 0u);
}

TEST(HostAbi, ConfigurationPlanner) {
    struct __bpf_capsule_object_config config = {};
    config.heap_base = 0x10000;
    config.heap_bytes = 0x100000;
    config.fiber_count = 1;
    config.stack_bytes_per_fiber = 0x40000;
    config.max_fibers = 4;
    config.arena_image_pages = 1;
    config.abi_magic = BPF_CAPSULE_ABI_MAGIC;
    config.abi_version = BPF_CAPSULE_ABI_VERSION;

    uint32_t entries = 0;
    struct bpf_capsule_config requested = {};
    requested.fiber_count = 2;
    requested.heap_bytes = 0x200000;
    requested.reserved_bytes = 17;

    // A short config record must be rejected without touching the output.
    unsigned char short_config[sizeof(config) - 1] = {0};
    struct __bpf_capsule_object_config untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    struct __bpf_capsule_object_config before = untouched;
    errno = 0;
    EXPECT_NE(__bpf_capsule_copy_plan(short_config, sizeof(short_config), requested, &untouched, &entries), 0);
    EXPECT_EQ(errno, ENOENT);
    EXPECT_EQ(memcmp(&untouched, &before, sizeof(untouched)), 0);

    struct __bpf_capsule_object_config malformed = config;
    malformed.heap_base = 0;
    errno = 0;
    EXPECT_NE(__bpf_capsule_plan(&malformed, sizeof(malformed), requested, &entries), 0);
    EXPECT_EQ(errno, EINVAL) << "logical page zero is reserved for null";

    malformed = config;
    malformed.stack_bytes_per_fiber = 3000;
    errno = 0;
    EXPECT_NE(__bpf_capsule_plan(&malformed, sizeof(malformed), requested, &entries), 0);
    EXPECT_EQ(errno, EINVAL) << "the fiber-stack ABI requires a bounded power of two";

    EXPECT_EQ(__bpf_capsule_plan(&config, sizeof(config), requested, &entries), 0);
    EXPECT_EQ(config.fiber_count, 2u);
    EXPECT_EQ(config.heap_reserved, 32u) << "reserved bytes are aligned up";
    EXPECT_NE(entries, 0u);

    // The exclusive end of data must fit in the 32-bit ABI field. Exactly
    // 4 GiB used to pass the arithmetic and narrow memory_end to zero.
    struct __bpf_capsule_object_config full = {};
    full.heap_base = 0x10000;
    full.heap_bytes = 0xffdf0000;
    full.fiber_count = 1;
    full.stack_bytes_per_fiber = 0x40000;
    full.max_fibers = 8;
    full.arena_image_pages = 1;
    full.abi_magic = BPF_CAPSULE_ABI_MAGIC;
    full.abi_version = BPF_CAPSULE_ABI_VERSION;
    struct bpf_capsule_config fills_address_space = {};
    fills_address_space.fiber_count = 8;
    fills_address_space.heap_bytes = full.heap_bytes;
    errno = 0;
    EXPECT_NE(__bpf_capsule_plan(&full, sizeof(full), fills_address_space, &entries), 0);
    EXPECT_EQ(errno, EOVERFLOW);

    config.abi_version++;
    errno = 0;
    EXPECT_NE(__bpf_capsule_plan(&config, sizeof(config), requested, &entries), 0);
    EXPECT_EQ(errno, EINVAL);
}

} // namespace
