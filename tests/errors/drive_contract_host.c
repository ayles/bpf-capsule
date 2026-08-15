// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bpf_capsule_host.h"

#include "../support/capsule_test.h"

struct scripted_step {
    unsigned int status;
    int64_t code;
    int syscall_errno;
    int retval;
};

static volatile struct capsule_result result;
static const struct scripted_step* script;
static size_t script_size;
static size_t script_index;

// This executable deliberately interposes the libbpf entry point so the host
// helper can be tested without loading BPF. The test target links shared
// libbpf; a future static-libbpf build must keep this mock in a separate link
// unit rather than pulling in libbpf's duplicate definition.
int bpf_prog_test_run_opts(int program_fd, struct bpf_test_run_opts* options) {
    (void)program_fd;
    if (script_index >= script_size) {
        errno = ENODATA;
        return -1;
    }
    const struct scripted_step* step = &script[script_index++];
    result.status = step->status;
    result.code = step->code;
    options->retval = (unsigned int)step->retval;
    if (step->syscall_errno) {
        errno = step->syscall_errno;
        return -1;
    }
    return 0;
}

static int check_run(
    const char* name, const struct scripted_step* steps, size_t count, unsigned long max_drains, int expected_return, int expected_errno,
    unsigned long expected_entries, unsigned long expected_drains, unsigned int expected_status, int64_t expected_code
) {
    result = (struct capsule_result){0};
    script = steps;
    script_size = count;
    script_index = 0;
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    unsigned long entries = 0;
    unsigned long drains = 0;
    errno = 0;
    int actual_return = capsule_test_drive(10, 11, &options, max_drains, &entries, &drains, &result);
    int actual_errno = errno;
    if (actual_return != expected_return || actual_errno != expected_errno || entries != expected_entries || drains != expected_drains ||
        script_index != count || result.status != expected_status || result.code != expected_code) {
        fprintf(
            stderr,
            "%s: return=%d/%d errno=%d/%d entries=%lu/%lu "
            "drains=%lu/%lu steps=%zu/%zu status=%u/%u code=%lld/%lld\n",
            name, actual_return, expected_return, actual_errno, expected_errno, entries, expected_entries, drains, expected_drains, script_index, count,
            result.status, expected_status, (long long)result.code, (long long)expected_code
        );
        return -1;
    }
    return 0;
}

static int check_invalid_arguments(void) {
    struct bpf_test_run_opts options = {.sz = sizeof(options)};
    errno = 0;
    if (capsule_test_drive(10, 11, NULL, 1, NULL, NULL, &result) != -1 || errno != EINVAL) {
        fprintf(stderr, "null options did not report EINVAL\n");
        return -1;
    }
    errno = 0;
    if (capsule_test_drive(10, 11, &options, 1, NULL, NULL, NULL) != -1 || errno != EINVAL) {
        fprintf(stderr, "null result did not report EINVAL\n");
        return -1;
    }
    return 0;
}

int main(void) {
    static const struct scripted_step ok[] = {{.status = CAPSULE_OK}};
    static const struct scripted_step pending_ok[] = {
        {.status = CAPSULE_PENDING},
        {.status = CAPSULE_OK},
    };
    static const struct scripted_step failed[] = {{.status = CAPSULE_EXITED, .code = CAPSULE_ERROR_TRAP}};
    static const struct scripted_step pending_failed[] = {
        {.status = CAPSULE_PENDING},
        {.status = CAPSULE_EXITED, .code = CAPSULE_ERROR_MEMORY_FAULT},
    };
    static const struct scripted_step yielded[] = {{.status = CAPSULE_YIELD}};
    static const struct scripted_step exited[] = {{.status = CAPSULE_EXITED, .code = 37}};
    static const struct scripted_step unknown[] = {{.status = 99}};
    static const struct scripted_step syscall_failed[] = {{.syscall_errno = EBADF}};
    static const struct scripted_step program_failed[] = {{.retval = -E2BIG}};
    static const struct scripted_step timed_out[] = {{.status = CAPSULE_PENDING}};

    int failed_contract = check_run("ok", ok, 1, 1, 0, 0, 1, 0, CAPSULE_OK, 0) || check_run("pending-ok", pending_ok, 2, 1, 0, 0, 1, 1, CAPSULE_OK, 0) ||
        check_run("framework-exit", failed, 1, 1, -1, ECANCELED, 1, 0, CAPSULE_EXITED, CAPSULE_ERROR_TRAP) ||
        check_run("pending-framework-exit", pending_failed, 2, 1, -1, ECANCELED, 1, 1, CAPSULE_EXITED, CAPSULE_ERROR_MEMORY_FAULT) ||
        check_run("yield", yielded, 1, 1, -1, EINPROGRESS, 1, 0, CAPSULE_YIELD, 0) || check_run("guest-exit", exited, 1, 1, 0, 0, 1, 0, CAPSULE_EXITED, 37) ||
        check_run("unknown", unknown, 1, 1, -1, EPROTO, 1, 0, 99, 0) || check_run("syscall", syscall_failed, 1, 1, -1, EBADF, 1, 0, CAPSULE_OK, 0) ||
        check_run("program", program_failed, 1, 1, -1, E2BIG, 1, 0, CAPSULE_OK, 0) ||
        check_run("timeout", timed_out, 1, 0, -1, ETIMEDOUT, 1, 0, CAPSULE_PENDING, 0) || check_invalid_arguments();
    if (failed_contract) {
        return 1;
    }
    if (result.status != CAPSULE_PENDING) {
        fprintf(stderr, "timeout did not preserve the pending result\n");
        return 1;
    }
    puts("DRIVE-CONTRACT-PASS");
    return 0;
}
