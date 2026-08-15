// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#pragma once

#include "bpf_capsule_abi.h"

enum sqlite_stage {
    SQLITE_STAGE_STARTED = 1,
    SQLITE_STAGE_HEAP_CONFIGURED,
    SQLITE_STAGE_INITIALIZED,
    SQLITE_STAGE_DATABASE_OPEN,
    SQLITE_STAGE_TABLE_CREATED,
    SQLITE_STAGE_ROWS_INSERTED,
    SQLITE_STAGE_QUERIES_COMPLETE,
    SQLITE_STAGE_COMPLETE,
};

struct sqlite_bpf_ctrl {
    uint64_t status; // step reached, or SQLite error
    uint64_t rows;   // rows seen by the select callback
    uint64_t sum;    // checksum over selected values
    struct capsule_result capsule;
    uint64_t sqlite_rc;
    uint64_t sqlite_error0, sqlite_error1;
};
