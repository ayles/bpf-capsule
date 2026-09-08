# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Three equal loops compete for capacity that admits only two baseline chunks.
# z_loop has eight call sites and takes priority over the one-call loops.
# Their tie is stable: a_loop gets the remaining chunk, b_loop stays virtualized.
file(MAKE_DIRECTORY "${WORK}")
execute_process(
    COMMAND
        "${BPF_CAPSULE_LD}" --passes=bpf-stackify --emit-llvm -bpf-capsule-verbose "${BEFORE}" -o "${WORK}/actual.bc"
    ERROR_VARIABLE stats
    COMMAND_ERROR_IS_FATAL ANY
)
execute_process(COMMAND "${LLVM_DIS}" "${WORK}/actual.bc" -o "${WORK}/actual.ll" COMMAND_ERROR_IS_FATAL ANY)
file(READ "${WORK}/actual.ll" ir)
if(
    NOT ir MATCHES "a_loop.body.chunk.guard:"
    OR NOT ir MATCHES "z_loop.body.chunk.guard:"
    OR ir MATCHES "b_loop.body.chunk.guard:"
)
    message(FATAL_ERROR "Chunks did not respect call frequency and stable ties: ${WORK}/actual.ll")
endif()
if(NOT stats MATCHES "chunked 2 dynamic loops.*cost ([0-9]+)/([0-9]+)")
    message(FATAL_ERROR "Expected two budgeted chunks: ${stats}")
endif()
if(CMAKE_MATCH_1 GREATER CMAKE_MATCH_2)
    message(FATAL_ERROR "Chunk expansion exceeded its shared budget: ${stats}")
endif()
