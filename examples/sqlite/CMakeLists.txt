# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel SQLite: the stock amalgamation through the same pipeline. Needs
# the amalgamation fetched below, or an explicit SQLITE_BPF_SOURCE_DIR.
set(SQLITE_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing SQLite amalgamation"
)
if(NOT SQLITE_BPF_SOURCE_DIR OR NOT EXISTS "${SQLITE_BPF_SOURCE_DIR}/sqlite3.c")
    fetch_example_source(
        fetched_sqlite
        bpf_capsule_sqlite
        URL
        https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip
        URL_HASH
        5592243caf28b2cdef41e6ab58d25d653dfc53deded8450eb66072c929f030c4
        ROOT_SUBDIR
        sqlite-amalgamation-3450100
        MARKER
        sqlite3.c
    )
    if(NOT fetched_sqlite)
        message(STATUS "SQLite example: upstream source unavailable, skipping")
        return()
    endif()
    set(SQLITE_BPF_SOURCE_DIR "${fetched_sqlite}")
endif()

# Integer-only, no OS, no libc malloc (memsys5 over the Capsule heap), no threads:
# the same configuration the kernel can actually express.
set(SQLITE_DEFS
    -DSQLITE_OS_OTHER=1
    -DSQLITE_THREADSAFE=0
    -DSQLITE_OMIT_LOAD_EXTENSION
    -DSQLITE_OMIT_WAL
    -DSQLITE_TEMP_STORE=3
    -DSQLITE_OMIT_DEPRECATED
    -DSQLITE_OMIT_PROGRESS_CALLBACK
    -DSQLITE_OMIT_SHARED_CACHE
    -DSQLITE_OMIT_AUTOINIT
    -DSQLITE_OMIT_UTF16
    -DSQLITE_OMIT_AUTHORIZATION
    -DSQLITE_OMIT_COMPLETE
    -DSQLITE_OMIT_TRACE
    -DSQLITE_UNTESTABLE
    -DSQLITE_OMIT_FLOATING_POINT
    -DSQLITE_OMIT_LOCALTIME
    -DSQLITE_OMIT_DATETIME_FUNCS
    -DSQLITE_ENABLE_MEMSYS5
    -Dfabs=__builtin_fabs
)

# softfloat.c satisfies the handful of double ops SQLite keeps even under
# SQLITE_OMIT_FLOATING_POINT (int<->double conversions in a few conversion
# paths surface as __bpf_i2d/__bpf_dcmp after bpf-soft-float); without it the
# object has unresolved soft-float symbols and will not load.
# Full `-g` on the 9 MiB amalgamation bloats IR, BTF and every later compiler
# data structure. It formerly made textual MIR parsing take minutes. Our driver
# still supplies the compile unit/BTF needed for programs and maps; upstream
# SQLite needs no line information in the BPF object.
set(SQLITE_BPF_INCLUDE_DIRECTORIES ${SQLITE_BPF_SOURCE_DIR} ${BPF_CAPSULE_LIBC_DIR}
                                   ${BPF_CAPSULE_LIBC_DIR}/include
)
set(SQLITE_BPF_OPTIONS -Wno-absolute-value -Wno-literal-conversion)
bpf_capsule_bitcode(
    SQLITE_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/sqlite_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
    INCLUDE_DIRECTORIES ${SQLITE_BPF_INCLUDE_DIRECTORIES}
    # memsys5 owns the Capsule heap; libc allocation symbols only satisfy
    # unreachable references retained by the amalgamation.
    COMPILE_DEFINITIONS ${SQLITE_DEFS} BPF_CAPSULE_FREESTANDING_NULL_ALLOCATOR
    COMPILE_OPTIONS ${SQLITE_BPF_OPTIONS} -g
)
bpf_capsule_bitcode(
    SQLITE_UPSTREAM_BC
    SOURCES ${SQLITE_BPF_SOURCE_DIR}/sqlite3.c
    INCLUDE_DIRECTORIES ${SQLITE_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${SQLITE_DEFS}
    COMPILE_OPTIONS ${SQLITE_BPF_OPTIONS} -g0
)

bpf_capsule_object(
    sqlite_bpf_lib_output
    OUTPUT sqlite_bpf_lib.o
    BITCODE ${SQLITE_DRIVER_BC} ${SQLITE_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    sqlite_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sqlite.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/sqlite_bpf_lib.o"
    NAME sqlite
    DEPENDS sqlite_bpf_lib_output
)

# The host reference is the same amalgamation compiled natively, so the test
# needs no system sqlite and both sides run identical code.
add_executable(
    sqlite sqlite_host.c ${SQLITE_BPF_SOURCE_DIR}/sqlite3.c
           "${CMAKE_CURRENT_BINARY_DIR}/sqlite.skel.h"
)
set_source_files_properties(${SQLITE_BPF_SOURCE_DIR}/sqlite3.c PROPERTIES COMPILE_OPTIONS -w)
target_include_directories(
    sqlite PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                   ${SQLITE_BPF_SOURCE_DIR}
)
target_compile_options(sqlite PRIVATE -Wall -Wextra -DSQLITE_THREADSAFE=0)
target_link_libraries(sqlite PkgConfig::LibBpf)
add_dependencies(sqlite sqlite_skeleton)

install(TARGETS sqlite RUNTIME DESTINATION libexec/bpf-capsule/examples/sqlite)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/sqlite_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/sqlite
    )
endif()
