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
        https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
        URL_HASH
        1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
        ROOT_SUBDIR
        sqlite-amalgamation-3530400
        MARKER
        sqlite3.c
    )
    set(SQLITE_BPF_SOURCE_DIR "${fetched_sqlite}")
endif()

# SQLite needs a VFS supplied by the embedder and this example has no threads.
# Loading dynamic extensions cannot exist in a freestanding BPF program;
# everything else, including floating-point SQL and SQLite's ordinary malloc
# path, stays enabled.
set(SQLITE_DEFS
    -DSQLITE_OS_OTHER=1
    -DSQLITE_THREADSAFE=0
    -DSQLITE_OMIT_LOAD_EXTENSION
)

# softfloat.c implements SQLite's arithmetic and mathfns.c supplies scalar
# operations such as fabs which the soft-float pass lowers explicitly.
# Full debug information on the amalgamation needlessly bloats every compiler
# stage. The driver still supplies the BTF needed for programs and maps.
set(SQLITE_BPF_INCLUDE_DIRECTORIES ${SQLITE_BPF_SOURCE_DIR} ${BPF_CAPSULE_LIBC_DIR}
                                   ${BPF_CAPSULE_LIBC_DIR}/include
)
bpf_capsule_bitcode(
    SQLITE_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/sqlite_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c ${BPF_CAPSULE_LIBC_DIR}/int128.c
            ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
    INCLUDE_DIRECTORIES ${SQLITE_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${SQLITE_DEFS}
    COMPILE_OPTIONS -g
)
bpf_capsule_bitcode(
    SQLITE_MATH_BC
    SOURCES ${BPF_CAPSULE_LIBC_DIR}/mathfns.c ${BPF_CAPSULE_LIBC_DIR}/strtod.c
    INCLUDE_DIRECTORIES ${SQLITE_BPF_INCLUDE_DIRECTORIES}
    COMPILE_OPTIONS -g
)
bpf_capsule_bitcode(
    SQLITE_UPSTREAM_BC
    SOURCES ${SQLITE_BPF_SOURCE_DIR}/sqlite3.c
    INCLUDE_DIRECTORIES ${SQLITE_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${SQLITE_DEFS}
    COMPILE_OPTIONS -g0
)

bpf_capsule_object(
    sqlite_bpf_lib_output
    OUTPUT sqlite_bpf_lib.o
    BITCODE ${SQLITE_DRIVER_BC} ${SQLITE_MATH_BC} ${SQLITE_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    sqlite_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/sqlite.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/sqlite_bpf_lib.o"
    NAME sqlite
    DEPENDS sqlite_bpf_lib_output
)

add_executable(sqlite sqlite_host.c "${CMAKE_CURRENT_BINARY_DIR}/sqlite.skel.h")
target_include_directories(
    sqlite PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_compile_options(sqlite PRIVATE -Wall -Wextra)
target_link_libraries(sqlite PRIVATE ${BPF_CAPSULE_HOST_TARGET})
add_dependencies(sqlite sqlite_skeleton)

install(TARGETS sqlite RUNTIME DESTINATION libexec/bpf-capsule/examples/sqlite)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/sqlite_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/sqlite
    )
endif()
