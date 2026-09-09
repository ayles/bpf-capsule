# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)

FetchContent_Declare(
    sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA256=1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
)
FetchContent_MakeAvailable(sqlite)

# The embedder supplies SQLite's documented VFS hooks. Native dynamic
# extensions cannot execute in BPF; the rest of SQLite remains enabled.
bpf_capsule_library(capsule_sqlite SOURCES "${sqlite_SOURCE_DIR}/sqlite3.c")
target_include_directories(capsule_sqlite PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(capsule_sqlite PRIVATE SQLITE_OS_OTHER=1 SQLITE_THREADSAFE=0 SQLITE_OMIT_LOAD_EXTENSION)
target_compile_options(capsule_sqlite PRIVATE -g)

# The same amalgamation compiled natively, for the examples' --native comparison.
add_library(sqlite_native STATIC "${sqlite_SOURCE_DIR}/sqlite3.c")
target_include_directories(sqlite_native PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(sqlite_native PRIVATE SQLITE_OS_OTHER=1 SQLITE_THREADSAFE=0 SQLITE_OMIT_LOAD_EXTENSION)
target_compile_options(sqlite_native PRIVATE -O2 -w)
target_link_libraries(sqlite_native PUBLIC m)
