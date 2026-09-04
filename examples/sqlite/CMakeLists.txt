# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel SQLite: the stock amalgamation through the same pipeline.
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleSqlite LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

FetchContent_Declare(
    sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA256=1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
)
FetchContent_MakeAvailable(sqlite)

bpf_capsule_object(
    sqlite_bpf
    OUTPUT sqlite.bpf.o
    SOURCES #
        sqlite_bpf.c
        ${sqlite_SOURCE_DIR}/sqlite3.c
    INCLUDE_DIRECTORIES ${sqlite_SOURCE_DIR}
    # SQLite needs a VFS supplied by the embedder and this example has no
    # threads. Loading dynamic extensions cannot exist in a freestanding BPF
    # program; everything else stays enabled.
    COMPILE_DEFINITIONS #
        SQLITE_OS_OTHER=1
        SQLITE_THREADSAFE=0
        SQLITE_OMIT_LOAD_EXTENSION
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(sqlite_skeleton OUTPUT sqlite.skel.h OBJECT "${sqlite_bpf}" NAME sqlite)

add_executable(sqlite sqlite_host.c)
target_compile_options(sqlite PRIVATE -Wall -Wextra)
target_link_libraries(sqlite PRIVATE BpfCapsule::host sqlite_skeleton)

install(TARGETS sqlite RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${sqlite_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
