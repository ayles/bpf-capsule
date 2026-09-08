# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel SQLite: the stock amalgamation through the same pipeline.
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleSqlite LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/sqlite ports/sqlite)

bpf_capsule_object(
    sqlite_bpf
    OUTPUT sqlite.bpf.o
    SOURCES sqlite_bpf.c
    LIBRARIES capsule_sqlite
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(sqlite_skeleton OUTPUT sqlite.skel.h OBJECT "${sqlite_bpf}" NAME sqlite)

add_executable(sqlite sqlite_host.c)
target_compile_options(sqlite PRIVATE -Wall -Wextra)
target_link_libraries(sqlite PRIVATE BpfCapsule::host sqlite_skeleton)

install(TARGETS sqlite RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${sqlite_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
