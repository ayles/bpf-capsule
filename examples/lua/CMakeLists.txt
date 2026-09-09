# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleLua LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/lua ports/lua)

bpf_capsule_object(
    lua_bpf
    OUTPUT lua.bpf.o
    SOURCES lua_bpf.c
    LIBRARIES capsule_lua
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS} --loop-budget-multiplier=4 --inline-limit=160
)
bpf_capsule_skeleton(lua_skeleton OUTPUT lua.skel.h OBJECT "${lua_bpf}" NAME lua_runner)

add_executable(lua lua_host.c)
target_compile_options(lua PRIVATE -Wall -Wextra)
target_link_libraries(lua PRIVATE BpfCapsule::host lua_skeleton)

install(TARGETS lua RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
