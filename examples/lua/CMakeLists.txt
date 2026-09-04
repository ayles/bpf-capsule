# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleLua LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

FetchContent_Declare(
    lua
    URL https://www.lua.org/ftp/lua-5.5.1.tar.gz
    URL_HASH SHA256=1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
)
FetchContent_MakeAvailable(lua)

file(GLOB LUA_BPF_SOURCES "${lua_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

bpf_capsule_object(
    lua_bpf
    OUTPUT lua.bpf.o
    SOURCES lua_bpf.c ${LUA_BPF_SOURCES}
    INCLUDE_DIRECTORIES ${lua_SOURCE_DIR}/src
    # Lua's computed-goto VM emits LLVM blockaddress constants, which the BPF
    # target cannot lower (the link otherwise fails on an undefined .Ltmp symbol).
    COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0
    COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/lua_capsule_config.h -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(lua_skeleton OUTPUT lua.skel.h OBJECT "${lua_bpf}" NAME lua_runner)

add_executable(lua lua_host.c)
target_compile_options(lua PRIVATE -Wall -Wextra)
target_link_libraries(lua PRIVATE BpfCapsule::host lua_skeleton)

install(TARGETS lua RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_SOURCE_DIR}/doc/readme.html" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-lua")
