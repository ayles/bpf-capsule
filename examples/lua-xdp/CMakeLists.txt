# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleLuaXdp LANGUAGES C)

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
    lua_xdp_bpf
    OUTPUT lua-xdp.bpf.o
    SOURCES lua_xdp_bpf.c lua_xdp_runtime.c ${LUA_BPF_SOURCES}
    INCLUDE_DIRECTORIES ${lua_SOURCE_DIR}/src
    # Lua's computed-goto VM emits LLVM blockaddress constants, which the BPF
    # target cannot lower (the link otherwise fails on an undefined .Ltmp symbol).
    COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0
    COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/lua_capsule_config.h -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(lua_xdp_skeleton OUTPUT lua_xdp.skel.h OBJECT "${lua_xdp_bpf}" NAME lua_xdp)

add_executable(lua_xdp lua_xdp_host.c)
set_target_properties(lua_xdp PROPERTIES OUTPUT_NAME lua-xdp)
target_compile_options(lua_xdp PRIVATE -Wall -Wextra)
target_link_libraries(lua_xdp PRIVATE BpfCapsule::host lua_xdp_skeleton)

install(TARGETS lua_xdp RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_xdp_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_SOURCE_DIR}/doc/readme.html" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-lua-xdp")
