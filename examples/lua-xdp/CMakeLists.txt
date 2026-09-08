# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleLuaXdp LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/lua ports/lua)

bpf_capsule_object(
    lua_xdp_bpf
    OUTPUT lua-xdp.bpf.o
    SOURCES lua_xdp_bpf.c lua_xdp_runtime.c
    LIBRARIES capsule_lua
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(lua_xdp_skeleton OUTPUT lua_xdp.skel.h OBJECT "${lua_xdp_bpf}" NAME lua_xdp)

add_executable(lua_xdp lua_xdp_host.c)
set_target_properties(lua_xdp PROPERTIES OUTPUT_NAME lua-xdp)
target_compile_options(lua_xdp PRIVATE -Wall -Wextra)
target_link_libraries(lua_xdp PRIVATE BpfCapsule::host lua_xdp_skeleton)

install(TARGETS lua_xdp RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${lua_xdp_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
