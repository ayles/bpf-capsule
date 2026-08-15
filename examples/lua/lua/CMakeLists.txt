# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Small stock-Lua stdin/stdout runner plus a native differential reference.

# Clang 22 crashes while emitting debug info for the upstream Lua sources on
# BPF. The Capsule driver supplies the compile unit and generated-subprogram
# BTF; only the application driver needs normal source debug information.
bpf_capsule_bitcode(
    LUA_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/lua_bpf.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES} ${CMAKE_CURRENT_SOURCE_DIR}/../common
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_object(
    lua_bpf_output
    OUTPUT lua_bpf.o
    BITCODE ${LUA_DRIVER_BC} ${LUA_CAPSULE_COMMON_BC} ${LUA_SUPPORT_BC} ${LUA_UPSTREAM_BC}
    DEPENDS lua_capsule_common_bitcode
)
bpf_capsule_skeleton(
    lua_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lua.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/lua_bpf.o"
    NAME lua_runner
    DEPENDS lua_bpf_output
)

add_executable(lua lua_host.c ${LUA_BPF_SOURCES} "${CMAKE_CURRENT_BINARY_DIR}/lua.skel.h")
set_source_files_properties(${LUA_BPF_SOURCES} PROPERTIES COMPILE_OPTIONS -w)
target_include_directories(
    lua PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                "${LUA_BPF_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/../common"
)
target_compile_options(lua PRIVATE -Wall -Wextra)
target_link_libraries(lua PRIVATE PkgConfig::LibBpf m)
add_dependencies(lua lua_skeleton)

install(TARGETS lua RUNTIME DESTINATION libexec/bpf-capsule/examples/lua)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/script.lua" DESTINATION libexec/bpf-capsule/examples/lua)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lua_bpf.o"
            DESTINATION libexec/bpf-capsule/examples/lua
    )
endif()
