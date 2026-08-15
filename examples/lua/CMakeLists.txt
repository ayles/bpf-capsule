# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set(LUA_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing Lua 5.4 source tree"
)
if(NOT LUA_BPF_SOURCE_DIR OR NOT EXISTS "${LUA_BPF_SOURCE_DIR}/src/lvm.c")
    fetch_example_source(
        fetched_lua
        bpf_capsule_lua
        URL
        https://www.lua.org/ftp/lua-5.4.8.tar.gz
        URL_HASH
        4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae
        ROOT_SUBDIR
        lua-5.4.8
        MARKER
        src/lvm.c
    )
    set(LUA_BPF_SOURCE_DIR "${fetched_lua}")
endif()

file(GLOB LUA_BPF_SOURCES "${LUA_BPF_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

set(LUA_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                ${LUA_BPF_SOURCE_DIR}/src
)
set(LUA_BPF_COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0 LUA_USE_C89)
set(LUA_BPF_COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/common/lua_capsule_config.h
                            -Wno-invalid-noreturn
)

# Both front ends link the identical interpreter, compatibility libc, and
# Lua platform adapter. Compile those inputs once; only each example's driver
# and the XDP retained-state runtime differ.
bpf_capsule_bitcode(
    LUA_CAPSULE_COMMON_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/common/lua_capsule_runtime.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES} ${CMAKE_CURRENT_SOURCE_DIR}/common
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g0
)
bpf_capsule_bitcode(
    LUA_SUPPORT_BC
    SOURCES ${BPF_CAPSULE_LIBC_DIR}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf.c
            ${BPF_CAPSULE_LIBC_DIR}/softfloat.c ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_bitcode(
    LUA_UPSTREAM_BC
    SOURCES ${LUA_BPF_SOURCES}
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g0
)
add_custom_target(
    lua_capsule_common_bitcode DEPENDS ${LUA_CAPSULE_COMMON_BC} ${LUA_SUPPORT_BC}
                                       ${LUA_UPSTREAM_BC}
)

if("all" IN_LIST BPF_CAPSULE_EXAMPLES OR "lua" IN_LIST BPF_CAPSULE_EXAMPLES)
    add_subdirectory(lua)
endif()
if("all" IN_LIST BPF_CAPSULE_EXAMPLES OR "lua-xdp" IN_LIST BPF_CAPSULE_EXAMPLES)
    add_subdirectory(lua-xdp)
endif()

install(
    FILES "${LUA_BPF_SOURCE_DIR}/doc/readme.html"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME lua-license.html
)
