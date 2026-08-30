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
    set(LUA_BPF_SOURCE_DIR
        "${fetched_lua}"
        CACHE PATH "use an existing Lua 5.4 source tree" FORCE
    )
endif()

file(GLOB LUA_BPF_SOURCES "${LUA_BPF_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

set(LUA_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                ${LUA_BPF_SOURCE_DIR}/src
)
set(LUA_BPF_COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0 LUA_USE_C89)
set(LUA_BPF_COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/lua_capsule_config.h
                            -Wno-invalid-noreturn
)

bpf_capsule_bitcode(
    LUA_SUPPORT_BC
    SOURCES ${BPF_CAPSULE_LIBC_DIR}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
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
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} ${BPF_CAPSULE_GUEST_DEBUG_FLAG}
)
bpf_capsule_bitcode(
    LUA_DRIVER_BC
    SOURCES lua_bpf.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_object(
    lua_bpf_output
    OUTPUT lua_bpf.o
    BITCODE ${LUA_DRIVER_BC} ${LUA_SUPPORT_BC} ${LUA_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    lua_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lua.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/lua_bpf.o"
    NAME lua_runner
    DEPENDS lua_bpf_output
)

add_executable(lua lua_host.c "${CMAKE_CURRENT_BINARY_DIR}/lua.skel.h")
target_include_directories(lua PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS})
target_compile_options(lua PRIVATE -Wall -Wextra)
target_link_libraries(lua PRIVATE ${BPF_CAPSULE_HOST_TARGET})
add_dependencies(lua lua_skeleton)

install(TARGETS lua RUNTIME DESTINATION libexec/bpf-capsule/examples/lua)
install(FILES script.lua DESTINATION libexec/bpf-capsule/examples/lua)
install(
    FILES "${LUA_BPF_SOURCE_DIR}/doc/readme.html"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME lua-license.html
)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lua_bpf.o"
            DESTINATION libexec/bpf-capsule/examples/lua
    )
endif()
