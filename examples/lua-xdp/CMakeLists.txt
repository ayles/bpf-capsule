# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set(LUA_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing Lua source tree"
)
if(NOT LUA_BPF_SOURCE_DIR OR NOT EXISTS "${LUA_BPF_SOURCE_DIR}/src/lvm.c")
    fetch_example_source(
        fetched_lua
        bpf_capsule_lua
        URL
        https://www.lua.org/ftp/lua-5.5.1.tar.gz
        URL_HASH
        1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
        ROOT_SUBDIR
        lua-5.5.1
        MARKER
        src/lvm.c
    )
    set(LUA_BPF_SOURCE_DIR
        "${fetched_lua}"
        CACHE PATH "use an existing Lua source tree" FORCE
    )
endif()

file(GLOB LUA_BPF_SOURCES "${LUA_BPF_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

set(LUA_BPF_INCLUDE_DIRECTORIES ${BPF_CAPSULE_LIBC_DIR} ${BPF_CAPSULE_LIBC_DIR}/include
                                ${LUA_BPF_SOURCE_DIR}/src
)
# Lua's computed-goto VM emits LLVM blockaddress constants, which the BPF
# target cannot lower (the link otherwise fails on an undefined .Ltmp symbol).
set(LUA_BPF_COMPILE_DEFINITIONS LUA_USE_JUMPTABLE=0)
set(LUA_BPF_COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/lua_capsule_config.h)

bpf_capsule_bitcode(
    LUA_XDP_SUPPORT_BC
    SOURCES ${BPF_CAPSULE_LIBC_DIR}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
            ${BPF_CAPSULE_LIBC_DIR}/softfloat.c ${BPF_CAPSULE_LIBC_DIR}/mathfns.c
            ${BPF_CAPSULE_LIBC_DIR}/strtod.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_bitcode(
    LUA_XDP_UPSTREAM_BC
    SOURCES ${LUA_BPF_SOURCES}
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} ${BPF_CAPSULE_GUEST_DEBUG_FLAG}
)
bpf_capsule_bitcode(
    LUA_XDP_DRIVER_BC
    SOURCES lua_xdp_bpf.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_bitcode(
    LUA_XDP_RUNTIME_BC
    SOURCES lua_xdp_runtime.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g0
)
bpf_capsule_object(
    lua_xdp_bpf_output
    OUTPUT lua_xdp_bpf.o
    BITCODE ${LUA_XDP_DRIVER_BC} ${LUA_XDP_RUNTIME_BC} ${LUA_XDP_SUPPORT_BC}
            ${LUA_XDP_UPSTREAM_BC}
)
bpf_capsule_skeleton(
    lua_xdp_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp_bpf.o"
    NAME lua_xdp
    DEPENDS lua_xdp_bpf_output
)

add_executable(lua_xdp lua_xdp_host.c "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp.skel.h")
set_target_properties(lua_xdp PROPERTIES OUTPUT_NAME lua-xdp)
target_include_directories(
    lua_xdp PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_compile_options(lua_xdp PRIVATE -Wall -Wextra)
target_link_libraries(lua_xdp PRIVATE ${BPF_CAPSULE_HOST_TARGET})
add_dependencies(lua_xdp lua_xdp_skeleton)

install(TARGETS lua_xdp RUNTIME DESTINATION libexec/bpf-capsule/examples/lua-xdp)
install(FILES packet_observer.lua DESTINATION libexec/bpf-capsule/examples/lua-xdp)
install(
    FILES "${LUA_BPF_SOURCE_DIR}/doc/readme.html"
    DESTINATION share/licenses/bpf-capsule-examples
    RENAME lua-license.html
)
