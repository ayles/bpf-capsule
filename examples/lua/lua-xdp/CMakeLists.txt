# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Stock Lua attached to live XDP, with one retained VM per Capsule fiber.

bpf_capsule_bitcode(
    LUA_XDP_DRIVER_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/lua_xdp_bpf.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES} ${CMAKE_CURRENT_SOURCE_DIR}/../common
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g
)
bpf_capsule_bitcode(
    LUA_XDP_RUNTIME_BC
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/lua_xdp_runtime.c
    INCLUDE_DIRECTORIES ${LUA_BPF_INCLUDE_DIRECTORIES} ${CMAKE_CURRENT_SOURCE_DIR}/../common
    COMPILE_DEFINITIONS ${LUA_BPF_COMPILE_DEFINITIONS}
    COMPILE_OPTIONS ${LUA_BPF_COMPILE_OPTIONS} -g0
)
bpf_capsule_object(
    lua_xdp_bpf_output
    OUTPUT lua_xdp_bpf.o
    BITCODE ${LUA_XDP_DRIVER_BC} ${LUA_XDP_RUNTIME_BC} ${LUA_CAPSULE_COMMON_BC} ${LUA_SUPPORT_BC}
            ${LUA_UPSTREAM_BC}
    DEPENDS lua_capsule_common_bitcode
)
bpf_capsule_skeleton(
    lua_xdp_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp_bpf.o"
    NAME lua_xdp
    DEPENDS lua_xdp_bpf_output
)

add_library(lua_xdp_loader STATIC lua_xdp_loader.c)
target_include_directories(
    lua_xdp_loader PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_compile_options(lua_xdp_loader PRIVATE -Wall -Wextra)
target_link_libraries(lua_xdp_loader PUBLIC PkgConfig::LibBpf)

add_executable(lua_xdp lua_xdp_host.c "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp.skel.h")
set_target_properties(lua_xdp PROPERTIES OUTPUT_NAME lua-xdp)
target_include_directories(
    lua_xdp PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_compile_options(lua_xdp PRIVATE -Wall -Wextra)
target_link_libraries(lua_xdp PRIVATE lua_xdp_loader)
add_dependencies(lua_xdp lua_xdp_skeleton)

install(TARGETS lua_xdp RUNTIME DESTINATION libexec/bpf-capsule/examples/lua-xdp)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packet_filter.lua"
              "${CMAKE_CURRENT_SOURCE_DIR}/packet_observer.lua"
        DESTINATION libexec/bpf-capsule/examples/lua-xdp
)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lua_xdp_bpf.o"
            DESTINATION libexec/bpf-capsule/examples/lua-xdp
    )
endif()
