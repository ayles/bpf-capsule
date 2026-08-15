# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_executable(lua_xdp_test_host lua_xdp_test_host.c)
target_include_directories(
    lua_xdp_test_host
    PRIVATE "${CMAKE_BINARY_DIR}/examples/lua/lua-xdp"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../examples/lua/lua-xdp" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_link_libraries(lua_xdp_test_host PRIVATE lua_xdp_loader pthread)
add_dependencies(lua_xdp_test_host lua_xdp_skeleton)

install(TARGETS lua_xdp_test_host RUNTIME DESTINATION libexec/bpf-capsule/tests/lua-xdp)
