# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_executable(lua_xdp_benchmark lua_xdp_benchmark.c)
target_include_directories(
    lua_xdp_benchmark
    PRIVATE "${CMAKE_BINARY_DIR}/examples/lua/lua-xdp"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../examples/lua/lua-xdp" ${BPF_CAPSULE_INCLUDE_DIRS}
)
target_link_libraries(lua_xdp_benchmark PRIVATE lua_xdp_loader)
add_dependencies(lua_xdp_benchmark lua_xdp_skeleton)

install(TARGETS lua_xdp_benchmark RUNTIME DESTINATION libexec/bpf-capsule/benchmarks/lua-xdp)
