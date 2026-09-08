# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Both tests link the same library built from the shared port definition.
add_subdirectory(../../ports/lua ports/lua)

set(lua_runner_link_options)
if(BPF_CAPSULE_TEST_FREPLACE)
    list(APPEND lua_runner_link_options --freplace)
endif()
capsule_test_object(
    lua_runner
    SOURCES lua_bpf.c
    LIBRARIES capsule_lua
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/common
    LINK_OPTIONS ${lua_runner_link_options}
)
capsule_gtest_host(
    lua_test
    SOURCES lua_test.cc
    SKELETONS lua_runner_skeleton
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_definitions(lua_test PRIVATE LUA_TEST_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/script.lua")
if(BPF_CAPSULE_TEST_FREPLACE)
    target_compile_definitions(lua_test PRIVATE BPF_CAPSULE_TEST_FREPLACE=1)
endif()

set(LUA_XDP_EXAMPLE "${BPF_CAPSULE_REPOSITORY_DIR}/examples/lua-xdp")
capsule_test_object(
    lua_xdp_test_guest
    SOURCES ${LUA_XDP_EXAMPLE}/lua_xdp_bpf.c ${LUA_XDP_EXAMPLE}/lua_xdp_runtime.c
    LIBRARIES capsule_lua
    INCLUDE_DIRECTORIES ${LUA_XDP_EXAMPLE}
)
capsule_gtest_host(
    lua_xdp_test
    SOURCES lua_xdp_test.cc
    SKELETONS lua_xdp_test_guest_skeleton
    INCLUDE_DIRECTORIES ${LUA_XDP_EXAMPLE}
    LIBRARIES pthread
)
target_compile_definitions(lua_xdp_test PRIVATE LUA_XDP_OBSERVER="${LUA_XDP_EXAMPLE}/packet_observer.lua")

install(FILES script.lua DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests")
install(
    FILES "${LUA_XDP_EXAMPLE}/packet_observer.lua"
    DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests"
    RENAME lua-xdp-observer.lua
)
