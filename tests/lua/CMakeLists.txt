# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Stock Lua through the toolchain, structured as a test. Upstream is
# fetched but never configured: its C sources are inputs to bpf-capsule-cc.
set(LUA_BPF_SOURCE_DIR
    ""
    CACHE PATH "use an existing Lua source tree"
)
if(NOT LUA_BPF_SOURCE_DIR OR NOT EXISTS "${LUA_BPF_SOURCE_DIR}/src/lvm.c")
    FetchContent_Declare(
        bpf_capsule_lua
        URL https://www.lua.org/ftp/lua-5.5.1.tar.gz
        URL_HASH SHA256=1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        SOURCE_SUBDIR .bpf-capsule-do-not-build
    )
    FetchContent_MakeAvailable(bpf_capsule_lua)
    FetchContent_GetProperties(bpf_capsule_lua SOURCE_DIR lua_source_dir)
    if(NOT EXISTS "${lua_source_dir}/src/lvm.c")
        message(FATAL_ERROR "fetched Lua source lacks src/lvm.c at ${lua_source_dir}")
    endif()
    set(LUA_BPF_SOURCE_DIR
        "${lua_source_dir}"
        CACHE PATH "use an existing Lua source tree" FORCE
    )
endif()

file(GLOB LUA_BPF_SOURCES "${LUA_BPF_SOURCE_DIR}/src/*.c")
list(FILTER LUA_BPF_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

# The driver carries -g (compile unit + BTF for the control section); the
# upstream interpreter compiles -g0 because clang crashes emitting its full
# debug info on BPF.
capsule_bpf_object(
    lua_runner
    SOURCES lua_bpf.c ${LIBC}/freestanding.c ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c
            ${LIBC}/softfloat.c ${LIBC}/mathfns.c ${LIBC}/strtod.c
    NODEBUG_SOURCES ${LUA_BPF_SOURCES}
    FLAGS -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/common ${LIBC_FLAGS} -I${LUA_BPF_SOURCE_DIR}/src
          -DLUA_USE_JUMPTABLE=0 -include ${CMAKE_CURRENT_SOURCE_DIR}/common/lua_capsule_config.h
)
capsule_gtest_host(lua_test SOURCES lua_test.cc DEPENDS lua_runner_skeleton
                   INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(lua_test PRIVATE LUA_TEST_SCRIPT="${CMAKE_CURRENT_SOURCE_DIR}/script.lua")

set(LUA_XDP_EXAMPLE "${CMAKE_SOURCE_DIR}/examples/lua-xdp")
capsule_bpf_object(
    lua_xdp_test_guest
    SOURCES ${LUA_XDP_EXAMPLE}/lua_xdp_bpf.c ${LIBC}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c ${LIBC}/softfloat.c ${LIBC}/mathfns.c
            ${LIBC}/strtod.c
    NODEBUG_SOURCES ${LUA_XDP_EXAMPLE}/lua_xdp_runtime.c ${LUA_BPF_SOURCES}
    FLAGS -I${LUA_XDP_EXAMPLE} ${LIBC_FLAGS} -I${LUA_BPF_SOURCE_DIR}/src
          -DLUA_USE_JUMPTABLE=0 -include ${LUA_XDP_EXAMPLE}/lua_capsule_config.h
)
capsule_gtest_host(
    lua_xdp_test
    SOURCES lua_xdp_test.cc
    DEPENDS lua_xdp_test_guest_skeleton
    INCLUDE_DIRECTORIES ${LUA_XDP_EXAMPLE}
    LIBRARIES pthread
)
target_compile_definitions(
    lua_xdp_test PRIVATE LUA_XDP_OBSERVER="${LUA_XDP_EXAMPLE}/packet_observer.lua"
)

if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES script.lua
            DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests")
    install(FILES "${LUA_XDP_EXAMPLE}/packet_observer.lua"
            DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/bpf-capsule/tests"
            RENAME lua-xdp-observer.lua
    )
endif()
