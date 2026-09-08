# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)

FetchContent_Declare(
    lua
    URL https://www.lua.org/ftp/lua-5.5.1.tar.gz
    URL_HASH SHA256=1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
)
FetchContent_MakeAvailable(lua)
file(GLOB lua_sources "${lua_SOURCE_DIR}/src/*.c")
list(FILTER lua_sources EXCLUDE REGEX "/(lua|luac)\\.c$")

bpf_capsule_library(capsule_lua SOURCES ${lua_sources})
target_include_directories(capsule_lua PUBLIC "${lua_SOURCE_DIR}/src")
# The BPF backend cannot lower the blockaddress constants in computed goto.
target_compile_definitions(capsule_lua PRIVATE LUA_USE_JUMPTABLE=0)
# Consumers need the declaration workaround too, until the SDK Clang fixes the
# -g crash on declarations with the name in parentheses.
target_compile_options(capsule_lua PUBLIC -include "${CMAKE_CURRENT_SOURCE_DIR}/lua_capsule_config.h")
target_compile_options(capsule_lua PRIVATE -g)
install(FILES "${lua_SOURCE_DIR}/doc/readme.html" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/lua")
