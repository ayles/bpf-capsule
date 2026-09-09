# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)
find_package(Patch REQUIRED)

FetchContent_Declare(
    quickjs
    GIT_REPOSITORY https://github.com/bellard/quickjs.git
    GIT_TAG 04be246001599f5995fa2f2d8c91a0f198d3f34c
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(quickjs)
# gersemi: off
FetchContent_Populate(
    quickjs_patched
    URL "${quickjs_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}" --quiet --batch --read-only=ignore -p1 -i
        "${CMAKE_CURRENT_SOURCE_DIR}/patches/0001-add-feature-switches.patch"
)
# gersemi: on

file(STRINGS "${quickjs_SOURCE_DIR}/VERSION" quickjs_version LIMIT_COUNT 1)
bpf_capsule_library(
    capsule_quickjs
    SOURCES
        "${quickjs_patched_SOURCE_DIR}/quickjs.c"
        "${quickjs_patched_SOURCE_DIR}/cutils.c"
        "${quickjs_patched_SOURCE_DIR}/libregexp.c"
        "${quickjs_patched_SOURCE_DIR}/libunicode.c"
        "${quickjs_patched_SOURCE_DIR}/dtoa.c"
)
target_include_directories(capsule_quickjs PUBLIC "${quickjs_patched_SOURCE_DIR}")
# Disable computed goto and thread-backed Atomics, not stack checks or
# allocator accounting. The default Capsule platform uses UTC local time.
target_compile_definitions(
    capsule_quickjs
    PRIVATE CONFIG_VERSION="${quickjs_version}" CONFIG_NO_DIRECT_DISPATCH CONFIG_NO_ATOMICS CONFIG_UTC_TIMEZONE
)
target_compile_options(capsule_quickjs PRIVATE -g)

# The same sources compiled natively, for the examples' --native comparison:
# the stock configuration except the UTC time zone the guest also uses.
add_library(
    quickjs_native
    STATIC
    "${quickjs_patched_SOURCE_DIR}/quickjs.c"
    "${quickjs_patched_SOURCE_DIR}/cutils.c"
    "${quickjs_patched_SOURCE_DIR}/libregexp.c"
    "${quickjs_patched_SOURCE_DIR}/libunicode.c"
    "${quickjs_patched_SOURCE_DIR}/dtoa.c"
)
target_include_directories(quickjs_native PUBLIC "${quickjs_patched_SOURCE_DIR}")
target_compile_definitions(quickjs_native PRIVATE CONFIG_VERSION="${quickjs_version}" CONFIG_UTC_TIMEZONE _GNU_SOURCE)
target_compile_options(quickjs_native PRIVATE -O2 -w)
target_link_libraries(quickjs_native PUBLIC m pthread)
install(FILES "${quickjs_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/quickjs")
