# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleQuickJS LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)
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

file(STRINGS "${quickjs_SOURCE_DIR}/VERSION" QUICKJS_VERSION LIMIT_COUNT 1)
bpf_capsule_object(
    quickjs_bpf
    OUTPUT quickjs.bpf.o
    SOURCES #
        quickjs_bpf.c
        ${quickjs_patched_SOURCE_DIR}/quickjs.c
        ${quickjs_patched_SOURCE_DIR}/cutils.c
        ${quickjs_patched_SOURCE_DIR}/libregexp.c
        ${quickjs_patched_SOURCE_DIR}/libunicode.c
        ${quickjs_patched_SOURCE_DIR}/dtoa.c
    INCLUDE_DIRECTORIES ${quickjs_patched_SOURCE_DIR}
    COMPILE_DEFINITIONS #
        CONFIG_VERSION="${QUICKJS_VERSION}"
        # Defining __EMSCRIPTEN__ would also disable direct dispatch and
        # thread-backed Atomics, but would needlessly drop the stack checks and
        # allocator accounting that Capsule supports.
        CONFIG_NO_DIRECT_DISPATCH
        CONFIG_NO_ATOMICS
        # Capsule's default platform has no timezone database and defines
        # local time as UTC.
        CONFIG_UTC_TIMEZONE
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(quickjs_skeleton OUTPUT quickjs.skel.h OBJECT "${quickjs_bpf}" NAME quickjs)

add_executable(quickjs quickjs_host.c)
target_compile_options(quickjs PRIVATE -Wall -Wextra)
target_link_libraries(quickjs PRIVATE BpfCapsule::host quickjs_skeleton)

install(TARGETS quickjs RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${quickjs_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${quickjs_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-quickjs")
