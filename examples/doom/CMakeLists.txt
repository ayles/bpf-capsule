# SPDX-License-Identifier: GPL-2.0-only
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleDoom LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)
find_package(Patch REQUIRED)

FetchContent_Declare(
    puredoom
    GIT_REPOSITORY https://github.com/Daivuk/PureDOOM.git
    GIT_TAG 355cfbd16fac119718879239336ee2ea408886bd
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(puredoom)

# PureDOOM leaves its framebuffer uninitialized and can over-read sparse cached
# lumps in the vanilla column drawer. Patch a private build-tree copy so a
# supplied checkout is never modified, the distributed changes are identified,
# and identical inputs render byte-identical frames.
set(patch_dir "${CMAKE_CURRENT_SOURCE_DIR}/patches")
# gersemi: off
FetchContent_Populate(
    puredoom_patched
    URL "${puredoom_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}" --quiet --batch --read-only=ignore -p1 -i "${patch_dir}/puredoom.patch"
)
# gersemi: on
bpf_capsule_object(
    doom_bpf
    OUTPUT doom.bpf.o
    SOURCES doom_bpf.c
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${puredoom_patched_SOURCE_DIR}
    # Upstream intentionally uses assignment in its WAD-probing conditions.
    COMPILE_OPTIONS -Wno-parentheses -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(doom_skeleton OUTPUT doom.skel.h OBJECT "${doom_bpf}" NAME doom)

add_executable(doom doom.c)
target_compile_options(doom PRIVATE -Wall -Wextra)
target_link_libraries(doom PRIVATE BpfCapsule::host doom_skeleton)

install(TARGETS doom RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${doom_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-doom")
install(
    FILES "${puredoom_SOURCE_DIR}/PureDOOM.h" doom.c doom_bpf.c bpf_ctrl.h CMakeLists.txt LICENSE
    DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/examples/doom/source"
)
install(
    DIRECTORY patches/
    DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/examples/doom/source/patches"
    FILES_MATCHING
    PATTERN "*.patch"
)
