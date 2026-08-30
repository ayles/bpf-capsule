# SPDX-License-Identifier: GPL-2.0-only
set(PUREDOOM_SOURCE_DIR
    ""
    CACHE PATH "use an existing PureDOOM source tree"
)
if(NOT PUREDOOM_SOURCE_DIR OR NOT EXISTS "${PUREDOOM_SOURCE_DIR}/PureDOOM.h")
    fetch_example_source(
        fetched_puredoom
        bpf_capsule_puredoom
        GIT_REPOSITORY
        https://github.com/Daivuk/PureDOOM.git
        GIT_TAG
        355cfbd16fac119718879239336ee2ea408886bd
        MARKER
        PureDOOM.h
    )
    if(NOT fetched_puredoom)
        message(STATUS "Doom example: PureDOOM source unavailable, skipping")
        return()
    endif()
    set(PUREDOOM_SOURCE_DIR "${fetched_puredoom}")
endif()
set(PUREDOOM_UPSTREAM_SOURCE_DIR "${PUREDOOM_SOURCE_DIR}")

# PureDOOM has two allocator-layout-dependent rendering paths: I_InitGraphics
# leaves its newly allocated framebuffer uninitialized, and the vanilla column
# drawer can sample up to 127 bytes beyond the content of a sparse cached lump.
# Patch a private build-tree copy so a supplied source checkout is never
# modified, the distributed changes are identified, and identical inputs
# render byte-identical frames.
set(PUREDOOM_PATCHES
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/0000-license-and-modification-notice.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/0001-initialize-framebuffer.patch"
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/0002-pad-cached-lumps.patch"
)
set_property(
    DIRECTORY
    APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS ${PUREDOOM_PATCHES}
)
set(PUREDOOM_BUILD_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/puredoom-source")
file(MAKE_DIRECTORY "${PUREDOOM_BUILD_SOURCE_DIR}")
configure_file(
    "${PUREDOOM_SOURCE_DIR}/PureDOOM.h" "${PUREDOOM_BUILD_SOURCE_DIR}/PureDOOM.h" COPYONLY
)
find_program(PATCH_EXECUTABLE patch REQUIRED)
foreach(PUREDOOM_PATCH IN LISTS PUREDOOM_PATCHES)
    execute_process(
        COMMAND "${PATCH_EXECUTABLE}" --quiet --batch -p1 -i "${PUREDOOM_PATCH}"
        WORKING_DIRECTORY "${PUREDOOM_BUILD_SOURCE_DIR}"
        RESULT_VARIABLE PUREDOOM_PATCH_RESULT
    )
    if(NOT PUREDOOM_PATCH_RESULT EQUAL 0)
        message(FATAL_ERROR "Doom example: cannot apply ${PUREDOOM_PATCH}")
    endif()
endforeach()
set(PUREDOOM_SOURCE_DIR "${PUREDOOM_BUILD_SOURCE_DIR}")

bpf_capsule_bitcode(
    DOOM_BITCODE
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/doom_bpf.c ${BPF_CAPSULE_LIBC_DIR}/freestanding.c
            ${BPF_CAPSULE_LIBC_DIR}/tlsf_capsule.c ${BPF_CAPSULE_LIBC_DIR}/softfloat.c
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${PUREDOOM_SOURCE_DIR} ${BPF_CAPSULE_LIBC_DIR}
                        ${BPF_CAPSULE_LIBC_DIR}/include
    COMPILE_OPTIONS -Wno-unused-function -Wno-unused-variable -Wno-parentheses -Wno-enum-compare -g
)

bpf_capsule_object(
    doom_bpf_output
    OUTPUT doom_bpf_lib.o
    BITCODE ${DOOM_BITCODE}
)
bpf_capsule_skeleton(
    doom_skeleton
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/doom.skel.h"
    OBJECT "${CMAKE_CURRENT_BINARY_DIR}/doom_bpf_lib.o"
    NAME doom
    DEPENDS doom_bpf_output
)

add_executable(doom doom.c bpf_ctrl.h "${CMAKE_CURRENT_BINARY_DIR}/doom.skel.h")
target_include_directories(
    doom PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" ${BPF_CAPSULE_INCLUDE_DIRS}
                 "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_options(doom PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(doom ${BPF_CAPSULE_HOST_TARGET})
add_dependencies(doom doom_skeleton)

install(TARGETS doom RUNTIME DESTINATION libexec/bpf-capsule/examples/doom)
if(BPF_CAPSULE_INSTALL_TEST_ARTIFACTS)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/doom_bpf_lib.o"
            DESTINATION libexec/bpf-capsule/examples/doom
    )
endif()
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/bpf-capsule-doom)
install(
    FILES "${PUREDOOM_UPSTREAM_SOURCE_DIR}/PureDOOM.h"
          doom.c
          doom_bpf.c
          bpf_ctrl.h
          CMakeLists.txt
          LICENSE
    DESTINATION share/bpf-capsule/examples/doom/source
)
install(DIRECTORY patches/ DESTINATION share/bpf-capsule/examples/doom/source/patches
        FILES_MATCHING PATTERN "*.patch")
