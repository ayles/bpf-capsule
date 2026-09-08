# SPDX-License-Identifier: GPL-2.0-only
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)
find_package(Patch REQUIRED)

FetchContent_Declare(
    puredoom
    GIT_REPOSITORY https://github.com/Daivuk/PureDOOM.git
    GIT_TAG 355cfbd16fac119718879239336ee2ea408886bd
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(puredoom)
# Patch a private copy: initialize the framebuffer and bound sparse cached
# lumps in the column drawer. Neither rendering fix is Capsule-specific.
# gersemi: off
FetchContent_Populate(
    puredoom_patched
    URL "${puredoom_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}" --quiet --batch --read-only=ignore -p1 -i
        "${CMAKE_CURRENT_SOURCE_DIR}/patches/puredoom.patch"
)
# gersemi: on

file(GLOB puredoom_sources "${puredoom_patched_SOURCE_DIR}/src/DOOM/*.c")
bpf_capsule_library(capsule_puredoom SOURCES ${puredoom_sources})
target_include_directories(capsule_puredoom PUBLIC "${puredoom_patched_SOURCE_DIR}/src/DOOM")
target_compile_options(capsule_puredoom PRIVATE -Wno-parentheses -g)
install(FILES "${puredoom_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/puredoom")
# Keep the original source and the identified modifications with distributions.
install(FILES CMakeLists.txt DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/ports/puredoom")
install(
    DIRECTORY "${puredoom_SOURCE_DIR}/src/DOOM"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/ports/puredoom/upstream/src"
)
install(
    FILES "${puredoom_SOURCE_DIR}/LICENSE"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/ports/puredoom/upstream"
)
install(DIRECTORY patches/ DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/ports/puredoom/patches")
