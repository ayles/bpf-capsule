# SPDX-License-Identifier: GPL-2.0-only
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleDoom LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)
add_subdirectory(../../ports/puredoom ports/puredoom)
bpf_capsule_object(
    doom_bpf
    OUTPUT doom.bpf.o
    SOURCES doom_bpf.c
    LIBRARIES capsule_puredoom
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}
    # Upstream intentionally uses assignment in its WAD-probing conditions.
    COMPILE_OPTIONS -Wno-parentheses -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS} --loop-budget-multiplier=4
)
bpf_capsule_skeleton(doom_skeleton OUTPUT doom.skel.h OBJECT "${doom_bpf}" NAME doom)

add_executable(doom doom.c)
target_compile_options(doom PRIVATE -Wall -Wextra -Wno-parentheses)
target_link_libraries(doom PRIVATE BpfCapsule::host doom_skeleton puredoom_native)

install(TARGETS doom RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${doom_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-doom")
install(
    FILES doom.c doom_bpf.c doom_engine.h bpf_ctrl.h CMakeLists.txt LICENSE
    DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/examples/doom"
)
