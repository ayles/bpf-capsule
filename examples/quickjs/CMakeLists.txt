# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleQuickJS LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/quickjs ports/quickjs)

bpf_capsule_object(
    quickjs_bpf
    OUTPUT quickjs.bpf.o
    SOURCES quickjs_bpf.c
    LIBRARIES capsule_quickjs
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(quickjs_skeleton OUTPUT quickjs.skel.h OBJECT "${quickjs_bpf}" NAME quickjs)

add_executable(quickjs quickjs_host.c)
target_compile_options(quickjs PRIVATE -Wall -Wextra)
target_link_libraries(quickjs PRIVATE BpfCapsule::host quickjs_skeleton)

install(TARGETS quickjs RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${quickjs_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
