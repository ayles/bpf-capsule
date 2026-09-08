# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsulePythonXdp LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)
add_subdirectory(../../ports/cpython ports/cpython)

bpf_capsule_object(
    python_xdp_bpf
    OUTPUT python-xdp.bpf.o
    SOURCES python_xdp_bpf.c python_xdp_runtime.c
    LIBRARIES capsule_cpython
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS} --fiber-stack=2097152
)
bpf_capsule_skeleton(python_xdp_skeleton OUTPUT python_xdp.skel.h OBJECT "${python_xdp_bpf}" NAME python_xdp)

add_executable(python_xdp python_xdp_host.c)
set_target_properties(python_xdp PROPERTIES OUTPUT_NAME python-xdp)
add_dependencies(python_xdp cpython_stdlib)
target_compile_options(python_xdp PRIVATE -Wall -Wextra)
target_link_libraries(python_xdp PRIVATE BpfCapsule::host python_xdp_skeleton)

get_target_property(python_stdlib_image capsule_cpython BPF_CAPSULE_CPYTHON_STDLIB)
install(TARGETS python_xdp RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${python_xdp_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${python_stdlib_image}" DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/python-xdp")
