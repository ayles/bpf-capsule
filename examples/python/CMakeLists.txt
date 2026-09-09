# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsulePython LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)
add_subdirectory(../../ports/cpython ports/cpython)

bpf_capsule_object(
    python_bpf
    OUTPUT python.bpf.o
    SOURCES python_bpf.c
    LIBRARIES capsule_cpython
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}
    COMPILE_OPTIONS -g
    # CPython has individual frames larger than the default 256 KiB stack.
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS} --fiber-stack=2097152
)
bpf_capsule_skeleton(python_skeleton OUTPUT python.skel.h OBJECT "${python_bpf}" NAME python)

find_package(Python3 3.14 COMPONENTS Interpreter REQUIRED)
add_executable(python python_host.c)
add_dependencies(python cpython_stdlib)
target_compile_options(python PRIVATE -Wall -Wextra)
# --native runs the same script under the interpreter the port was built with.
target_compile_definitions(python PRIVATE "PYTHON_NATIVE_INTERPRETER=\"${Python3_EXECUTABLE}\"")
target_link_libraries(python PRIVATE BpfCapsule::host python_skeleton)

get_target_property(python_stdlib_image capsule_cpython BPF_CAPSULE_CPYTHON_STDLIB)
install(TARGETS python RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${python_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${python_stdlib_image}" DESTINATION "${CMAKE_INSTALL_DATADIR}/bpf-capsule/python")
