# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleFib LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

bpf_capsule_object(
    fib_bpf
    OUTPUT fib.bpf.o
    SOURCES fib_bpf.c
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)

bpf_capsule_skeleton(fib_skeleton OUTPUT fib.skel.h OBJECT "${fib_bpf}" NAME fib)

add_executable(fib fib_host.c)
target_compile_options(fib PRIVATE -Wall -Wextra)
target_link_libraries(fib PRIVATE BpfCapsule::host fib_skeleton)

install(TARGETS fib RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${fib_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
