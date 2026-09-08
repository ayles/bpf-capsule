# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel zlib: stock zlib sources (inflate side) through the standard
# pipeline. The same source tree supplies the native compressor in the host.
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleZlib LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/zlib ports/zlib)

bpf_capsule_object(
    zlib_bpf
    OUTPUT zlib.bpf.o
    SOURCES zlib_bpf.c
    LIBRARIES capsule_zlib
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(zlib_skeleton OUTPUT zlib.skel.h OBJECT "${zlib_bpf}" NAME zlib)

add_executable(zlib zlib_host.c)
target_compile_options(zlib PRIVATE -Wall -Wextra)
target_link_libraries(zlib PRIVATE BpfCapsule::host zlib_skeleton ZLIB::ZLIBSTATIC)

install(TARGETS zlib RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${zlib_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
