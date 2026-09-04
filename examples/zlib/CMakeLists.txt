# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# In-kernel zlib: stock zlib sources (inflate side) through the standard
# pipeline. The same source tree supplies the native compressor in the host.
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleZlib LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG da607da739fa6047df13e66a2af6b8bec7c2a498
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(zlib)

set(ZLIB_SRC
    ${zlib_SOURCE_DIR}/inflate.c
    ${zlib_SOURCE_DIR}/inftrees.c
    ${zlib_SOURCE_DIR}/inffast.c
    ${zlib_SOURCE_DIR}/adler32.c
    ${zlib_SOURCE_DIR}/crc32.c
    ${zlib_SOURCE_DIR}/zutil.c
)

bpf_capsule_object(
    zlib_bpf
    OUTPUT zlib.bpf.o
    SOURCES zlib_bpf.c ${ZLIB_SRC}
    INCLUDE_DIRECTORIES ${zlib_SOURCE_DIR}
    COMPILE_DEFINITIONS Z_SOLO
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(zlib_skeleton OUTPUT zlib.skel.h OBJECT "${zlib_bpf}" NAME zlib)

add_executable(zlib zlib_host.c)
target_compile_options(zlib PRIVATE -Wall -Wextra)
target_link_libraries(zlib PRIVATE BpfCapsule::host zlib_skeleton ZLIB::ZLIBSTATIC)

install(TARGETS zlib RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${zlib_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(
    FILES "${zlib_SOURCE_DIR}/LICENSE"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-examples"
    RENAME zlib-LICENSE
)
