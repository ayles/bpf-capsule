# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleWasm3 LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

FetchContent_Declare(
    wasm3
    GIT_REPOSITORY https://github.com/wasm3/wasm3.git
    GIT_TAG 0cd38327f0c721e75172f4f1eeb55854dc0517af
    GIT_SHALLOW FALSE
)
FetchContent_Populate(wasm3)

# The host uses zlib to prepare the input; the interpreted wasm32 module uses
# the same sources to decompress it.
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

# This module needs only the core interpreter, not wasm3's optional host APIs.
file(GLOB WASM3_SRC ${wasm3_SOURCE_DIR}/source/*.c)
list(FILTER WASM3_SRC EXCLUDE REGEX "/m3_api_.*\\.c$")

set(WASM_ZLIB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/guest_zlib.c
    ${zlib_SOURCE_DIR}/inflate.c
    ${zlib_SOURCE_DIR}/inftrees.c
    ${zlib_SOURCE_DIR}/inffast.c
    ${zlib_SOURCE_DIR}/adler32.c
    ${zlib_SOURCE_DIR}/crc32.c
    ${zlib_SOURCE_DIR}/zutil.c
)
# Compile the module to freestanding wasm32.
find_program(WASM3_CLANG NAMES clang-${BPF_CAPSULE_LLVM_MAJOR} clang REQUIRED)
set(WASM_ZLIB_MODULE "${CMAKE_CURRENT_BINARY_DIR}/zlib_guest.wasm")
add_custom_command(
    OUTPUT "${WASM_ZLIB_MODULE}"
    COMMAND
        "${WASM3_CLANG}" --target=wasm32 -fuse-ld=lld -O2 -nostdlib -DZ_SOLO -I${CMAKE_CURRENT_SOURCE_DIR}
        -I${BPF_CAPSULE_INCLUDE_DIR} -I${zlib_SOURCE_DIR} -Wl,--no-entry -Wl,--export=guest_zlib_run
        -Wl,--export=guest_zin -Wl,--export=guest_zout -Wl,--export=guest_zctrl ${WASM_ZLIB_SOURCES} -o
        "${WASM_ZLIB_MODULE}"
    DEPENDS ${WASM_ZLIB_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/wasm3_ctrl.h
    VERBATIM
    COMMAND_EXPAND_LISTS
)

bpf_capsule_object(
    wasm3_bpf
    OUTPUT wasm3.bpf.o
    DEPENDS "${WASM_ZLIB_MODULE}"
    SOURCES wasm3_bpf.c ${WASM3_SRC}
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR} ${wasm3_SOURCE_DIR}/source
    # Leave half of the fiber stack for the C frames surrounding wasm3's
    # recursive interpreter calls.
    COMPILE_DEFINITIONS d_m3MaxNativeStack=${BPF_CAPSULE_FIBER_STACK_BYTES}/2
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(wasm3_skeleton OUTPUT wasm3.skel.h OBJECT "${wasm3_bpf}" NAME wasm3)

add_executable(wasm3 wasm3_host.c)
target_compile_options(wasm3 PRIVATE -Wall -Wextra)
target_link_libraries(wasm3 PRIVATE BpfCapsule::host wasm3_skeleton ZLIB::ZLIBSTATIC)

install(TARGETS wasm3 RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${wasm3_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${wasm3_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-wasm3/wasm3")
install(FILES "${zlib_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-wasm3/zlib")
