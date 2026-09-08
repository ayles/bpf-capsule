# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleWasm3 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

add_subdirectory(../../ports/wasm3 ports/wasm3)
add_subdirectory(../../ports/zlib ports/zlib)
# The host compresses with native zlib; the interpreted module uses its inflater.
get_target_property(zlib_sources capsule_zlib BPF_CAPSULE_SOURCES)
get_target_property(zlib_includes capsule_zlib INTERFACE_INCLUDE_DIRECTORIES)
set(WASM_ZLIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/guest_zlib.c ${zlib_sources})
# Compile the module to freestanding wasm32.
find_program(WASM3_CLANG NAMES clang-${BPF_CAPSULE_LLVM_MAJOR} clang REQUIRED)
set(WASM_ZLIB_MODULE "${CMAKE_CURRENT_BINARY_DIR}/zlib_guest.wasm")
add_custom_command(
    OUTPUT "${WASM_ZLIB_MODULE}"
    COMMAND
        "${WASM3_CLANG}" --target=wasm32 -fuse-ld=lld -O2 -nostdlib -DZ_SOLO -I${CMAKE_CURRENT_SOURCE_DIR}
        -I${BPF_CAPSULE_INCLUDE_DIR} "-I$<JOIN:${zlib_includes},;-I>" -Wl,--no-entry -Wl,--export=guest_zlib_run
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
    SOURCES wasm3_bpf.c
    LIBRARIES capsule_wasm3
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(wasm3_skeleton OUTPUT wasm3.skel.h OBJECT "${wasm3_bpf}" NAME wasm3)

add_executable(wasm3 wasm3_host.c)
target_compile_options(wasm3 PRIVATE -Wall -Wextra)
target_link_libraries(wasm3 PRIVATE BpfCapsule::host wasm3_skeleton ZLIB::ZLIBSTATIC)

install(TARGETS wasm3 RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${wasm3_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
