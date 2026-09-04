# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleLlama2 LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(BpfCapsule CONFIG REQUIRED)

FetchContent_Declare(
    llama2
    GIT_REPOSITORY https://github.com/karpathy/llama2.c.git
    GIT_TAG 350e04fe35433e6d2941dce5a1f53308f87058eb
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(llama2)

bpf_capsule_object(
    llama2_bpf
    OUTPUT llama2.bpf.o
    SOURCES llama2_bpf.c
    INCLUDE_DIRECTORIES ${llama2_SOURCE_DIR}
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(llama2_skeleton OUTPUT llama2.skel.h OBJECT "${llama2_bpf}" NAME llama2)

add_executable(llama2 llama2_host.c)
target_include_directories(llama2 SYSTEM PRIVATE "${llama2_SOURCE_DIR}")
target_compile_options(llama2 PRIVATE -Wall -Wextra)
target_link_libraries(llama2 PRIVATE BpfCapsule::host llama2_skeleton m)

# The int8 path uses checkpoint-selected scale groups. Most arithmetic becomes
# integer dot products; the fp32 build above performs it through soft-float.
bpf_capsule_object(
    llama2q_bpf
    OUTPUT llama2q.bpf.o
    SOURCES llama2q_bpf.c
    INCLUDE_DIRECTORIES ${llama2_SOURCE_DIR}
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(llama2q_skeleton OUTPUT llama2q.skel.h OBJECT "${llama2q_bpf}" NAME llama2q)

add_executable(llama2-q8 llama2_host.c)
target_include_directories(llama2-q8 SYSTEM PRIVATE "${llama2_SOURCE_DIR}")
target_compile_options(llama2-q8 PRIVATE -Wall -Wextra)
target_compile_definitions(llama2-q8 PRIVATE LLAMA2_QUANTIZED)
target_link_libraries(llama2-q8 PRIVATE BpfCapsule::host llama2q_skeleton m)

install(TARGETS llama2 llama2-q8 RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${llama2_bpf}" "${llama2q_bpf}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(
    FILES "${llama2_SOURCE_DIR}/LICENSE"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule-examples"
    RENAME llama2.c-LICENSE
)
