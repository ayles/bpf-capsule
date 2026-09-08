# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)

FetchContent_Declare(
    wasm3
    GIT_REPOSITORY https://github.com/wasm3/wasm3.git
    GIT_TAG 0cd38327f0c721e75172f4f1eeb55854dc0517af
    GIT_SHALLOW FALSE
)
FetchContent_Populate(wasm3)
file(GLOB wasm3_sources "${wasm3_SOURCE_DIR}/source/*.c")
list(FILTER wasm3_sources EXCLUDE REGEX "/m3_api_.*\\.c$")
# Leave half of the default 256 KiB stack for the surrounding C frames.
# The internal headers used by embedders need the same stack layout.
bpf_capsule_library(capsule_wasm3 SOURCES ${wasm3_sources})
target_include_directories(capsule_wasm3 PUBLIC "${wasm3_SOURCE_DIR}/source")
target_compile_definitions(capsule_wasm3 PUBLIC d_m3MaxNativeStack=131072)
target_compile_options(capsule_wasm3 PRIVATE -g)
install(FILES "${wasm3_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/wasm3")
