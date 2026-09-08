# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)

# The same sources supply the native compressor and the Capsule inflater.
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

set(zlib_inflate_sources
    "${zlib_SOURCE_DIR}/inflate.c"
    "${zlib_SOURCE_DIR}/inftrees.c"
    "${zlib_SOURCE_DIR}/inffast.c"
    "${zlib_SOURCE_DIR}/adler32.c"
    "${zlib_SOURCE_DIR}/crc32.c"
    "${zlib_SOURCE_DIR}/zutil.c"
)
bpf_capsule_library(capsule_zlib SOURCES ${zlib_inflate_sources})
target_include_directories(capsule_zlib PUBLIC "${zlib_SOURCE_DIR}")
target_compile_definitions(capsule_zlib PRIVATE Z_SOLO)
target_compile_options(capsule_zlib PRIVATE -g)
# wasm3 compiles this same inflater for wasm32, not through the Capsule linker.
set_property(TARGET capsule_zlib PROPERTY BPF_CAPSULE_SOURCES "${zlib_inflate_sources}")
install(FILES "${zlib_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/zlib")
