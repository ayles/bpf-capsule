# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Ordinary static libraries cross-compiled with bpf-capsule-cc and llvm-ar.
cmake_minimum_required(VERSION 3.24)
project(CapsulePythonLibraries LANGUAGES C)
# CMake cannot scan a bitcode archive for its binary ABI probe strings.
# bpf-capsule-cc always targets bpfel, independently of the host architecture.
set(CMAKE_C_BYTE_ORDER LITTLE_ENDIAN)
include(FetchContent)
include(GNUInstallDirs)
find_package(Patch REQUIRED)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zlib
    URL https://github.com/madler/zlib/archive/da607da739fa6047df13e66a2af6b8bec7c2a498.tar.gz
    URL_HASH SHA256=b9258cf6254e7f7c37f1cd61dba943a1c5ea3cff5718c789834dac359094f5f7
)
FetchContent_MakeAvailable(zlib)

# bzip2 has a Makefile, but no upstream CMake project.
FetchContent_Declare(
    bzip2
    URL https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz
    URL_HASH SHA256=ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269
)
FetchContent_MakeAvailable(bzip2)
add_library(
    bz2
    STATIC
    ${bzip2_SOURCE_DIR}/blocksort.c
    ${bzip2_SOURCE_DIR}/huffman.c
    ${bzip2_SOURCE_DIR}/crctable.c
    ${bzip2_SOURCE_DIR}/randtable.c
    ${bzip2_SOURCE_DIR}/compress.c
    ${bzip2_SOURCE_DIR}/decompress.c
    ${bzip2_SOURCE_DIR}/bzlib.c
)
install(TARGETS bz2 ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${bzip2_SOURCE_DIR}/bzlib.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Capsule cannot start worker threads; the streaming codecs remain complete.
set(XZ_THREADS no CACHE STRING "" FORCE)
set(XZ_NLS OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_SCRIPTS OFF CACHE BOOL "" FORCE)
set(XZ_DOC OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    xz
    URL https://github.com/tukaani-project/xz/releases/download/v5.8.3/xz-5.8.3.tar.xz
    URL_HASH SHA256=fff1ffcf2b0da84d308a14de513a1aa23d4e9aa3464d17e64b9714bfdd0bbfb6
    SOURCE_SUBDIR
    _source_only
)
FetchContent_MakeAvailable(xz)
# Upstream's codecs support unknown CPU/memory capacity (returning zero),
# but its CMake frontend treats that supported fallback as a configuration
# error. Keep the sources intact except for changing that error to a warning.
FetchContent_Populate(
    xz_patched
    URL "${xz_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}"
        --quiet
        --batch
        --read-only=ignore
        -p1
        -i
        "${CMAKE_CURRENT_SOURCE_DIR}/xz-cmake.patch"
)
add_subdirectory("${xz_patched_SOURCE_DIR}" "${xz_patched_BINARY_DIR}")

set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    zstd
    URL https://github.com/facebook/zstd/archive/v1.5.7.tar.gz
    URL_HASH SHA256=37d7284556b20954e56e1ca85b80226768902e2edabd3b649e9e72c0c9012ee3
    SOURCE_SUBDIR
    build/cmake
)
FetchContent_MakeAvailable(zstd)

FetchContent_Declare(
    sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA256=1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d
)
FetchContent_MakeAvailable(sqlite)
add_library(sqlite3 STATIC ${sqlite_SOURCE_DIR}/sqlite3.c sqlite_platform.c)
target_include_directories(sqlite3 PRIVATE ${sqlite_SOURCE_DIR} ${CAPSULE_INCLUDE_DIR})
# Use SQLite's documented embedder hooks: an in-memory-only VFS and real
# recursive fiber mutexes. Dynamic native extensions cannot execute in BPF.
target_compile_definitions(sqlite3 PRIVATE SQLITE_OS_OTHER=1 SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION)
install(TARGETS sqlite3 ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${sqlite_SOURCE_DIR}/sqlite3.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Keep the original dependency notices beside the installed bitcode archives.
install(FILES ${zlib_SOURCE_DIR}/LICENSE DESTINATION share/licenses/zlib)
install(FILES ${bzip2_SOURCE_DIR}/LICENSE DESTINATION share/licenses/bzip2)
install(FILES ${xz_SOURCE_DIR}/COPYING ${xz_SOURCE_DIR}/COPYING.0BSD DESTINATION share/licenses/xz)
install(FILES ${zstd_SOURCE_DIR}/LICENSE DESTINATION share/licenses/zstd)
