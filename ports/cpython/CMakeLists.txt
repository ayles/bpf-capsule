# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(ExternalProject)
include(FetchContent)
include(GNUInstallDirs)
find_package(Patch REQUIRED)
find_package(Python3 3.14 COMPONENTS Interpreter REQUIRED)
find_program(cpython_bash NAMES bash REQUIRED)
find_program(cpython_make NAMES gmake make REQUIRED)
foreach(tool IN ITEMS ar nm ranlib)
    find_program(
        cpython_llvm_${tool}
        NAMES llvm-${tool}-${BPF_CAPSULE_LLVM_MAJOR} llvm-${tool}
        HINTS "${BPF_CAPSULE_LLVM_TOOLS_DIR}"
        REQUIRED
    )
endforeach()
FetchContent_Declare(
    cpython
    URL https://github.com/python/cpython/archive/refs/tags/v3.14.7.tar.gz
    URL_HASH SHA256=23794c71dc5aa636ef2f6774270c3d48f755afaaa474fd3e0d49de8292b69dbb
    SOURCE_SUBDIR
    _bpf_capsule_source_only
)
FetchContent_MakeAvailable(cpython)

# CPython's compression and database modules link ordinary static libraries.
# Their upstream build systems run in a nested project with bpf-capsule-cc as
# the C compiler, so no source list is maintained here.
set(library_prefix "${CMAKE_CURRENT_BINARY_DIR}/python-libraries")
set(library_sources)
foreach(
    dependency
    ZLIB
    BZIP2
    XZ
    ZSTD
    SQLITE
)
    if(DEFINED FETCHCONTENT_SOURCE_DIR_${dependency})
        list(APPEND library_sources "-DFETCHCONTENT_SOURCE_DIR_${dependency}=${FETCHCONTENT_SOURCE_DIR_${dependency}}")
    endif()
endforeach()
set(library_archives
    "${library_prefix}/lib/libz.a"
    "${library_prefix}/lib/libbz2.a"
    "${library_prefix}/lib/liblzma.a"
    "${library_prefix}/lib/libzstd.a"
    "${library_prefix}/lib/libsqlite3.a"
)
ExternalProject_Add(
    cpython_libraries
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries"
    CMAKE_ARGS
        -DCMAKE_SYSTEM_NAME=Generic -DCMAKE_SYSTEM_PROCESSOR=bpf
        "-DCMAKE_C_COMPILER=$<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>"
        "-DCMAKE_CXX_COMPILER=$<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>"
        "-DCMAKE_ASM_COMPILER=$<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>" -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
        "-DCMAKE_AR=${cpython_llvm_ar}" "-DCMAKE_RANLIB=${cpython_llvm_ranlib}" -DCMAKE_C_FLAGS=-g
        "-DCMAKE_INSTALL_PREFIX=${library_prefix}" -DCMAKE_INSTALL_LIBDIR=lib
        "-DCAPSULE_INCLUDE_DIR=${BPF_CAPSULE_INCLUDE_DIR}" ${library_sources}
    BUILD_BYPRODUCTS ${library_archives}
)
# Keep a supplied checkout immutable and build CPython's normal Autoconf
# tree from the small Capsule platform patch.
# gersemi: off
FetchContent_Populate(
    cpython_patched
    URL "${cpython_SOURCE_DIR}"
    PATCH_COMMAND
        "${Patch_EXECUTABLE}" --quiet --batch --read-only=ignore -p1 -i
        "${CMAKE_CURRENT_SOURCE_DIR}/cpython.patch"
)
# gersemi: on

execute_process(
    COMMAND "${cpython_patched_SOURCE_DIR}/config.guess"
    OUTPUT_VARIABLE cpython_build_triple
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

# Configure only links LLVM probes and never lowers or executes them. Keep
# that support profile-neutral; the final object owns target selection.
_bpf_capsule_runtime_bitcode(cpython_runtime)
_bpf_capsule_platform_bitcode(cpython_platform)
set(cpython_configure_support
    ${cpython_runtime}
    ${cpython_platform}
    "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}"
    ${library_archives}
)
list(JOIN cpython_configure_support ":" cpython_configure_support_argument)

set(cpython_build_dir "${CMAKE_CURRENT_BINARY_DIR}/cpython")
set(cpython_tool_env
    "BPF_CAPSULE_CONFIGURE_CC=$<TARGET_FILE:${BPF_CAPSULE_CC_TARGET}>"
    "BPF_CAPSULE_CONFIGURE_LD=$<TARGET_FILE:${BPF_CAPSULE_LD_TARGET}>"
    "BPF_CAPSULE_CONFIGURE_LIBC=${BPF_CAPSULE_LIBC_ARCHIVE}"
    "BPF_CAPSULE_CONFIGURE_NM=${cpython_llvm_nm}"
    "BPF_CAPSULE_CONFIGURE_SUPPORT=${cpython_configure_support_argument}"
)
set(cpython_archives
    "${cpython_build_dir}/libpython3.14.a"
    "${cpython_build_dir}/Modules/expat/libexpat.a"
    "${cpython_build_dir}/Modules/_decimal/libmpdec/libmpdec.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_HMAC.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_Hash_BLAKE2.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_Hash_MD5.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_Hash_SHA1.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_Hash_SHA2.a"
    "${cpython_build_dir}/Modules/_hacl/libHacl_Hash_SHA3.a"
)
# HACL's portable crypto headers otherwise redeclare the endian macros that
# Picolibc already provides; select their documented system-header path.
set(cpython_cppflags -D__USE_SYSTEM_ENDIAN_H__ "-I${library_prefix}/include")
list(JOIN cpython_cppflags " " cpython_cppflags_argument)

ExternalProject_Add(
    cpython_build
    DEPENDS cpython_libraries ${cpython_runtime_target} ${cpython_platform_target}
    SOURCE_DIR "${cpython_patched_SOURCE_DIR}"
    BINARY_DIR "${cpython_build_dir}"
    CONFIGURE_COMMAND
        "${CMAKE_COMMAND}" -E env "CONFIG_SITE=${CMAKE_CURRENT_SOURCE_DIR}/configure.site" "MODULE_BUILDTYPE=static"
        ${cpython_tool_env} "CC=${cpython_bash} ${CMAKE_CURRENT_SOURCE_DIR}/configure-cc.sh" "AR=${cpython_llvm_ar}"
        "RANLIB=${cpython_llvm_ranlib}" "CPPFLAGS=${cpython_cppflags_argument}" "<SOURCE_DIR>/configure"
        "--build=${cpython_build_triple}" --host=bpf-unknown-none "--with-build-python=${Python3_EXECUTABLE}"
        --without-mimalloc --without-ensurepip --disable-test-modules --with-readline=no --with-pkg-config=no
    # encodings is needed before a custom import loader can be installed.
    # Regenerate the manifest after patching: the release archive contains
    # generated files for the upstream manifest.
    BUILD_COMMAND "${Python3_EXECUTABLE}" "<SOURCE_DIR>/Tools/build/freeze_modules.py" --frozen-modules
    COMMAND "${CMAKE_COMMAND}" -E env ${cpython_tool_env} "${cpython_make}" -j4 libpython3.14.a
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${cpython_archives}
)
ExternalProject_Add_StepDependencies(
    cpython_build
    configure
    "${CMAKE_CURRENT_SOURCE_DIR}/configure.site"
    "${CMAKE_CURRENT_SOURCE_DIR}/configure-cc.sh"
    "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}"
)
ExternalProject_Add_Step(
    cpython_build
    check_modules
    COMMAND "${CMAKE_COMMAND}" "-DBUILD_DIR=${cpython_build_dir}" -P "${CMAKE_CURRENT_SOURCE_DIR}/check_modules.cmake"
    DEPENDEES configure
    DEPENDERS build
)

file(GLOB_RECURSE cpython_stdlib_sources CONFIGURE_DEPENDS "${cpython_SOURCE_DIR}/Lib/*.py")
set(cpython_stdlib_image "${CMAKE_CURRENT_BINARY_DIR}/stdlib.pack")
add_custom_command(
    OUTPUT "${cpython_stdlib_image}"
    COMMAND
        "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/pack_stdlib.py" "${cpython_SOURCE_DIR}/Lib"
        "${cpython_stdlib_image}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/pack_stdlib.py" ${cpython_stdlib_sources}
    COMMENT "Pack the CPython standard library"
    VERBATIM
)
add_custom_target(cpython_stdlib ALL DEPENDS "${cpython_stdlib_image}")

# Embedders link capsule_cpython: the interpreter, its statically linked
# modules and libraries, the loader for the packed standard library, and the
# pthread surface that makes a fiber CPython's thread.
bpf_capsule_library(capsule_cpython SOURCES python_stdlib.c python_threads.c DEPENDS cpython_build)
target_include_directories(
    capsule_cpython
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${cpython_build_dir}" "${cpython_patched_SOURCE_DIR}/Include"
)
target_link_libraries(capsule_cpython PUBLIC ${cpython_archives} ${library_archives})
target_compile_options(capsule_cpython PRIVATE -g)
set_property(TARGET capsule_cpython PROPERTY BPF_CAPSULE_CPYTHON_STDLIB "${cpython_stdlib_image}")

set(license_dir "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/cpython")
install(DIRECTORY "${library_prefix}/share/licenses/" DESTINATION "${license_dir}")
install(FILES "${cpython_SOURCE_DIR}/LICENSE" DESTINATION "${license_dir}")
install(FILES "${cpython_SOURCE_DIR}/Modules/expat/COPYING" DESTINATION "${license_dir}/expat")

# These bundled libraries keep their notices in source headers rather than
# separate license files. Install their original text from the fetched
# release.
foreach(
    source
    IN
    ITEMS
        Modules/_decimal/libmpdec/mpdecimal.h
        Modules/_hacl/Hacl_Hash_SHA2.h
        Modules/_hacl/include/krml/internal/target.h
)
    file(READ "${cpython_SOURCE_DIR}/${source}" contents LIMIT 8192)
    string(FIND "${contents}" "*/" end)
    math(EXPR end "${end} + 2")
    string(SUBSTRING "${contents}" 0 ${end} notice)
    get_filename_component(name "${source}" NAME_WE)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${name}.LICENSE" "${notice}\n")
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${name}.LICENSE" DESTINATION "${license_dir}")
endforeach()
