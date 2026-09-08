# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Compiler-rt's ordinary C sources become a profile-neutral bitcode archive.
# No source patches or replacement implementations are needed.
# This is llvmPackages_23's monorepoSrc from the nixpkgs pinned in flake.lock.
# Keep this commit and the nixpkgs LLVM source pin in sync when updating.
include(FetchContent)
FetchContent_Declare(
    compiler_rt
    URL https://github.com/llvm/llvm-project/archive/acdf320b78fcf075ddcf660b51cf18d5c0af755b.tar.gz
    URL_HASH SHA256=8deb068ad973fd73400f2d2a20ec1801d064ff840c72863421d0f09da9cc783e
    SOURCE_SUBDIR
    _bpf_capsule_source_only
)
FetchContent_MakeAvailable(compiler_rt)

set(compiler_rt_builtins "${compiler_rt_SOURCE_DIR}/compiler-rt/lib/builtins")
set(compiler_rt_sources
    adddf3
    subdf3
    muldf3
    divdf3
    comparedf2
    floatdidf
    floatundidf
    fixdfdi
    fixunsdfdi
    extendsfdf2
    truncdfsf2
    addsf3
    subsf3
    mulsf3
    divsf3
    comparesf2
    floatdisf
    floatundisf
    fixsfdi
    fixunssfdi
    negdf2
    negsf2
    fp_mode
    clzdi2
    clzsi2
    multi3
    udivmodti4
    udivti3
    umodti3
    divti3
    modti3
    mulodi4
)
file(GLOB compiler_rt_headers "${compiler_rt_builtins}/*.h" "${compiler_rt_builtins}/*.inc")
set(compiler_rt_objects)
# __SOFTFP__ selects integer conversions instead of recursively emitting the
# floating-point operations we are lowering. The soft-float sources use their
# 64-bit-limb path rather than introducing new i128 arithmetic here.
foreach(name IN LISTS compiler_rt_sources)
    set(source "${compiler_rt_builtins}/${name}.c")
    set(object "${CMAKE_CURRENT_BINARY_DIR}/compiler-rt/${name}.bc")
    add_custom_command(
        OUTPUT "${object}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/compiler-rt"
        COMMAND
            $<TARGET_FILE:bpf-capsule-cc> -g -D__SOFTFP__ -U__SIZEOF_INT128__ -include
            "${PROJECT_SOURCE_DIR}/src/runtime/compiler/compiler_rt.h" -c "${source}" -o "${object}"
        DEPENDS
            bpf-capsule-cc
            bpf_capsule_picolibc
            "${source}"
            ${compiler_rt_headers}
            "${PROJECT_SOURCE_DIR}/src/runtime/compiler/compiler_rt.h"
        VERBATIM
    )
    list(APPEND compiler_rt_objects "${object}")
    # The unprivileged differential test compiles the very same sources with
    # the host compiler. Keep their local includes beside them in the SDK.
    install(FILES "${source}" DESTINATION "${BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR}/compiler-rt")
endforeach()
install(FILES ${compiler_rt_headers} DESTINATION "${BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR}/compiler-rt")
set(BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/compiler-rt/libclang_rt.builtins.a")
add_custom_command(
    OUTPUT "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}"
    COMMAND "${BPF_CAPSULE_LLVM_AR}" rcs "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}" ${compiler_rt_objects}
    DEPENDS ${compiler_rt_objects}
    VERBATIM
)
add_custom_target(bpf_capsule_compiler_rt ALL DEPENDS "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}")
install(FILES "${BPF_CAPSULE_COMPILER_RUNTIME_ARCHIVE}" DESTINATION "${BPF_CAPSULE_INSTALL_COMPILER_RUNTIME_DIR}")
install(
    FILES "${compiler_rt_SOURCE_DIR}/compiler-rt/LICENSE.TXT"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/compiler-rt"
)
