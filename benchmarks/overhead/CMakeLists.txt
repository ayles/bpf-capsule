# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
_bpf_capsule_implicit_include_flags(OVERHEAD_SYSTEM_INCLUDE_FLAGS C)
set(OVERHEAD_DIRECT_FLAGS
    -target
    bpf
    -mcpu=${_BPF_CAPSULE_CPU}
    -DBPF_CAPSULE_TARGET_KERNEL=${_BPF_CAPSULE_RUNTIME_TARGET}
    -DBPF_CAPSULE_FIBER_STACK_BYTES=${BPF_CAPSULE_FIBER_STACK_BYTES}
    ${OVERHEAD_SYSTEM_INCLUDE_FLAGS}
    -I${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/guest
    -I${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/abi
    -I${CMAKE_CURRENT_SOURCE_DIR}
    -nostdlib
    -ffreestanding
    -fno-unroll-loops
    -Wno-option-ignored
    -Wno-unused-command-line-argument
    -g
    -O2
    -mllvm
    -bpf-stack-size=512
)
foreach(directory IN LISTS LibBpf_INCLUDE_DIRS)
    list(APPEND OVERHEAD_DIRECT_FLAGS -I${directory})
endforeach()

set(OVERHEAD_BPF_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/guest
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/runtime/abi ${CMAKE_CURRENT_SOURCE_DIR}
)

# Stock clang -> eBPF: no project pass and no project runtime.
add_custom_command(
    OUTPUT overhead_direct.o
    COMMAND
        ${CMAKE_COMMAND} -E env NIX_CFLAGS_COMPILE= NIX_CFLAGS_LINK= ${BPF_CAPSULE_CLANG}
        ${OVERHEAD_DIRECT_FLAGS} -DOH_DIRECT -c ${CMAKE_CURRENT_SOURCE_DIR}/overhead_bpf.c -o
        overhead_direct.o
    DEPENDS overhead_bpf.c overhead_ctrl.h workload.h
    VERBATIM
)
add_custom_target(overhead_direct_output DEPENDS overhead_direct.o)

# Identical workload source, now compiled as IR and sent through the complete
# transformation pipeline and normal late code generator.
bpf_capsule_bitcode(
    OVERHEAD_MANAGED_BC
    INCLUDE_DIRECTORIES ${OVERHEAD_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS OH_TRANSFORMED
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/overhead_bpf.c
)

bpf_capsule_object(
    overhead_transformed_output
    OUTPUT overhead_transformed.o
    BITCODE ${OVERHEAD_MANAGED_BC}
)

# Same source and selected runtime count, with only the compile-time verifier
# bound changed. Sixty-four covers ordinary CPU counts without introducing a
# one-fiber-only code shape; the host selects its online CPU count (capped at
# 64) for both objects.
bpf_capsule_bitcode(
    OVERHEAD_MANAGED_EXACT_BC
    INCLUDE_DIRECTORIES ${OVERHEAD_BPF_INCLUDE_DIRECTORIES}
    COMPILE_DEFINITIONS OH_TRANSFORMED BPF_CAPSULE_MAX_FIBERS=64
    COMPILE_OPTIONS -g
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/overhead_exact_bpf.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/overhead_bpf.c
)

bpf_capsule_object(
    overhead_transformed_exact_output
    OUTPUT overhead_transformed_exact.o
    BITCODE ${OVERHEAD_MANAGED_EXACT_BC}
    RUNTIME_COMPILE_DEFINITIONS BPF_CAPSULE_MAX_FIBERS=64
)

add_executable(overhead_host overhead_host.c)
target_include_directories(
    overhead_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_options(overhead_host PRIVATE -O2 -fno-unroll-loops)
target_compile_definitions(overhead_host PRIVATE OH_COMPARISON_MAX_FIBERS=64)
target_link_libraries(overhead_host PkgConfig::LibBpf)
add_dependencies(
    overhead_host overhead_direct_output overhead_transformed_output
    overhead_transformed_exact_output
)

install(TARGETS overhead_host RUNTIME DESTINATION libexec/bpf-capsule/benchmarks/overhead)
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/overhead_direct.o"
          "${CMAKE_CURRENT_BINARY_DIR}/overhead_transformed.o"
          "${CMAKE_CURRENT_BINARY_DIR}/overhead_transformed_exact.o"
    DESTINATION libexec/bpf-capsule/benchmarks/overhead
)

# ---------------------------------------------------------------- Rust path
# One no_std crate is linked into a native executable, a stock rustc/LLVM eBPF
# object, and the full transformed runtime.  rustc emits target rlibs as LLVM
# bitcode, so the small extraction/link sequence mirrors examples/rust without
# bringing alloc or any libc into this integer-only benchmark.
find_program(OVERHEAD_RUSTC rustc)
if(OVERHEAD_RUSTC)
    # Global BPF subprograms need BTF function records. rustc only gives llc
    # enough DISubprogram metadata to emit those records when debuginfo is on;
    # without it libbpf cannot relocate the direct object's Rust calls.
    add_custom_command(
        OUTPUT rust_overhead_bpf.a
        COMMAND
            ${CMAKE_COMMAND} -E env NIX_CFLAGS_COMPILE= NIX_CFLAGS_LINK= ${OVERHEAD_RUSTC} --edition
            2021 --target bpfel-unknown-none --crate-name rust_overhead_bpf --crate-type staticlib
            -C panic=abort -C opt-level=2 -C codegen-units=1 -C debuginfo=2 -C no-prepopulate-passes
            ${CMAKE_CURRENT_SOURCE_DIR}/rust_workload.rs -o rust_overhead_bpf.a
        DEPENDS rust_workload.rs
        COMMENT "rustc (bpf) integer overhead workload"
        VERBATIM
    )

    add_custom_command(
        OUTPUT rust_overhead_crate.bc
        COMMAND
            "${CMAKE_COMMAND}" "-DBPF_CAPSULE_LLVM_AR=${BPF_CAPSULE_LLVM_AR}"
            "-DBPF_CAPSULE_LLVM_LINK=${BPF_CAPSULE_LLVM_LINK}"
            "-DBPF_CAPSULE_RUST_ARCHIVE=${CMAKE_CURRENT_BINARY_DIR}/rust_overhead_bpf.a"
            "-DBPF_CAPSULE_RUST_CRATE_NAME=rust_overhead_bpf"
            "-DBPF_CAPSULE_RUST_WORK_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/rust_oh_mem"
            "-DBPF_CAPSULE_RUST_OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/rust_overhead_crate.bc" -P
            "${CMAKE_CURRENT_LIST_DIR}/../../cmake/ExtractRustBitcode.cmake"
        DEPENDS rust_overhead_bpf.a "${CMAKE_CURRENT_LIST_DIR}/../../cmake/ExtractRustBitcode.cmake"
        COMMENT "Extract Rust overhead bitcode"
        VERBATIM
    )
    add_custom_target(rust_overhead_crate_output DEPENDS rust_overhead_crate.bc)

    bpf_capsule_bitcode(
        RUST_OH_DIRECT_DRIVER_BC
        INCLUDE_DIRECTORIES ${OVERHEAD_BPF_INCLUDE_DIRECTORIES}
        COMPILE_OPTIONS -g
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rust_overhead_direct_bpf.c
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/rust_overhead_bpf.c
                ${CMAKE_CURRENT_SOURCE_DIR}/overhead_ctrl.h
    )
    bpf_capsule_bitcode(
        RUST_OH_TRANSFORMED_DRIVER_BC
        INCLUDE_DIRECTORIES ${OVERHEAD_BPF_INCLUDE_DIRECTORIES}
        COMPILE_OPTIONS -g
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rust_overhead_transformed_bpf.c
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/rust_overhead_bpf.c
                ${CMAKE_CURRENT_SOURCE_DIR}/overhead_ctrl.h
    )

    add_custom_command(
        OUTPUT rust_overhead_direct.o
        COMMAND ${BPF_CAPSULE_LLVM_LINK} ${RUST_OH_DIRECT_DRIVER_BC} rust_overhead_crate.bc -o
                rust_overhead_direct_link.bc
        # Ordinary link-time dead stripping removes rustc's unused panic
        # handler, whose PanicInfo prototype is not valid BTF on Linux 5.15.
        # Keep the three workload functions global so the verifier checks each
        # once, exactly as a normal direct-eBPF link should.
        COMMAND
            ${BPF_CAPSULE_OPT} --disable-loop-unrolling --passes=default<O2>,internalize,globaldce
            -internalize-public-api-list=rust_overhead_empty,rust_overhead_run,rust_oh_classify,rust_oh_mix,rust_oh_workload,rust_oh_ctrl,rust_oh_input,_license
            rust_overhead_direct_link.bc -o rust_overhead_direct_opt.bc
        COMMAND
            ${BPF_CAPSULE_LLC} -O2 -mcpu=${_BPF_CAPSULE_CPU} -filetype=obj -enable-tail-merge=false
            --bpf-stack-size=512 rust_overhead_direct_opt.bc -o rust_overhead_direct.o
        DEPENDS rust_overhead_crate_output rust_overhead_crate.bc ${RUST_OH_DIRECT_DRIVER_BC}
        COMMAND_EXPAND_LISTS VERBATIM
    )
    add_custom_target(rust_overhead_direct_output DEPENDS rust_overhead_direct.o)

    add_custom_command(
        OUTPUT rust_overhead_transformed_link.bc
        COMMAND ${BPF_CAPSULE_LLVM_LINK} ${RUST_OH_TRANSFORMED_DRIVER_BC} rust_overhead_crate.bc -o
                rust_overhead_transformed_link.bc
        DEPENDS rust_overhead_crate_output rust_overhead_crate.bc ${RUST_OH_TRANSFORMED_DRIVER_BC}
        VERBATIM
    )
    bpf_capsule_object(
        rust_overhead_transformed_output
        OUTPUT rust_overhead_transformed.o
        BITCODE rust_overhead_transformed_link.bc
        DEPENDS rust_overhead_crate_output ${RUST_OH_TRANSFORMED_DRIVER_BC}
    )

    add_custom_command(
        OUTPUT librust_overhead_native.a
        COMMAND
            ${OVERHEAD_RUSTC} --edition 2021 --crate-name rust_overhead_native --crate-type
            staticlib -C panic=abort -C opt-level=2 -C codegen-units=1 -C debuginfo=0
            ${CMAKE_CURRENT_SOURCE_DIR}/rust_workload.rs -o librust_overhead_native.a
        DEPENDS rust_workload.rs
        COMMENT "rustc (native) integer overhead workload"
        VERBATIM
    )
    add_custom_target(rust_overhead_native_output DEPENDS librust_overhead_native.a)

    add_executable(rust_overhead_host rust_overhead_host.c)
    target_include_directories(rust_overhead_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
    target_compile_options(rust_overhead_host PRIVATE -O2)
    target_link_libraries(
        rust_overhead_host PkgConfig::LibBpf ${CMAKE_CURRENT_BINARY_DIR}/librust_overhead_native.a
    )
    add_dependencies(
        rust_overhead_host rust_overhead_native_output rust_overhead_direct_output
        rust_overhead_transformed_output
    )

    install(TARGETS rust_overhead_host RUNTIME DESTINATION libexec/bpf-capsule/benchmarks/overhead)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/rust_overhead_direct.o"
                  "${CMAKE_CURRENT_BINARY_DIR}/rust_overhead_transformed.o"
            DESTINATION libexec/bpf-capsule/benchmarks/overhead
    )
endif()
