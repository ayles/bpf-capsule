# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# The capsule passes as an object library, linked statically into
# bpf-capsule-ld. OBJECT (not STATIC) is load-bearing: several files register
# themselves purely through static initializers (the machine pass, cl::opts),
# and an archive would drop their unreferenced members.
add_library(
    bpf_capsule_passes OBJECT
    # shared support
    common.cpp
    target.cpp
    # one file per pass (atomics fuses two passes that share a predicate)
    atomics.cpp
    define_undef.cpp
    expand_i128.cpp
    expand_mem.cpp
    expand_sret.cpp
    internalize.cpp
    validate_no_float.cpp
    lower_arena_sext.cpp
    memory.cpp
    inline_policy.cpp
    normalize_irreducible.cpp
    no_jump_tables.cpp
    capsule_domains.cpp
    lower_capsule_call.cpp
    lower_capsule_exit.cpp
    lower_sdiv.cpp
    suspend_barriers.cpp
    sanitize_btf.cpp
    scalarize_agg.cpp
    softfloat.cpp
    split_shift63.cpp
    stackify.cpp
    # late machine pass (registers itself into codegen via TargetPassConfig)
    machine_stack_budget.cpp
    unified_spills_mir.cpp
    machine_flatten.cpp
    # pipeline string + pass-name registration for the linker
    registry.cpp
)
target_include_directories(
    bpf_capsule_passes PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
                              "${CMAKE_CURRENT_SOURCE_DIR}/../runtime/internal"
                              "${CMAKE_CURRENT_SOURCE_DIR}/../runtime/guest"
)
target_include_directories(bpf_capsule_passes SYSTEM PUBLIC ${BPF_CAPSULE_LLVM_INCLUDE_DIRS})
target_compile_definitions(bpf_capsule_passes PUBLIC ${BPF_CAPSULE_LLVM_DEFINITIONS})
target_compile_options(bpf_capsule_passes PRIVATE -fno-rtti -fno-exceptions)
set_target_properties(bpf_capsule_passes PROPERTIES POSITION_INDEPENDENT_CODE ON)
