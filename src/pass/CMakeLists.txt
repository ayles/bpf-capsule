# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
find_package(LLVM REQUIRED)

# The IR pipeline and late machine passes are tied to one LLVM major. Refuse
# anything else instead of failing late and opaquely.
if(NOT LLVM_VERSION_MAJOR EQUAL 22)
    message(FATAL_ERROR "BPF Capsule requires LLVM 22; find_package(LLVM) found "
                        "LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}"
    )
endif()
# Recorded for the installed package config, which re-checks the consumer's
# discovered llc/clang/opt against the plugin's LLVM major.
set(BPF_CAPSULE_PLUGIN_LLVM_MAJOR
    "${LLVM_VERSION_MAJOR}"
    CACHE INTERNAL "LLVM major version the pass plugin is built against"
)

include(AddLLVM)

add_llvm_pass_plugin(
    bpf_capsule_pass
    common.cpp
    partition.cpp
    pass.cpp
    softfloat.cpp
    unified_spills_mir.cpp
    stackify.cpp
    internalize_runtime.cpp
    memory.cpp
    target.cpp
    varargs.cpp
)

target_include_directories(bpf_capsule_pass PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../runtime/abi")

install(
    TARGETS bpf_capsule_pass
    EXPORT BpfCapsuleTargets
    LIBRARY DESTINATION lib/bpf-capsule
)
