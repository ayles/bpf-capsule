# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Reviewable, whole-module contracts for the compiler passes.  Inputs and
# expected outputs are checked-in LLVM text; RunIrPassCase.cmake parses and
# reprints both through the pinned LLVM toolchain before comparing them.

find_program(
    BPF_CAPSULE_LLVM_AS
    NAMES llvm-as-${LLVM_VERSION_MAJOR} llvm-as
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
find_program(
    BPF_CAPSULE_LLVM_DIS
    NAMES llvm-dis-${LLVM_VERSION_MAJOR} llvm-dis
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)
find_program(
    BPF_CAPSULE_LLC
    NAMES llc-${LLVM_VERSION_MAJOR} llc
    HINTS "${LLVM_TOOLS_BINARY_DIR}"
    REQUIRED
)

# llc's -run-pass mode is the canonical parser/printer for post-selection
# MIR. Loading the exact object library used by bpf-capsule-ld exposes the
# legacy machine passes without maintaining a second test-only registration
# path.
add_library(bpf_capsule_pass_contract_plugin MODULE $<TARGET_OBJECTS:bpf_capsule_passes>)
target_link_libraries(bpf_capsule_pass_contract_plugin PRIVATE LLVM)
set_target_properties(bpf_capsule_pass_contract_plugin PROPERTIES PREFIX "")

function(capsule_ir_pass_contract name pipeline fixture)
    set(before "${CMAKE_CURRENT_SOURCE_DIR}/ir/${fixture}.before.ll")
    set(after "${CMAKE_CURRENT_SOURCE_DIR}/ir/${fixture}.after.ll")
    if(NOT EXISTS "${before}" OR NOT EXISTS "${after}")
        message(FATAL_ERROR "pass contract ${name} is missing ${fixture}.before.ll or ${fixture}.after.ll")
    endif()
    set(extra_arg "")
    if(ARGC GREATER 3)
        set(extra_arg "${ARGV3}")
    endif()
    add_test(
        NAME "PassContract.IR.${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DBPF_CAPSULE_LD=$<TARGET_FILE:bpf-capsule-ld>"
            "-DLLVM_AS=${BPF_CAPSULE_LLVM_AS}"
            "-DLLVM_DIS=${BPF_CAPSULE_LLVM_DIS}"
            "-DPIPELINE=${pipeline}"
            "-DEXTRA_ARG=${extra_arg}"
            "-DBEFORE=${before}"
            "-DAFTER=${after}"
            "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/${name}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/RunIrPassCase.cmake"
    )
    set_tests_properties("PassContract.IR.${name}" PROPERTIES LABELS "pass-contract;unprivileged")
endfunction()

function(capsule_ir_pass_diagnostic name pipeline fixture)
    set(before "${CMAKE_CURRENT_SOURCE_DIR}/ir/${fixture}.before.ll")
    set(errors "${CMAKE_CURRENT_SOURCE_DIR}/ir/${fixture}.errors.txt")
    if(NOT EXISTS "${before}" OR NOT EXISTS "${errors}")
        message(FATAL_ERROR "pass diagnostic ${name} is missing ${fixture}.before.ll or ${fixture}.errors.txt")
    endif()
    set(extra_arg "")
    if(ARGC GREATER 3)
        set(extra_arg "${ARGV3}")
    endif()
    add_test(
        NAME "PassContract.Diagnostic.${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DBPF_CAPSULE_LD=$<TARGET_FILE:bpf-capsule-ld>"
            "-DLLVM_AS=${BPF_CAPSULE_LLVM_AS}"
            "-DLLVM_DIS=${BPF_CAPSULE_LLVM_DIS}"
            "-DPIPELINE=${pipeline}"
            "-DEXTRA_ARG=${extra_arg}"
            "-DBEFORE=${before}"
            "-DERRORS=${errors}"
            "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/diagnostic-${name}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/RunIrDiagnosticCase.cmake"
    )
    set_tests_properties("PassContract.Diagnostic.${name}" PROPERTIES LABELS "pass-contract;unprivileged")
endfunction()

function(capsule_mir_pass_contract name pass fixture)
    set(before "${CMAKE_CURRENT_SOURCE_DIR}/mir/${fixture}.before.mir")
    set(after "${CMAKE_CURRENT_SOURCE_DIR}/mir/${fixture}.after.mir")
    if(NOT EXISTS "${before}" OR NOT EXISTS "${after}")
        message(FATAL_ERROR "MIR pass contract ${name} is missing ${fixture}.before.mir or ${fixture}.after.mir")
    endif()
    set(extra_arg "")
    if(ARGC GREATER 3)
        set(extra_arg "${ARGV3}")
    endif()
    add_test(
        NAME "PassContract.MIR.${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DLLC=${BPF_CAPSULE_LLC}"
            "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass_contract_plugin>"
            "-DPASS=${pass}"
            "-DEXTRA_ARG=${extra_arg}"
            "-DBEFORE=${before}"
            "-DAFTER=${after}"
            "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/mir-${name}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/RunMirPassCase.cmake"
    )
    set_tests_properties("PassContract.MIR.${name}" PROPERTIES LABELS "pass-contract;unprivileged")
endfunction()

function(capsule_mir_pass_diagnostic name pass fixture)
    set(before "${CMAKE_CURRENT_SOURCE_DIR}/mir/${fixture}.before.mir")
    set(errors "${CMAKE_CURRENT_SOURCE_DIR}/mir/${fixture}.errors.txt")
    if(NOT EXISTS "${before}" OR NOT EXISTS "${errors}")
        message(FATAL_ERROR "MIR pass diagnostic ${name} is missing ${fixture}.before.mir or ${fixture}.errors.txt")
    endif()
    set(extra_arg "")
    if(ARGC GREATER 3)
        set(extra_arg "${ARGV3}")
    endif()
    add_test(
        NAME "PassContract.MIRDiagnostic.${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DLLC=${BPF_CAPSULE_LLC}"
            "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass_contract_plugin>"
            "-DPASS=${pass}"
            "-DEXTRA_ARG=${extra_arg}"
            "-DBEFORE=${before}"
            "-DERRORS=${errors}"
            "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/mir-diagnostic-${name}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/RunMirDiagnosticCase.cmake"
    )
    set_tests_properties("PassContract.MIRDiagnostic.${name}" PROPERTIES LABELS "pass-contract;unprivileged")
endfunction()

function(capsule_machine_pipeline_contract name fixture)
    set(before "${CMAKE_CURRENT_SOURCE_DIR}/machine-pipeline/${fixture}.before.ll")
    set(after "${CMAKE_CURRENT_SOURCE_DIR}/machine-pipeline/${fixture}.after.mir")
    if(NOT EXISTS "${before}" OR NOT EXISTS "${after}")
        message(FATAL_ERROR "machine pipeline contract ${name} is missing ${fixture}.before.ll or ${fixture}.after.mir")
    endif()
    add_test(
        NAME "PassContract.MachinePipeline.${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DLLC=${BPF_CAPSULE_LLC}"
            "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass_contract_plugin>"
            "-DLLVM_AS=${BPF_CAPSULE_LLVM_AS}"
            "-DLLVM_DIS=${BPF_CAPSULE_LLVM_DIS}"
            "-DBEFORE=${before}"
            "-DAFTER=${after}"
            "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/machine-pipeline-${name}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/RunMachinePipelineCase.cmake"
    )
    set_tests_properties("PassContract.MachinePipeline.${name}" PROPERTIES LABELS "pass-contract;unprivileged")
endfunction()

# The inventory below covers every registered pass, starting with the late
# correctness rules that exposed real kernel/JIT bugs.
capsule_ir_pass_contract(split-shift63 "function(bpf-split-shift63)" split-shift63/basic)
capsule_ir_pass_contract(no-jump-tables "function(bpf-no-jump-tables)" no-jump-tables/basic)
capsule_ir_pass_contract(inline-policy "function(bpf-inline-policy)" inline-policy/basic)
capsule_ir_pass_contract(inline-policy-o2 "function(bpf-inline-policy),default<O2>" inline-policy/o2)
capsule_ir_pass_contract(normalize-irreducible "function(bpf-normalize-irreducible)" normalize-irreducible/switch-entries)
capsule_ir_pass_contract(lower-sdiv "bpf-lower-sdiv" lower-sdiv/basic)
capsule_ir_pass_contract(lower-arena-sext "function(bpf-lower-arena-sext)" lower-arena-sext/basic)
capsule_ir_pass_contract(internalize "bpf-internalize" internalize/basic)
capsule_ir_pass_contract(finalize-atomic-load-store "function(bpf-finalize-atomic-load-store)" atomics/finalize-load-store)
capsule_ir_pass_contract(scalarize-agg "function(bpf-scalarize-agg)" scalarize-agg/nested)
capsule_ir_pass_contract(define-undef "function(bpf-define-undef)" define-undef/traps-and-poison)
capsule_ir_pass_contract(add-suspend-barriers "bpf-add-suspend-barriers" suspend-barriers/add)
capsule_ir_pass_contract(remove-suspend-barriers "bpf-remove-suspend-barriers" suspend-barriers/remove)
capsule_ir_pass_contract(validate-atomics-accepted "function(bpf-validate-atomics)" atomics/validate-accepted)
capsule_ir_pass_contract(validate-no-float-accepted "function(bpf-validate-no-float)" validate-no-float/accepted)
capsule_ir_pass_contract(expand-sret "bpf-expand-sret" expand-sret/direct)
capsule_ir_pass_contract(expand-i128 "bpf-expand-i128" expand-i128/arithmetic)
capsule_ir_pass_contract(lower-capsule-exit "bpf-lower-capsule-exit" lower-capsule-exit/wrapper-chain)
capsule_ir_pass_contract(lower-capsule-exit-traps "bpf-lower-capsule-exit" lower-capsule-exit/traps)
capsule_ir_pass_contract(capsule-domains "bpf-capsule-domains" capsule-domains/partition)
capsule_ir_pass_contract(sanitize-btf "bpf-sanitize-btf" sanitize-btf/names-and-fragments)
capsule_ir_pass_contract(sanitize-btf-invalid-attachments "bpf-sanitize-btf" sanitize-btf/invalid-attachments)
capsule_ir_pass_contract(expand-varargs "bpf-expand-varargs" varargs/pack-and-walk)
capsule_ir_pass_contract(expand-memcpy "function(bpf-expand-mem)" expand-mem/memcpy)
capsule_ir_pass_contract(expand-memset "function(bpf-expand-mem)" expand-mem/memset)
capsule_ir_pass_contract(expand-memmove "function(bpf-expand-mem)" expand-mem/memmove)
capsule_ir_pass_contract(expand-native-memcpy "function(bpf-expand-mem)" expand-mem/native-memcpy)
capsule_ir_pass_contract(expand-native-memset "function(bpf-expand-mem)" expand-mem/native-memset)
capsule_ir_pass_contract(softfloat-arithmetic "bpf-soft-float" softfloat/arithmetic)
capsule_ir_pass_contract(softfloat-conversions "bpf-soft-float" softfloat/conversions)
capsule_ir_pass_contract(softfloat-ordered-comparisons "bpf-soft-float" softfloat/ordered-comparisons)
capsule_ir_pass_contract(softfloat-unordered-comparisons "bpf-soft-float" softfloat/unordered-comparisons)
capsule_ir_pass_contract(softfloat-values "bpf-soft-float" softfloat/values)
capsule_ir_pass_contract(softfloat-capsule-boundary "bpf-soft-float,bpf-capsule-domains" softfloat/capsule-boundary)
capsule_ir_pass_contract(softfloat-intrinsics "bpf-soft-float" softfloat/intrinsics)
capsule_ir_pass_contract(softfloat-declaration-debug "bpf-soft-float" softfloat/declaration-debug)
capsule_ir_pass_contract(lower-capsule-call "bpf-lower-capsule-call" lower-capsule-call/scalar-and-void)
capsule_ir_pass_contract(lower-capsule-call-sret "bpf-lower-capsule-call" lower-capsule-call/sret-root)
capsule_ir_pass_contract(infer-address-spaces "function(bpf-infer-as)" infer-address-spaces/arena-derived)
capsule_ir_pass_contract(memory-arena "bpf-memory-arena" memory-arena/layout-and-routing)
capsule_ir_pass_contract(memory-fixed-direct-global "bpf-memory-fixed" memory-fixed/direct-global)
capsule_ir_pass_contract(memory-fixed-general-accessors "bpf-memory-fixed" memory-fixed/general-accessors "-bpf-memory-fixed-direct-regions=2")
capsule_ir_pass_contract(memory-fixed-stack-backing "bpf-memory-fixed" memory-fixed/stack-backing "-bpf-memory-fixed-direct-regions=2")
capsule_ir_pass_contract(stackify "bpf-stackify" stackify/two-region)
capsule_ir_pass_contract(stackify-managed-calls "bpf-stackify" stackify/managed-calls)
capsule_ir_pass_contract(stackify-setjmp "bpf-stackify" stackify/setjmp)
capsule_ir_pass_contract(stackify-single-use-inline "bpf-stackify" stackify/single-use-inline)
capsule_ir_pass_contract(stackify-aligned-frame "bpf-stackify" stackify/aligned-frame)
capsule_ir_pass_contract(stackify-root-result-scope "bpf-stackify" stackify/root-result-scope)
capsule_ir_pass_contract(stackify-dynamic-alloca "bpf-stackify" stackify/dynamic-alloca)
capsule_ir_pass_contract(stackify-helper-alloca-select "bpf-stackify" stackify/helper-alloca-select)
capsule_ir_pass_contract(stackify-borrowed-context "bpf-stackify" stackify/borrowed-context)
capsule_ir_pass_contract(stackify-native-loop "bpf-stackify" stackify/native-loop)
capsule_ir_pass_contract(stackify-chunked-loop "bpf-stackify" stackify/chunked-loop)
capsule_ir_pass_contract(stackify-branching-loop "bpf-stackify" stackify/branching-loop)
capsule_ir_pass_contract(stackify-virtualized-loop "bpf-stackify" stackify/virtualized-loop)
capsule_ir_pass_contract(stackify-terminating-helper "bpf-stackify" stackify/terminating-helper)
capsule_ir_pass_contract(stackify-native-runtime-btf "bpf-stackify" stackify/native-runtime-btf)
capsule_ir_pass_contract(stackify-direct "bpf-stackify-direct" stackify-direct/two-region)
capsule_ir_pass_contract(stackify-fixed "bpf-stackify-fixed" stackify-fixed/two-region)
capsule_ir_pass_contract(stackify-fixed-v3 "bpf-stackify-fixed-v3" stackify-fixed-v3/two-region)
capsule_ir_pass_contract(stackify-fixed-v3-branching-loop "bpf-stackify-fixed-v3" stackify-fixed-v3/branching-loop)
capsule_mir_pass_contract(unified-spills-scalar "bpf-unified-spills" unified-spills/scalar "-bpf-unified-spill-limit=16")
capsule_mir_pass_contract(unified-spills-rematerialized-pointer "bpf-unified-spills" unified-spills/rematerialized-pointer "-bpf-unified-spill-limit=0")
capsule_mir_pass_contract(unified-spills-pinned-pointer-and-mask "bpf-unified-spills" unified-spills/pinned-pointer-and-mask "-bpf-unified-spill-limit=24")
capsule_mir_pass_contract(unified-spills-arena-arithmetic "bpf-unified-spills" unified-spills/arena-arithmetic "")
capsule_mir_pass_contract(unified-spills-path-merge "bpf-unified-spills" unified-spills/path-merge "-bpf-unified-spill-limit=16")
capsule_mir_pass_contract(unified-spills-opaque-definition "bpf-unified-spills" unified-spills/opaque-definition "-bpf-unified-spill-limit=16")
capsule_mir_pass_contract(unified-spills-immediate-store "bpf-unified-spills" unified-spills/immediate-store "-bpf-unified-spill-limit=16")
capsule_mir_pass_diagnostic(unified-spills-transient-partition "bpf-unified-spills" unified-spills/rejected-transient-partition "-bpf-unified-spill-limit=16")
capsule_mir_pass_diagnostic(unified-spills-unsafe-frame "bpf-unified-spills" unified-spills/rejected-unsafe-frame "-bpf-unified-spill-limit=16")
capsule_mir_pass_diagnostic(unified-spills-native-budget "bpf-unified-spills" unified-spills/pinned-pointer-and-mask "-bpf-unified-spill-limit=16")
capsule_mir_pass_diagnostic(unified-spills-missing-anchor "bpf-unified-spills" unified-spills/rejected-missing-anchor "-bpf-unified-spill-limit=16")
capsule_mir_pass_diagnostic(unified-spills-stack-size "bpf-unified-spills" unified-spills/rejected-stack-size "-bpf-unified-spill-limit=16")
capsule_mir_pass_contract(machine-stack-budget-nested-native "bpf-machine-stack-budget" machine-stack-budget/nested-native "")
capsule_mir_pass_contract(machine-flatten-terminal-units "bpf-machine-flatten" machine-flatten/terminal-units "")
capsule_mir_pass_contract(machine-flatten-finalize-local-returns "bpf-machine-flatten-finalize" machine-flatten-finalize/local-returns "")
capsule_mir_pass_contract(machine-flatten-finalize-v3-cfg "bpf-machine-flatten-finalize" machine-flatten-finalize/v3-cfg "-mcpu=v3")
capsule_mir_pass_contract(machine-flatten-finalize-v3-relay "bpf-machine-flatten-finalize" machine-flatten-finalize/v3-relay "-mcpu=v3|-bpf-machine-flatten-conditional-branch-span=2")
capsule_mir_pass_contract(machine-flatten-finalize-v3-late-backedge "bpf-machine-flatten-finalize" machine-flatten-finalize/v3-late-backedge "-mcpu=v3|-bpf-machine-flatten-conditional-branch-span=3")
capsule_mir_pass_contract(machine-flatten-finalize-v3-cascade "bpf-machine-flatten-finalize" machine-flatten-finalize/v3-cascade "-mcpu=v3|-bpf-machine-flatten-v3-branch-span=4|-bpf-machine-flatten-v3-relay-step=3")
capsule_mir_pass_contract(machine-flatten-finalize-v4-relay "bpf-machine-flatten-finalize" machine-flatten-finalize/v4-relay "-mcpu=v4|-bpf-machine-flatten-conditional-branch-span=2")
capsule_machine_pipeline_contract(machine-flatten-dispatch-locality dispatch-locality)
capsule_machine_pipeline_contract(machine-flatten-jump-table-locality jump-table-locality)
capsule_machine_pipeline_contract(machine-flatten-router-shared-suffix router-shared-suffix)
capsule_machine_pipeline_contract(machine-flatten-hierarchy-rehash hierarchy-rehash)

capsule_ir_pass_diagnostic(validate-atomics-rejected "function(bpf-validate-atomics)" atomics/validate-rejected)
capsule_ir_pass_diagnostic(validate-atomics-cmpxchg "function(bpf-validate-atomics)" atomics/rejected-cmpxchg)
capsule_ir_pass_diagnostic(validate-atomics-fence "function(bpf-validate-atomics)" atomics/rejected-fence)
capsule_ir_pass_diagnostic(validate-atomics-ordering "function(bpf-validate-atomics)" atomics/rejected-ordering)
capsule_ir_pass_diagnostic(validate-atomics-alignment "function(bpf-validate-atomics)" atomics/rejected-alignment)
capsule_ir_pass_diagnostic(validate-no-float-rejected "function(bpf-validate-no-float)" validate-no-float/rejected)
capsule_ir_pass_diagnostic(lower-sdiv-rejected "bpf-lower-sdiv" lower-sdiv/rejected)
capsule_ir_pass_diagnostic(capsule-domains-shared-function "bpf-capsule-domains" capsule-domains/shared-function)
capsule_ir_pass_diagnostic(capsule-domains-shared-global "bpf-capsule-domains" capsule-domains/shared-global)
capsule_ir_pass_diagnostic(capsule-domains-nested-boundary "bpf-capsule-domains" capsule-domains/nested-boundary)
capsule_ir_pass_diagnostic(varargs-external "bpf-expand-varargs" varargs/external)
capsule_ir_pass_diagnostic(varargs-wide-slot "bpf-expand-varargs" varargs/wide-slot)
capsule_ir_pass_diagnostic(varargs-invoke "bpf-expand-varargs" varargs/rejected-invoke)
capsule_ir_pass_diagnostic(softfloat-narrow "bpf-soft-float" softfloat/rejected-narrow)
capsule_ir_pass_diagnostic(softfloat-wide "bpf-soft-float" softfloat/rejected-wide)
capsule_ir_pass_diagnostic(softfloat-vector "bpf-soft-float" softfloat/rejected-vector)
capsule_ir_pass_diagnostic(softfloat-wide-conversion "bpf-soft-float" softfloat/rejected-wide-conversion)
capsule_ir_pass_diagnostic(softfloat-missing-intrinsic "bpf-soft-float" softfloat/rejected-missing-intrinsic)
capsule_ir_pass_diagnostic(capsule-call-escaped "bpf-lower-capsule-call" lower-capsule-call/rejected-escaped)
capsule_ir_pass_diagnostic(capsule-call-target "bpf-lower-capsule-call" lower-capsule-call/rejected-target)
capsule_ir_pass_diagnostic(capsule-call-layout "bpf-lower-capsule-call" lower-capsule-call/rejected-layout)
capsule_ir_pass_diagnostic(capsule-call-void-output "bpf-lower-capsule-call" lower-capsule-call/rejected-void-output)
capsule_ir_pass_diagnostic(capsule-call-argument-count "bpf-lower-capsule-call" lower-capsule-call/rejected-argument-count)
capsule_ir_pass_diagnostic(capsule-call-argument-type "bpf-lower-capsule-call" lower-capsule-call/rejected-argument-type)
capsule_ir_pass_diagnostic(capsule-exit-malformed "bpf-lower-capsule-exit" lower-capsule-exit/rejected-malformed)
capsule_ir_pass_diagnostic(capsule-exit-escaped "bpf-lower-capsule-exit" lower-capsule-exit/rejected-escaped)
capsule_ir_pass_diagnostic(define-undef-native-trap "function(bpf-define-undef)" define-undef/rejected-native-trap)
capsule_ir_pass_diagnostic(memory-config-definition "bpf-memory-fixed" memory-fixed/rejected-config-definition)
capsule_ir_pass_diagnostic(memory-config-section "bpf-memory-fixed" memory-fixed/rejected-config-section)
capsule_ir_pass_diagnostic(memory-config-backend "bpf-memory-fixed" memory-fixed/rejected-config-backend)
capsule_ir_pass_diagnostic(memory-fixed-layout-overflow "bpf-memory-fixed" memory-fixed/rejected-layout-overflow)
capsule_ir_pass_diagnostic(memory-fixed-image-budget "bpf-memory-fixed" memory-fixed/rejected-image-budget "-bpf-memory-fixed-direct-regions=1")
capsule_ir_pass_diagnostic(memory-fixed-access-shape "bpf-memory-fixed" memory-fixed/rejected-access-shape "-bpf-memory-fixed-direct-regions=1")
capsule_ir_pass_diagnostic(memory-arena-layout-overflow "bpf-memory-arena" memory-arena/rejected-layout-overflow)
capsule_ir_pass_diagnostic(memory-arena-control-state "bpf-memory-arena" memory-arena/rejected-control-state)
capsule_ir_pass_diagnostic(memory-arena-stack-abi "bpf-memory-arena" memory-arena/rejected-stack-abi)
capsule_ir_pass_diagnostic(stackify-native-yield "bpf-stackify" stackify/rejected-native-yield)
capsule_ir_pass_diagnostic(stackify-native-setjmp "bpf-stackify" stackify/rejected-native-setjmp)
capsule_ir_pass_diagnostic(stackify-nosuspend-proof "bpf-stackify" stackify/rejected-nosuspend-proof)
capsule_ir_pass_diagnostic(stackify-root-result "bpf-stackify" stackify/rejected-root-result)
capsule_ir_pass_diagnostic(stackify-frame-layout "bpf-stackify" stackify/rejected-frame-layout)
capsule_ir_pass_diagnostic(stackify-fiber-count "bpf-stackify" stackify/rejected-fiber-count)
capsule_ir_pass_diagnostic(stackify-accessor-abi "bpf-stackify" stackify/rejected-accessor-abi)
capsule_ir_pass_diagnostic(stackify-copy-return-abi "bpf-stackify" stackify/rejected-copy-return-abi)
capsule_ir_pass_diagnostic(stackify-stackrestore "bpf-stackify" stackify/rejected-stackrestore)
capsule_ir_pass_diagnostic(stackify-variadic-survivor "bpf-stackify" stackify/rejected-variadic-survivor)
capsule_ir_pass_diagnostic(stackify-borrowed-without-btf "bpf-stackify" stackify/rejected-borrowed-without-btf)
capsule_ir_pass_diagnostic(stackify-helper-pointer-load "bpf-stackify" stackify/rejected-helper-pointer-load)
capsule_ir_pass_diagnostic(stackify-helper-allocation "bpf-stackify" stackify/rejected-helper-allocation)
capsule_ir_pass_diagnostic(stackify-verifier-pointer-call "bpf-stackify" stackify/rejected-verifier-pointer-call)
capsule_ir_pass_diagnostic(stackify-sectioned-pointer-call "bpf-stackify" stackify/rejected-sectioned-pointer-call)
capsule_ir_pass_diagnostic(stackify-verifier-pointer-loop "bpf-stackify" stackify/rejected-verifier-pointer-loop)
capsule_ir_pass_diagnostic(stackify-verifier-pointer-chunk "bpf-stackify" stackify/rejected-verifier-pointer-chunk)
capsule_ir_pass_diagnostic(stackify-scalar-context-path "bpf-stackify" stackify/rejected-scalar-context-path)
