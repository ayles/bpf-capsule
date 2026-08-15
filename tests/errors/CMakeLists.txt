# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_executable(error_strings_host error_strings_host.c)
target_include_directories(error_strings_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})

add_executable(host_header_cpp host_header_cpp.cpp)
target_include_directories(host_header_cpp PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})

add_executable(drive_contract_host drive_contract_host.c)
target_include_directories(drive_contract_host PRIVATE ${BPF_CAPSULE_INCLUDE_DIRS})
target_link_libraries(drive_contract_host PkgConfig::LibBpf)

install(TARGETS error_strings_host host_header_cpp drive_contract_host
        RUNTIME DESTINATION libexec/bpf-capsule/tests/errors
)

add_custom_target(
    compiler_error_contract ALL
    COMMAND
        "${CMAKE_COMMAND}" "-DOPT=${BPF_CAPSULE_OPT}" "-DPLUGIN=$<TARGET_FILE:bpf_capsule_pass>"
        "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}" -P
        "${CMAKE_CURRENT_SOURCE_DIR}/verify-compiler-errors.cmake"
    DEPENDS bpf_capsule_pass
    COMMENT "Compiler unsupported-input diagnostic contract"
    VERBATIM
)
