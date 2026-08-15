# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)

foreach(variable IN ITEMS BPF_CAPSULE_BPFTOOL BPF_CAPSULE_SKELETON_INPUT
                          BPF_CAPSULE_SKELETON_OUTPUT BPF_CAPSULE_SKELETON_NAME
)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "GenerateSkeleton.cmake: ${variable} is required")
    endif()
endforeach()

get_filename_component(output_directory "${BPF_CAPSULE_SKELETON_OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${output_directory}")
set(temporary "${BPF_CAPSULE_SKELETON_OUTPUT}.tmp")
execute_process(
    COMMAND "${BPF_CAPSULE_BPFTOOL}" gen skeleton "${BPF_CAPSULE_SKELETON_INPUT}" name
            "${BPF_CAPSULE_SKELETON_NAME}"
    OUTPUT_FILE "${temporary}"
    ERROR_VARIABLE error_output
    RESULT_VARIABLE result
)
if(NOT result EQUAL 0)
    file(REMOVE "${temporary}")
    message(FATAL_ERROR "bpftool gen skeleton failed: ${error_output}")
endif()
file(COPY_FILE "${temporary}" "${BPF_CAPSULE_SKELETON_OUTPUT}" ONLY_IF_DIFFERENT)
file(REMOVE "${temporary}")
