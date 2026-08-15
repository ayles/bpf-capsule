# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)
project(BpfCapsuleInvalidArgument C)

find_package(BpfCapsule CONFIG REQUIRED)
bpf_capsule_runtime_bitcode(
    unused
    TYPO
)
