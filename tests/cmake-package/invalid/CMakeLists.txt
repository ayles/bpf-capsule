# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.24)
project(BpfCapsuleInvalidArgument C)

find_package(BpfCapsule CONFIG REQUIRED)
bpf_capsule_object(unused TYPO OUTPUT unused.bpf.o SOURCES ../smoke.c)
