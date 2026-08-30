# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.21)
project(BpfCapsulePackageSmoke C CXX)

find_package(BpfCapsule CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LibBpf libbpf>=1.4.0 REQUIRED IMPORTED_TARGET)
set(BPF_CAPSULE_LIBBPF_TARGET PkgConfig::LibBpf)

bpf_capsule_bitcode(smoke_bc
    SOURCES smoke.c smoke_cpp.cpp
    COMPILE_OPTIONS -g)
bpf_capsule_object(smoke_bpf
    OUTPUT smoke.bpf.o
    BITCODE ${smoke_bc})
add_custom_target(package_smoke ALL DEPENDS smoke_bpf)

add_executable(host_smoke host.c)
target_link_libraries(host_smoke PRIVATE BpfCapsule::host)
