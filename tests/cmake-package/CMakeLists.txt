# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# A complete consumer of an installed BPF Capsule package: C and C++ guest
# sources through cc and ld, a libbpf skeleton, and a host executable that
# embeds it. The README points here as the complete example, and the test suite
# configures and builds it against the installed SDK for every target profile.
# Nothing here loads BPF, so it needs no privilege.
cmake_minimum_required(VERSION 3.24)
project(BpfCapsulePackageSmoke C CXX)

find_package(BpfCapsule CONFIG REQUIRED)

bpf_capsule_object(
    smoke_bpf
    OUTPUT smoke.bpf.o
    SOURCES smoke.c smoke_cpp.cpp
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(smoke_skeleton OUTPUT smoke.skel.h OBJECT "${smoke_bpf}" NAME smoke)

add_executable(host_smoke host.c)
target_link_libraries(host_smoke PRIVATE BpfCapsule::host smoke_skeleton)
