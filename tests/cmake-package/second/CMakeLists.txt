# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_object(
    second_bpf
    OUTPUT second.bpf.o
    SOURCES ../smoke.c
    LIBRARIES Smoke::library
    COMPILE_OPTIONS -g
    LINK_OPTIONS ${BPF_CAPSULE_LINK_OPTIONS}
)
bpf_capsule_skeleton(second_skeleton OUTPUT smoke.skel.h OBJECT "${second_bpf}" NAME smoke)
add_executable(host_second ../host.c)
target_link_libraries(host_second PRIVATE BpfCapsule::host second_skeleton)
