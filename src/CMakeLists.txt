# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_subdirectory(pass)

install(FILES runtime/guest/bpf_capsule.h runtime/host/bpf_capsule_host.h
              runtime/abi/bpf_capsule_abi.h DESTINATION include/bpf-capsule
)
install(FILES runtime/guest/bpf_capsule.c DESTINATION share/bpf-capsule/runtime)
