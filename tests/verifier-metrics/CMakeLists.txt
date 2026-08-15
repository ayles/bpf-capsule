# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_executable(verifier_load_probe verifier_load_probe.c)
target_compile_options(verifier_load_probe PRIVATE -Wall -Wextra)
target_link_libraries(verifier_load_probe PkgConfig::LibBpf)

install(TARGETS verifier_load_probe RUNTIME DESTINATION libexec/bpf-capsule/tests/verifier-metrics)
