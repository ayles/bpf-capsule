# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
include_guard(GLOBAL)
include(FetchContent)
include(GNUInstallDirs)

FetchContent_Declare(
    llama2
    GIT_REPOSITORY https://github.com/karpathy/llama2.c.git
    GIT_TAG 350e04fe35433e6d2941dce5a1f53308f87058eb
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(llama2)

# Upstream exposes no library header: embedders include run.c or runq.c to
# access its model types. Keep that source interface, shared by host and guest.
add_library(capsule_llama2 INTERFACE)
target_include_directories(capsule_llama2 INTERFACE "${llama2_SOURCE_DIR}")
install(FILES "${llama2_SOURCE_DIR}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/bpf-capsule/llama2")
