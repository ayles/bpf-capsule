# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
bpf_capsule_library(smoke_seed SOURCES seed.c)
target_include_directories(smoke_seed PUBLIC include)

# GLOBAL makes the imported archive visible to consumers in other directories.
add_library(smoke_seed_import STATIC IMPORTED GLOBAL)
set_target_properties(
    smoke_seed_import
    PROPERTIES
        IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libsmoke_seed.a"
        INTERFACE_INCLUDE_DIRECTORIES "$<TARGET_PROPERTY:smoke_seed,INTERFACE_INCLUDE_DIRECTORIES>"
)
add_dependencies(smoke_seed_import smoke_seed)

set(extra_source)
if(NOT SMOKE_REMOVE_MEMBER)
    set(extra_source unused.c)
endif()
# Ordinary scopes: the private seed archive still reaches the final link, the
# public header directory and definition reach consumers, the private
# definition does not.
bpf_capsule_library(smoke_library SOURCES ../smoke_cpp.cpp ${extra_source})
target_include_directories(smoke_library PUBLIC include)
target_link_libraries(smoke_library PRIVATE smoke_seed_import)
target_compile_definitions(smoke_library PUBLIC SMOKE_LIBRARY_PUBLIC=1 PRIVATE SMOKE_LIBRARY_PRIVATE=1)
target_compile_options(smoke_library PRIVATE -g)
