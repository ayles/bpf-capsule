# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
file(MAKE_DIRECTORY "${WORK}")
file(WRITE "${WORK}/unwind.ll" "target triple = \"bpfel\"\ndefine i64 @identity(i64 %x) uwtable { ret i64 %x }\n")
execute_process(
    COMMAND "${BPF_CAPSULE_LD}" --passes=no-op-module --emit-asm "${WORK}/unwind.ll" -o "${WORK}/unwind.s"
    COMMAND_ERROR_IS_FATAL ANY
)
file(READ "${WORK}/unwind.s" assembly)
if(assembly MATCHES "\\.cfi_startproc|\\.eh_frame")
    message(FATAL_ERROR "BPF assembly still requests an unwind table")
endif()
execute_process(
    COMMAND "${BPF_CAPSULE_LD}" --passes=no-op-module "${WORK}/unwind.ll" -o "${WORK}/unwind.o"
    COMMAND_ERROR_IS_FATAL ANY
)
execute_process(
    COMMAND "${LLVM_READELF}" --sections "${WORK}/unwind.o"
    OUTPUT_VARIABLE sections
    COMMAND_ERROR_IS_FATAL ANY
)
if(sections MATCHES "\\.eh_frame")
    message(FATAL_ERROR "BPF object contains an unwind table")
endif()
