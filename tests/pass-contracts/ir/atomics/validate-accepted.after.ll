source_filename = "validate-atomics.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@native32 = global i32 0, section ".data.native32", align 4
@native64 = global i64 0, section ".data.native64", align 8

define i64 @managed(ptr %memory, ptr %pointer, i32 %value32, i64 %value64) !bpf.capsule !0 {
entry:
  %loaded8 = load atomic i8, ptr %memory unordered, align 1
  store atomic i8 %loaded8, ptr %memory monotonic, align 1
  %loaded16 = load atomic i16, ptr %memory monotonic, align 2
  store atomic i16 %loaded16, ptr %memory unordered, align 2
  %loaded32 = load atomic i32, ptr %memory unordered, align 4
  store atomic i32 %loaded32, ptr %memory monotonic, align 4
  %loaded64 = load atomic i64, ptr %memory monotonic, align 8
  store atomic i64 %loaded64, ptr %memory unordered, align 8
  %loaded.pointer = load atomic ptr, ptr %memory unordered, align 8
  store atomic ptr %loaded.pointer, ptr %memory monotonic, align 8
  %add32 = atomicrmw add ptr @native32, i32 %value32 monotonic, align 4
  %and32 = atomicrmw and ptr @native32, i32 %value32 monotonic, align 4
  %or32 = atomicrmw or ptr @native32, i32 %value32 monotonic, align 4
  %xor32 = atomicrmw xor ptr @native32, i32 %value32 monotonic, align 4
  %xchg32 = atomicrmw xchg ptr @native32, i32 %value32 monotonic, align 4
  %cmp32 = cmpxchg ptr @native32, i32 %add32, i32 %value32 monotonic monotonic, align 4
  %add64 = atomicrmw add ptr @native64, i64 %value64 monotonic, align 8
  %and64 = atomicrmw and ptr @native64, i64 %value64 monotonic, align 8
  %or64 = atomicrmw or ptr @native64, i64 %value64 monotonic, align 8
  %xor64 = atomicrmw xor ptr @native64, i64 %value64 monotonic, align 8
  %xchg64 = atomicrmw xchg ptr @native64, i64 %value64 monotonic, align 8
  %cmp64 = cmpxchg ptr @native64, i64 %add64, i64 %value64 monotonic monotonic, align 8
  fence syncscope("singlethread") acq_rel
  ret i64 %loaded64
}

!0 = !{}
