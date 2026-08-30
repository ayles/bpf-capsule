source_filename = "infer-address-spaces.ll"
target datalayout = "e-m:e-p:64:64-p1:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@arena = addrspace(1) global [4 x i32] zeroinitializer

define i32 @load_arena(i64 %index) {
entry:
  %generic = addrspacecast ptr addrspace(1) @arena to ptr
  %slot = getelementptr [4 x i32], ptr %generic, i64 0, i64 %index
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}
