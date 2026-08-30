source_filename = "softfloat-values.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%pair = type { float, double }
%pair.bpf_bits = type { i32, i64 }

@memory = global %pair { float 1.000000e+00, double 2.000000e+00 }, align 8

define { i32, i64 } @ssa_values(i1 %condition, i32 %input) {
entry:
  %local = alloca float, align 4
  store i32 %input, ptr %local, align 4
  %0 = load i32, ptr %local, align 4
  br i1 %condition, label %left, label %right

left:                                             ; preds = %entry
  br label %merge

right:                                            ; preds = %entry
  br label %merge

merge:                                            ; preds = %right, %left
  %1 = phi i32 [ %0, %left ], [ 1077936128, %right ]
  %2 = select i1 %condition, i32 %1, i32 1082130432
  store i32 %2, ptr @memory, align 4
  %3 = insertvalue { i32, i64 } poison, i32 %2, 0
  %4 = insertvalue { i32, i64 } %3, i64 4617315517961601024, 1
  %5 = extractvalue { i32, i64 } %4, 0
  ret { i32, i64 } %4
}

define %pair.bpf_bits @pair_identity(%pair.bpf_bits %value) {
entry:
  ret %pair.bpf_bits %value
}

define i32 @callee(i32 %value) {
entry:
  ret i32 %value
}

define i32 @caller(i32 %value) {
entry:
  %0 = call i32 @callee(i32 %value)
  ret i32 %0
}
