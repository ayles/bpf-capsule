source_filename = "softfloat-values.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%pair = type { float, double }

@memory = global %pair { float 1.000000e+00, double 2.000000e+00 }, align 8

define { float, double } @ssa_values(i1 %condition, float %input) {
entry:
  %local = alloca float, align 4
  store float %input, ptr %local, align 4
  %loaded = load float, ptr %local, align 4
  br i1 %condition, label %left, label %right

left:                                             ; preds = %entry
  br label %merge

right:                                            ; preds = %entry
  br label %merge

merge:                                            ; preds = %right, %left
  %merged = phi float [ %loaded, %left ], [ 3.000000e+00, %right ]
  %selected = select i1 %condition, float %merged, float 4.000000e+00
  store float %selected, ptr @memory, align 4
  %first = insertvalue { float, double } poison, float %selected, 0
  %pair.value = insertvalue { float, double } %first, double 5.000000e+00, 1
  %extracted = extractvalue { float, double } %pair.value, 0
  ret { float, double } %pair.value
}

define %pair @pair_identity(%pair %value) {
entry:
  ret %pair %value
}

define float @callee(float %value) {
entry:
  ret float %value
}

define float @caller(float %value) {
entry:
  %result = call float @callee(float %value)
  ret float %result
}
