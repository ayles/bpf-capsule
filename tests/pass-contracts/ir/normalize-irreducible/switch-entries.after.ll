source_filename = "switch-entries.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @choose_cycle(i32 %selector, i1 %again) {
entry:
  switch i32 %selector, label %exit [
    i32 0, label %entry.left_crit_edge
    i32 1, label %entry.right_crit_edge
  ]

entry.right_crit_edge:                            ; preds = %entry
  br label %right

entry.left_crit_edge:                             ; preds = %entry
  br label %left

left:                                             ; preds = %body, %entry.left_crit_edge
  br label %body

right:                                            ; preds = %body, %entry.right_crit_edge
  br label %body

body:                                             ; preds = %right, %left
  br i1 %again, label %left, label %right

exit:                                             ; preds = %entry
  ret i32 %selector
}
