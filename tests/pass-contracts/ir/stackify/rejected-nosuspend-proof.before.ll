source_filename = "stackify-rejected-nosuspend-proof.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @unbounded_native(i64 %limit) #0 {
entry:
  br label %loop

loop:                                             ; preds = %loop, %entry
  %value = phi i64 [ 0, %entry ], [ %next, %loop ]
  %next = add i64 %value, 1
  %more = icmp ult i64 %next, %limit
  br i1 %more, label %loop, label %exit

exit:                                             ; preds = %loop
  ret i64 %next
}

attributes #0 = { "capsule.nosuspend" }
