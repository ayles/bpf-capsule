source_filename = "machine-locality.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @root(i32 %value) !bpf.capsule.flatten.root !0 {
entry:
  %is.zero = icmp eq i32 %value, 0
  br i1 %is.zero, label %call.unit0, label %call.unit1

call.unit0:                                       ; preds = %entry
  %from.unit0 = call i32 @unit0(i32 %value)
  ret i32 %from.unit0

call.unit1:                                       ; preds = %entry
  %from.unit1 = call i32 @unit1(i32 %value)
  ret i32 %from.unit1
}

define i32 @unit0(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 10
  ret i32 %result
}

define i32 @unit1(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 20
  ret i32 %result
}

!0 = !{i32 0}
