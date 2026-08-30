source_filename = "machine-jump-table-locality.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @root(i32 %index, i32 %value) !bpf.capsule.flatten.root !0 {
entry:
  switch i32 %index, label %bad [
    i32 0, label %call.unit0
    i32 1, label %call.unit1
    i32 2, label %call.unit2
    i32 3, label %call.unit3
    i32 4, label %call.unit4
    i32 5, label %call.unit5
    i32 6, label %call.unit6
    i32 7, label %call.unit7
    i32 8, label %call.unit0
    i32 9, label %call.unit1
    i32 10, label %call.unit2
    i32 11, label %call.unit3
    i32 12, label %call.unit4
    i32 13, label %call.unit5
    i32 14, label %call.unit6
    i32 15, label %call.unit7
    i32 16, label %call.unit0
    i32 17, label %call.unit1
    i32 18, label %call.unit2
    i32 19, label %call.unit3
    i32 20, label %call.unit4
    i32 21, label %call.unit5
    i32 22, label %call.unit6
    i32 23, label %call.unit7
    i32 24, label %call.unit0
    i32 25, label %call.unit1
    i32 26, label %call.unit2
    i32 27, label %call.unit3
    i32 28, label %call.unit4
    i32 29, label %call.unit5
    i32 30, label %call.unit6
    i32 31, label %call.unit7
    i32 32, label %call.unit0
    i32 33, label %call.unit1
    i32 34, label %call.unit2
    i32 35, label %call.unit3
  ]

call.unit0:                                       ; preds = %entry, %entry, %entry, %entry, %entry
  %from.unit0 = call i32 @unit0(i32 %value)
  ret i32 %from.unit0

call.unit1:                                       ; preds = %entry, %entry, %entry, %entry, %entry
  %from.unit1 = call i32 @unit1(i32 %value)
  ret i32 %from.unit1

call.unit2:                                       ; preds = %entry, %entry, %entry, %entry, %entry
  %from.unit2 = call i32 @unit2(i32 %value)
  ret i32 %from.unit2

call.unit3:                                       ; preds = %entry, %entry, %entry, %entry, %entry
  %from.unit3 = call i32 @unit3(i32 %value)
  ret i32 %from.unit3

call.unit4:                                       ; preds = %entry, %entry, %entry, %entry
  %from.unit4 = call i32 @unit4(i32 %value)
  ret i32 %from.unit4

call.unit5:                                       ; preds = %entry, %entry, %entry, %entry
  %from.unit5 = call i32 @unit5(i32 %value)
  ret i32 %from.unit5

call.unit6:                                       ; preds = %entry, %entry, %entry, %entry
  %from.unit6 = call i32 @unit6(i32 %value)
  ret i32 %from.unit6

call.unit7:                                       ; preds = %entry, %entry, %entry, %entry
  %from.unit7 = call i32 @unit7(i32 %value)
  ret i32 %from.unit7

bad:                                              ; preds = %entry
  ret i32 -1
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

define i32 @unit2(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 30
  ret i32 %result
}

define i32 @unit3(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 40
  ret i32 %result
}

define i32 @unit4(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 50
  ret i32 %result
}

define i32 @unit5(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 60
  ret i32 %result
}

define i32 @unit6(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 70
  ret i32 %result
}

define i32 @unit7(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 80
  ret i32 %result
}

!0 = !{i32 0}
