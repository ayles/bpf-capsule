source_filename = "machine-router-shared-suffix.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare i32 @scalar_step(i32)

define i32 @root(i32 %router, i32 %key, i32 %value) !bpf.capsule.flatten.root !0 {
entry:
  switch i32 %router, label %scalar [
    i32 0, label %call.router0
    i32 1, label %call.router1
    i32 2, label %call.region0
    i32 3, label %call.region1
    i32 4, label %call.region2
    i32 5, label %call.region3
  ]

call.router0:                                     ; preds = %entry
  %from.router0 = call i32 @router0(i32 %key, i32 %value)
  ret i32 %from.router0

call.router1:                                     ; preds = %entry
  %from.router1 = call i32 @router1(i32 %key, i32 %value)
  ret i32 %from.router1

call.region0:                                     ; preds = %entry
  ret i32 -10

call.region1:                                     ; preds = %entry
  ret i32 -11

call.region2:                                     ; preds = %entry
  ret i32 -12

call.region3:                                     ; preds = %entry
  ret i32 -13

scalar:                                           ; preds = %entry
  ret i32 -14
}

define i32 @router0(i32 %key, i32 %value) !bpf.capsule.flatten.unit !0 !bpf.capsule.flatten.router !1 {
entry:
  switch i32 %key, label %scalar [
    i32 0, label %call.region0
    i32 1, label %call.region1
    i32 2, label %call.region0
    i32 3, label %call.region1
    i32 4, label %call.region0
    i32 5, label %call.region1
    i32 6, label %call.region0
    i32 7, label %call.region1
    i32 8, label %call.region0
    i32 9, label %call.region1
    i32 10, label %call.region0
    i32 11, label %call.region1
    i32 12, label %call.region0
    i32 13, label %call.region1
    i32 14, label %call.region0
    i32 15, label %call.region1
    i32 16, label %call.region0
    i32 17, label %call.region1
    i32 18, label %call.region0
    i32 19, label %call.region1
    i32 20, label %call.region0
    i32 21, label %call.region1
    i32 22, label %call.region0
    i32 23, label %call.region1
    i32 24, label %call.region0
    i32 25, label %call.region1
    i32 26, label %call.region0
    i32 27, label %call.region1
    i32 28, label %call.region0
    i32 29, label %call.region1
    i32 30, label %call.region0
    i32 31, label %call.region1
  ]

call.region0:                                     ; preds = %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry
  %from.region0 = call i32 @region0(i32 %value)
  ret i32 %from.region0

call.region1:                                     ; preds = %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry
  %from.region1 = call i32 @region1(i32 %value)
  ret i32 %from.region1

scalar:                                           ; preds = %entry
  %from.scalar = call i32 @scalar_step(i32 %value)
  ret i32 %from.scalar
}

define i32 @router1(i32 %key, i32 %value) !bpf.capsule.flatten.unit !0 !bpf.capsule.flatten.router !1 {
entry:
  switch i32 %key, label %scalar [
    i32 0, label %call.region2
    i32 1, label %call.region3
    i32 2, label %call.region2
    i32 3, label %call.region3
    i32 4, label %call.region2
    i32 5, label %call.region3
    i32 6, label %call.region2
    i32 7, label %call.region3
    i32 8, label %call.region2
    i32 9, label %call.region3
    i32 10, label %call.region2
    i32 11, label %call.region3
    i32 12, label %call.region2
    i32 13, label %call.region3
    i32 14, label %call.region2
    i32 15, label %call.region3
    i32 16, label %call.region2
    i32 17, label %call.region3
    i32 18, label %call.region2
    i32 19, label %call.region3
    i32 20, label %call.region2
    i32 21, label %call.region3
    i32 22, label %call.region2
    i32 23, label %call.region3
    i32 24, label %call.region2
    i32 25, label %call.region3
    i32 26, label %call.region2
    i32 27, label %call.region3
    i32 28, label %call.region2
    i32 29, label %call.region3
    i32 30, label %call.region2
    i32 31, label %call.region3
  ]

call.region2:                                     ; preds = %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry
  %from.region2 = call i32 @region2(i32 %value)
  ret i32 %from.region2

call.region3:                                     ; preds = %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry, %entry
  %from.region3 = call i32 @region3(i32 %value)
  ret i32 %from.region3

scalar:                                           ; preds = %entry
  %from.scalar = call i32 @scalar_step(i32 %value)
  ret i32 %from.scalar
}

define i32 @region0(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 10
  ret i32 %result
}

define i32 @region1(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 20
  ret i32 %result
}

define i32 @region2(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 30
  ret i32 %result
}

define i32 @region3(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 40
  ret i32 %result
}

!0 = !{i32 0}
!1 = !{}
