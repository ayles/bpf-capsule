source_filename = "machine-hierarchy-rehash.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @root(i32 %selector, i32 %key, i32 %value) !bpf.capsule.flatten.root !0 {
entry:
  switch i32 %selector, label %bad [
    i32 0, label %call.router
    i32 1, label %call.region0
    i32 2, label %call.region1
    i32 3, label %call.region2
    i32 4, label %call.region3
    i32 5, label %call.region4
    i32 6, label %call.region5
    i32 7, label %call.region6
    i32 8, label %call.region7
    i32 9, label %call.region8
    i32 10, label %call.region9
    i32 11, label %call.region10
    i32 12, label %call.region11
  ]

call.router:                                      ; preds = %entry
  %result = call i32 @router(i32 %key, i32 %value)
  ret i32 %result

call.region0:                                     ; preds = %entry
  ret i32 -10

call.region1:                                     ; preds = %entry
  ret i32 -11

call.region2:                                     ; preds = %entry
  ret i32 -12

call.region3:                                     ; preds = %entry
  ret i32 -13

call.region4:                                     ; preds = %entry
  ret i32 -14

call.region5:                                     ; preds = %entry
  ret i32 -15

call.region6:                                     ; preds = %entry
  ret i32 -16

call.region7:                                     ; preds = %entry
  ret i32 -17

call.region8:                                     ; preds = %entry
  ret i32 -18

call.region9:                                     ; preds = %entry
  ret i32 -19

call.region10:                                    ; preds = %entry
  ret i32 -20

call.region11:                                    ; preds = %entry
  ret i32 -21

bad:                                              ; preds = %entry
  ret i32 -1
}

define i32 @router(i32 %key, i32 %value) !bpf.capsule.flatten.unit !0 !bpf.capsule.flatten.router !1 {
entry:
  switch i32 %key, label %bad [
    i32 0, label %call.region0
    i32 1, label %call.region1
    i32 2, label %call.region2
    i32 3, label %call.region3
    i32 4, label %call.region4
    i32 5, label %call.region5
    i32 6, label %call.region6
    i32 7, label %call.region7
    i32 8, label %call.region8
    i32 9, label %call.region9
    i32 10, label %call.region10
    i32 11, label %call.region11
  ]

call.region0:                                     ; preds = %entry
  %result0 = call i32 @region0(i32 %value)
  ret i32 %result0

call.region1:                                     ; preds = %entry
  %result1 = call i32 @region1(i32 %value)
  ret i32 %result1

call.region2:                                     ; preds = %entry
  %result2 = call i32 @region2(i32 %value)
  ret i32 %result2

call.region3:                                     ; preds = %entry
  %result3 = call i32 @region3(i32 %value)
  ret i32 %result3

call.region4:                                     ; preds = %entry
  %result4 = call i32 @region4(i32 %value)
  ret i32 %result4

call.region5:                                     ; preds = %entry
  %result5 = call i32 @region5(i32 %value)
  ret i32 %result5

call.region6:                                     ; preds = %entry
  %result6 = call i32 @region6(i32 %value)
  ret i32 %result6

call.region7:                                     ; preds = %entry
  %result7 = call i32 @region7(i32 %value)
  ret i32 %result7

call.region8:                                     ; preds = %entry
  %result8 = call i32 @region8(i32 %value)
  ret i32 %result8

call.region9:                                     ; preds = %entry
  %result9 = call i32 @region9(i32 %value)
  ret i32 %result9

call.region10:                                    ; preds = %entry
  %result10 = call i32 @region10(i32 %value)
  ret i32 %result10

call.region11:                                    ; preds = %entry
  %result11 = call i32 @region11(i32 %value)
  ret i32 %result11

bad:                                              ; preds = %entry
  ret i32 -1
}

define i32 @region0(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 10
  ret i32 %result
}

define i32 @region1(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 11
  ret i32 %result
}

define i32 @region2(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 12
  ret i32 %result
}

define i32 @region3(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 13
  ret i32 %result
}

define i32 @region4(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 14
  ret i32 %result
}

define i32 @region5(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 15
  ret i32 %result
}

define i32 @region6(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 16
  ret i32 %result
}

define i32 @region7(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 17
  ret i32 %result
}

define i32 @region8(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 18
  ret i32 %result
}

define i32 @region9(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 19
  ret i32 %result
}

define i32 @region10(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 20
  ret i32 %result
}

define i32 @region11(i32 %value) !bpf.capsule.flatten.unit !0 {
entry:
  %result = add i32 %value, 21
  ret i32 %result
}

!0 = !{i32 0}
!1 = !{}
