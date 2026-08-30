source_filename = "no-jump-tables.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @dispatch(i32 %pc) {
entry:
  switch i32 %pc, label %invalid [
    i32 1, label %one
    i32 2, label %two
  ]

one:                                              ; preds = %entry
  ret i32 11

two:                                              ; preds = %entry
  ret i32 22

invalid:                                          ; preds = %entry
  ret i32 -1
}
