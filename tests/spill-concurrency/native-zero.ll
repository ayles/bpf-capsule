; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; A zero Capsule-step budget must not try to relocate an ordinary native BPF
; function: it has no leased fiber and therefore no private scratch lane.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@native_zero_result = dso_local global i64 0, section ".bss.zero", align 8
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1

define dso_local i32 @native_zero_control() section "syscall" {
entry:
  %slot0 = alloca i64, align 8
  %slot1 = alloca i64, align 8
  %slot2 = alloca i64, align 8
  %slot3 = alloca i64, align 8
  store volatile i64 1, ptr %slot0, align 8
  store volatile i64 2, ptr %slot1, align 8
  store volatile i64 4, ptr %slot2, align 8
  store volatile i64 8, ptr %slot3, align 8
  %v0 = load volatile i64, ptr %slot0, align 8
  %v1 = load volatile i64, ptr %slot1, align 8
  %v2 = load volatile i64, ptr %slot2, align 8
  %v3 = load volatile i64, ptr %slot3, align 8
  %s0 = add i64 %v0, %v1
  %s1 = add i64 %v2, %v3
  %sum = add i64 %s0, %s1
  store volatile i64 %sum, ptr @native_zero_result, align 8
  ret i32 0
}

attributes #0 = { noinline nounwind }
