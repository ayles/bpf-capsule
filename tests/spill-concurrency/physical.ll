; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; A post-register-allocation regression fixture. It is intentionally LLVM IR:
; the bpf.capsule.physical metadata is compiler-internal, and fixed volatile
; allocas make the late spill relocation independent of source optimization.

target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

%fiber.control = type { i64, i64 }
@bpf_capsule_fibers = dso_local global [3 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@bpf_call_stack = dso_local global [3 x [262144 x i8]] zeroinitializer, section ".bss.stack", align 8
@spill_results = dso_local global [6 x i64] zeroinitializer, section ".bss.spillr", align 8
@spill_noise = dso_local global i64 1, section ".data.spillr", align 8
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1

define dso_local i64 @spill_pressure(i32 %fiber, i64 %seed, i64 %sp) #0 !bpf.capsule !1 !bpf.capsule.physical !0 !bpf.capsule.stack.size !2 {
entry:
  %bounded.seed = and i64 %seed, 2097151
  %slot0 = alloca i64, align 8
  %slot1 = alloca i64, align 8
  %slot2 = alloca i64, align 8
  %slot3 = alloca i64, align 8
  %slot4 = alloca i64, align 8
  %slot5 = alloca i64, align 8
  %slot6 = alloca i64, align 8
  %slot7 = alloca i64, align 8
  %slot8 = alloca i64, align 8
  %slot9 = alloca i64, align 8
  %slot10 = alloca i64, align 8
  %slot11 = alloca i64, align 8
  %slot12 = alloca i64, align 8
  %slot13 = alloca i64, align 8
  %slot14 = alloca i64, align 8
  %slot15 = alloca i64, align 8
  %slot16 = alloca i64, align 8
  %slot17 = alloca i64, align 8
  %slot18 = alloca i64, align 8
  %slot19 = alloca i64, align 8
  %slot20 = alloca i64, align 8
  %slot21 = alloca i64, align 8
  %slot22 = alloca i64, align 8
  %slot23 = alloca i64, align 8
  %slot24 = alloca i64, align 8
  %slot25 = alloca i64, align 8
  %slot26 = alloca i64, align 8
  %slot27 = alloca i64, align 8
  %slot28 = alloca i64, align 8
  %slot29 = alloca i64, align 8
  %slot30 = alloca i64, align 8
  %slot31 = alloca i64, align 8
  %slot32 = alloca i64, align 8
  %slot33 = alloca i64, align 8
  %slot34 = alloca i64, align 8
  %slot35 = alloca i64, align 8
  %slot36 = alloca i64, align 8
  %slot37 = alloca i64, align 8
  %slot38 = alloca i64, align 8
  %slot39 = alloca i64, align 8
  %slot40 = alloca i64, align 8
  %slot41 = alloca i64, align 8
  %slot42 = alloca i64, align 8
  %slot43 = alloca i64, align 8
  %slot44 = alloca i64, align 8
  %slot45 = alloca i64, align 8
  %slot46 = alloca i64, align 8
  %slot47 = alloca i64, align 8
  %fiber.valid = icmp ult i32 %fiber, 3
  %fiber.index = select i1 %fiber.valid, i32 %fiber, i32 0
  %stack = getelementptr inbounds [3 x [262144 x i8]], ptr @bpf_call_stack, i64 0, i32 %fiber.index, i64 0
  %control = getelementptr inbounds [3 x %fiber.control], ptr @bpf_capsule_fibers, i64 0, i32 %fiber.index
  %abort = getelementptr inbounds %fiber.control, ptr %control, i32 0, i32 0
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r,r,r"(ptr %stack, i64 %sp, ptr %abort)
  %value0 = add i64 %bounded.seed, 0
  store volatile i64 %value0, ptr %slot0, align 8
  %value1 = add i64 %bounded.seed, 1
  store volatile i64 %value1, ptr %slot1, align 8
  %value2 = add i64 %bounded.seed, 2
  store volatile i64 %value2, ptr %slot2, align 8
  %value3 = add i64 %bounded.seed, 3
  store volatile i64 %value3, ptr %slot3, align 8
  %value4 = add i64 %bounded.seed, 4
  store volatile i64 %value4, ptr %slot4, align 8
  %value5 = add i64 %bounded.seed, 5
  store volatile i64 %value5, ptr %slot5, align 8
  %value6 = add i64 %bounded.seed, 6
  store volatile i64 %value6, ptr %slot6, align 8
  %value7 = add i64 %bounded.seed, 7
  store volatile i64 %value7, ptr %slot7, align 8
  %value8 = add i64 %bounded.seed, 8
  store volatile i64 %value8, ptr %slot8, align 8
  %value9 = add i64 %bounded.seed, 9
  store volatile i64 %value9, ptr %slot9, align 8
  %value10 = add i64 %bounded.seed, 10
  store volatile i64 %value10, ptr %slot10, align 8
  %value11 = add i64 %bounded.seed, 11
  store volatile i64 %value11, ptr %slot11, align 8
  %value12 = add i64 %bounded.seed, 12
  store volatile i64 %value12, ptr %slot12, align 8
  %value13 = add i64 %bounded.seed, 13
  store volatile i64 %value13, ptr %slot13, align 8
  %value14 = add i64 %bounded.seed, 14
  store volatile i64 %value14, ptr %slot14, align 8
  %value15 = add i64 %bounded.seed, 15
  store volatile i64 %value15, ptr %slot15, align 8
  %value16 = add i64 %bounded.seed, 16
  store volatile i64 %value16, ptr %slot16, align 8
  %value17 = add i64 %bounded.seed, 17
  store volatile i64 %value17, ptr %slot17, align 8
  %value18 = add i64 %bounded.seed, 18
  store volatile i64 %value18, ptr %slot18, align 8
  %value19 = add i64 %bounded.seed, 19
  store volatile i64 %value19, ptr %slot19, align 8
  %value20 = add i64 %bounded.seed, 20
  store volatile i64 %value20, ptr %slot20, align 8
  %value21 = add i64 %bounded.seed, 21
  store volatile i64 %value21, ptr %slot21, align 8
  %value22 = add i64 %bounded.seed, 22
  store volatile i64 %value22, ptr %slot22, align 8
  %value23 = add i64 %bounded.seed, 23
  store volatile i64 %value23, ptr %slot23, align 8
  %value24 = add i64 %bounded.seed, 24
  store volatile i64 %value24, ptr %slot24, align 8
  %value25 = add i64 %bounded.seed, 25
  store volatile i64 %value25, ptr %slot25, align 8
  %value26 = add i64 %bounded.seed, 26
  store volatile i64 %value26, ptr %slot26, align 8
  %value27 = add i64 %bounded.seed, 27
  store volatile i64 %value27, ptr %slot27, align 8
  %value28 = add i64 %bounded.seed, 28
  store volatile i64 %value28, ptr %slot28, align 8
  %value29 = add i64 %bounded.seed, 29
  store volatile i64 %value29, ptr %slot29, align 8
  %value30 = add i64 %bounded.seed, 30
  store volatile i64 %value30, ptr %slot30, align 8
  %value31 = add i64 %bounded.seed, 31
  store volatile i64 %value31, ptr %slot31, align 8
  %value32 = add i64 %bounded.seed, 32
  store volatile i64 %value32, ptr %slot32, align 8
  %value33 = add i64 %bounded.seed, 33
  store volatile i64 %value33, ptr %slot33, align 8
  %value34 = add i64 %bounded.seed, 34
  store volatile i64 %value34, ptr %slot34, align 8
  %value35 = add i64 %bounded.seed, 35
  store volatile i64 %value35, ptr %slot35, align 8
  %value36 = add i64 %bounded.seed, 36
  store volatile i64 %value36, ptr %slot36, align 8
  %value37 = add i64 %bounded.seed, 37
  store volatile i64 %value37, ptr %slot37, align 8
  %value38 = add i64 %bounded.seed, 38
  store volatile i64 %value38, ptr %slot38, align 8
  %value39 = add i64 %bounded.seed, 39
  store volatile i64 %value39, ptr %slot39, align 8
  %value40 = add i64 %bounded.seed, 40
  store volatile i64 %value40, ptr %slot40, align 8
  %value41 = add i64 %bounded.seed, 41
  store volatile i64 %value41, ptr %slot41, align 8
  %value42 = add i64 %bounded.seed, 42
  store volatile i64 %value42, ptr %slot42, align 8
  %value43 = add i64 %bounded.seed, 43
  store volatile i64 %value43, ptr %slot43, align 8
  %value44 = add i64 %bounded.seed, 44
  store volatile i64 %value44, ptr %slot44, align 8
  %value45 = add i64 %bounded.seed, 45
  store volatile i64 %value45, ptr %slot45, align 8
  %value46 = add i64 %bounded.seed, 46
  store volatile i64 %value46, ptr %slot46, align 8
  %value47 = add i64 %bounded.seed, 47
  store volatile i64 %value47, ptr %slot47, align 8
  br label %delay

delay:
  %delay.i = phi i32 [ 0, %entry ], [ %delay.next, %delay ]
  %noise = load volatile i64, ptr @spill_noise, align 8
  %delay.next = add nuw nsw i32 %delay.i, 1
  %delay.done = icmp eq i32 %delay.next, 1024
  br i1 %delay.done, label %collect, label %delay

collect:
  %load0 = load volatile i64, ptr %slot0, align 8
  %load1 = load volatile i64, ptr %slot1, align 8
  %load2 = load volatile i64, ptr %slot2, align 8
  %load3 = load volatile i64, ptr %slot3, align 8
  %load4 = load volatile i64, ptr %slot4, align 8
  %load5 = load volatile i64, ptr %slot5, align 8
  %load6 = load volatile i64, ptr %slot6, align 8
  %load7 = load volatile i64, ptr %slot7, align 8
  %load8 = load volatile i64, ptr %slot8, align 8
  %load9 = load volatile i64, ptr %slot9, align 8
  %load10 = load volatile i64, ptr %slot10, align 8
  %load11 = load volatile i64, ptr %slot11, align 8
  %load12 = load volatile i64, ptr %slot12, align 8
  %load13 = load volatile i64, ptr %slot13, align 8
  %load14 = load volatile i64, ptr %slot14, align 8
  %load15 = load volatile i64, ptr %slot15, align 8
  %load16 = load volatile i64, ptr %slot16, align 8
  %load17 = load volatile i64, ptr %slot17, align 8
  %load18 = load volatile i64, ptr %slot18, align 8
  %load19 = load volatile i64, ptr %slot19, align 8
  %load20 = load volatile i64, ptr %slot20, align 8
  %load21 = load volatile i64, ptr %slot21, align 8
  %load22 = load volatile i64, ptr %slot22, align 8
  %load23 = load volatile i64, ptr %slot23, align 8
  %load24 = load volatile i64, ptr %slot24, align 8
  %load25 = load volatile i64, ptr %slot25, align 8
  %load26 = load volatile i64, ptr %slot26, align 8
  %load27 = load volatile i64, ptr %slot27, align 8
  %load28 = load volatile i64, ptr %slot28, align 8
  %load29 = load volatile i64, ptr %slot29, align 8
  %load30 = load volatile i64, ptr %slot30, align 8
  %load31 = load volatile i64, ptr %slot31, align 8
  %load32 = load volatile i64, ptr %slot32, align 8
  %load33 = load volatile i64, ptr %slot33, align 8
  %load34 = load volatile i64, ptr %slot34, align 8
  %load35 = load volatile i64, ptr %slot35, align 8
  %load36 = load volatile i64, ptr %slot36, align 8
  %load37 = load volatile i64, ptr %slot37, align 8
  %load38 = load volatile i64, ptr %slot38, align 8
  %load39 = load volatile i64, ptr %slot39, align 8
  %load40 = load volatile i64, ptr %slot40, align 8
  %load41 = load volatile i64, ptr %slot41, align 8
  %load42 = load volatile i64, ptr %slot42, align 8
  %load43 = load volatile i64, ptr %slot43, align 8
  %load44 = load volatile i64, ptr %slot44, align 8
  %load45 = load volatile i64, ptr %slot45, align 8
  %load46 = load volatile i64, ptr %slot46, align 8
  %load47 = load volatile i64, ptr %slot47, align 8
  %sum0 = xor i64 0, %load0
  %sum1 = xor i64 %sum0, %load1
  %sum2 = xor i64 %sum1, %load2
  %sum3 = xor i64 %sum2, %load3
  %sum4 = xor i64 %sum3, %load4
  %sum5 = xor i64 %sum4, %load5
  %sum6 = xor i64 %sum5, %load6
  %sum7 = xor i64 %sum6, %load7
  %sum8 = xor i64 %sum7, %load8
  %sum9 = xor i64 %sum8, %load9
  %sum10 = xor i64 %sum9, %load10
  %sum11 = xor i64 %sum10, %load11
  %sum12 = xor i64 %sum11, %load12
  %sum13 = xor i64 %sum12, %load13
  %sum14 = xor i64 %sum13, %load14
  %sum15 = xor i64 %sum14, %load15
  %sum16 = xor i64 %sum15, %load16
  %sum17 = xor i64 %sum16, %load17
  %sum18 = xor i64 %sum17, %load18
  %sum19 = xor i64 %sum18, %load19
  %sum20 = xor i64 %sum19, %load20
  %sum21 = xor i64 %sum20, %load21
  %sum22 = xor i64 %sum21, %load22
  %sum23 = xor i64 %sum22, %load23
  %sum24 = xor i64 %sum23, %load24
  %sum25 = xor i64 %sum24, %load25
  %sum26 = xor i64 %sum25, %load26
  %sum27 = xor i64 %sum26, %load27
  %sum28 = xor i64 %sum27, %load28
  %sum29 = xor i64 %sum28, %load29
  %sum30 = xor i64 %sum29, %load30
  %sum31 = xor i64 %sum30, %load31
  %sum32 = xor i64 %sum31, %load32
  %sum33 = xor i64 %sum32, %load33
  %sum34 = xor i64 %sum33, %load34
  %sum35 = xor i64 %sum34, %load35
  %sum36 = xor i64 %sum35, %load36
  %sum37 = xor i64 %sum36, %load37
  %sum38 = xor i64 %sum37, %load38
  %sum39 = xor i64 %sum38, %load39
  %sum40 = xor i64 %sum39, %load40
  %sum41 = xor i64 %sum40, %load41
  %sum42 = xor i64 %sum41, %load42
  %sum43 = xor i64 %sum42, %load43
  %sum44 = xor i64 %sum43, %load44
  %sum45 = xor i64 %sum44, %load45
  %sum46 = xor i64 %sum45, %load46
  %sum47 = xor i64 %sum46, %load47
  ; Forty-seven consecutive values have a seed-dependent XOR. The final
  ; volatile load still keeps all 48 slots live across the delay, but leaving
  ; it out avoids the seed-independent XOR of an aligned 48-value range.
  ret i64 %sum46
}

define dso_local i32 @spill_fiber_zero() section "syscall" {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %next, %record ]
  %actual = call i64 @spill_pressure(i32 0, i64 4096, i64 262144)
  %bad = icmp ne i64 %actual, 4143
  %errors = load volatile i64, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 0), align 8
  %bad64 = zext i1 %bad to i64
  %errors.next = add i64 %errors, %bad64
  store volatile i64 %errors.next, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 0), align 8
  br label %record

record:
  %next = add nuw nsw i32 %i, 1
  %done = icmp eq i32 %next, 64
  br i1 %done, label %exit, label %loop

exit:
  %calls = load volatile i64, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 2), align 8
  %calls.next = add i64 %calls, 1
  store volatile i64 %calls.next, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 2), align 8
  ret i32 0
}

define dso_local i32 @spill_fiber_two() section "syscall" {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %next, %record ]
  %actual = call i64 @spill_pressure(i32 2, i64 1048576, i64 262144)
  %bad = icmp ne i64 %actual, 1048623
  %errors = load volatile i64, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 1), align 8
  %bad64 = zext i1 %bad to i64
  %errors.next = add i64 %errors, %bad64
  store volatile i64 %errors.next, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 1), align 8
  br label %record

record:
  %next = add nuw nsw i32 %i, 1
  %done = icmp eq i32 %next, 64
  br i1 %done, label %exit, label %loop

exit:
  %calls = load volatile i64, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 3), align 8
  %calls.next = add i64 %calls, 1
  store volatile i64 %calls.next, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 3), align 8
  ret i32 0
}

define dso_local i32 @spill_overflow() section "syscall" {
entry:
  %abort.ptr = getelementptr inbounds [3 x %fiber.control], ptr @bpf_capsule_fibers, i64 0, i64 1, i32 0
  store volatile i64 0, ptr %abort.ptr, align 8
  %actual = call i64 @spill_pressure(i32 1, i64 8192, i64 40)
  %abort = load volatile i64, ptr %abort.ptr, align 8
  store volatile i64 %abort, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 4), align 8
  store volatile i64 %actual, ptr getelementptr inbounds ([6 x i64], ptr @spill_results, i64 0, i64 5), align 8
  ret i32 0
}

attributes #0 = { noinline nounwind }

!0 = !{i32 0}
!1 = !{}
!2 = !{i64 262144}
