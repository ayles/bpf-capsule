source_filename = "arena-spills.ll"
target triple = "bpfel"

declare i64 @callee(i64, i64, i64, i64, i64)

define i64 @physical(ptr %input, ptr %stack.base) !bpf.capsule.allocation.unit !0 !bpf.capsule.stack.size !1 {
entry:
  call void asm sideeffect "# bpf_capsule_stack_anchor", "r"(ptr %stack.base)
  %p0 = getelementptr i64, ptr %input, i64 0
  %v0 = load volatile i64, ptr %p0, align 8
  %p1 = getelementptr i64, ptr %input, i64 1
  %v1 = load volatile i64, ptr %p1, align 8
  %p2 = getelementptr i64, ptr %input, i64 2
  %v2 = load volatile i64, ptr %p2, align 8
  %p3 = getelementptr i64, ptr %input, i64 3
  %v3 = load volatile i64, ptr %p3, align 8
  %p4 = getelementptr i64, ptr %input, i64 4
  %v4 = load volatile i64, ptr %p4, align 8
  %p5 = getelementptr i64, ptr %input, i64 5
  %v5 = load volatile i64, ptr %p5, align 8
  %p6 = getelementptr i64, ptr %input, i64 6
  %v6 = load volatile i64, ptr %p6, align 8
  %p7 = getelementptr i64, ptr %input, i64 7
  %v7 = load volatile i64, ptr %p7, align 8
  %p8 = getelementptr i64, ptr %input, i64 8
  %v8 = load volatile i64, ptr %p8, align 8
  %arena = addrspacecast ptr %input to ptr addrspace(1)
  %called = call i64 @callee(i64 0, i64 0, i64 0, i64 0, i64 0)
  %held = load volatile i64, ptr addrspace(1) %arena, align 8
  %r0 = add i64 %called, %held
  %r1 = add i64 %r0, %v0
  %r2 = add i64 %r1, %v1
  %r3 = add i64 %r2, %v2
  %r4 = add i64 %r3, %v3
  %r5 = add i64 %r4, %v4
  %r6 = add i64 %r5, %v5
  %r7 = add i64 %r6, %v6
  %r8 = add i64 %r7, %v7
  %r9 = add i64 %r8, %v8
  ret i64 %r9
}

!0 = !{i32 0}
!1 = !{i64 1024}
