; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

%fiber.control = type { i64, i64, i64, i64 }
@bpf_capsule_fibers = global [1 x %fiber.control] zeroinitializer, section ".bss.bpfctrl", align 8
@two_throw_root = global ptr @two_throw_sites
@lifetime_throw_root = global ptr @throw_through_lifetime

declare void @__bpf_capsule_exit(i32)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture)

define i32 @throw_with_successors(i1 %condition) {
entry:
  call void @__bpf_capsule_exit(i32 42)
  br i1 %condition, label %left, label %right

left:
  br label %merge

right:
  br label %merge

merge:
  %value = phi i32 [ 1, %left ], [ 2, %right ]
  ret i32 %value
}

define internal void @throw_wrapper(i32 %code) noreturn {
entry:
  call void @__bpf_capsule_exit(i32 %code)
  unreachable
}

; A normal-returning function may contain more than one conditional exit
; site. Reopening the first site must not mark the whole function handled and
; leave the second unreachable for bpf-define-undef to overwrite.
define i32 @two_throw_sites(i2 %path) {
entry:
  switch i2 %path, label %normal [
    i2 1, label %left
    i2 2, label %right
  ]

left:
  call void @throw_wrapper(i32 41)
  unreachable

right:
  call void @throw_wrapper(i32 42)
  unreachable

normal:
  ret i32 7
}

; Optimized noreturn wrappers commonly retain a lifetime marker between their
; call and unreachable. That marker is transparent when the wrapper chain is
; reopened into an ordinary return across the managed/native boundary.
define i32 @throw_through_lifetime(i32 %code) {
entry:
  %slot = alloca i8, align 1
  call void @throw_wrapper(i32 %code)
  call void @llvm.lifetime.end.p0(i64 1, ptr %slot)
  unreachable
}
