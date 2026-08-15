; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
target triple = "bpf"

declare i32 @__gxx_personality_v0(...)

define i32 @variadic_callee(i32 %fixed, ...) {
entry:
  ret i32 %fixed
}

define i32 @invoke_variadic() personality ptr @__gxx_personality_v0 {
entry:
  %value = invoke i32 (i32, ...) @variadic_callee(i32 7, i64 11)
          to label %done unwind label %failed

done:
  ret i32 %value

failed:
  %landing = landingpad { ptr, i32 }
          cleanup
  ret i32 -1
}
