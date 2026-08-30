source_filename = "varargs-rejected-invoke.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare i32 @__gxx_personality_v0(...)

define i32 @variadic_callee(i32 %fixed, ...) {
entry:
  ret i32 %fixed
}

define i32 @invoke_variadic() personality ptr @__gxx_personality_v0 {
entry:
  %value = invoke i32 (i32, ...) @variadic_callee(i32 7, i64 11)
          to label %done unwind label %failed

done:                                             ; preds = %entry
  ret i32 %value

failed:                                           ; preds = %entry
  %landing = landingpad { ptr, i32 }
          cleanup
  ret i32 -1
}
