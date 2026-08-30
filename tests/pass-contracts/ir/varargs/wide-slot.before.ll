source_filename = "varargs-wide-slot.ll"
target triple = "bpfel"

define i32 @callee(i32 %fixed, ...) {
entry:
  ret i32 %fixed
}

define i32 @caller(i128 %wide) {
entry:
  %result = call i32 (i32, ...) @callee(i32 1, i128 %wide)
  ret i32 %result
}
