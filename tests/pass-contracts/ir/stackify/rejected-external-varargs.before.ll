source_filename = "stackify-rejected-external-varargs.ll"
target triple = "bpfel"

declare i32 @external(i32, ...)

define i32 @caller() {
entry:
  %result = call i32 (i32, ...) @external(i32 1, i32 2)
  ret i32 %result
}
