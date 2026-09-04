define i64 @archive_bundle(i64 %x) {
entry:
  %result = call i64 @archive_override(i64 %x)
  ret i64 %result
}

define weak i64 @archive_override(i64 %x) {
entry:
  %result = add i64 %x, 1
  ret i64 %result
}
