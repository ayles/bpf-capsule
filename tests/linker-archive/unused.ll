declare i64 @archive_missing(i64)

define i64 @archive_unused(i64 %x) {
entry:
  %result = call i64 @archive_missing(i64 %x)
  ret i64 %result
}
