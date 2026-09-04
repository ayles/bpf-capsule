declare i64 @archive_bar(i64)
@archive_data = external global i64

define i64 @archive_foo(i64 %x) {
entry:
  %bar = call i64 @archive_bar(i64 %x)
  %data = load i64, ptr @archive_data
  %result = add i64 %bar, %data
  ret i64 %result
}
