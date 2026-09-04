declare i64 @archive_foo(i64)
declare i64 @archive_bundle(i64)
declare extern_weak i64 @archive_optional(i64)
declare extern_weak i64 @loader_optional(i64) section ".ksyms"
declare i64 @archive_unused(i64)

@archive_data = external global i64

define i64 @archive_override(i64 %x) {
entry:
  %result = add i64 %x, 1000
  ret i64 %result
}

define i1 @archive_optional_present() {
entry:
  %present = icmp ne ptr @archive_optional, null
  ret i1 %present
}

define i1 @loader_optional_present() {
entry:
  %present = icmp ne ptr @loader_optional, null
  ret i1 %present
}

define i64 @archive_entry(i64 %x) {
entry:
  %foo = call i64 @archive_foo(i64 %x)
  %bundle = call i64 @archive_bundle(i64 %foo)
  %data = load i64, ptr @archive_data
  %result = add i64 %bundle, %data
  ret i64 %result
}
