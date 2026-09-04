declare void @llvm.memcpy.p0.p0.i64(ptr noalias writeonly, ptr noalias readonly, i64, i1 immarg)
declare void @llvm.memmove.p0.p0.i64(ptr writeonly, ptr readonly, i64, i1 immarg)
declare void @llvm.memset.p0.i64(ptr writeonly, i8, i64, i1 immarg)

define ptr @archive_mem_entry(ptr %dst, ptr %src, i64 %length) {
entry:
  call void @llvm.memcpy.p0.p0.i64(ptr %dst, ptr %src, i64 %length, i1 false)
  call void @llvm.memmove.p0.p0.i64(ptr %dst, ptr %src, i64 %length, i1 false)
  call void @llvm.memset.p0.i64(ptr %dst, i8 0, i64 %length, i1 false)
  ret ptr %dst
}
