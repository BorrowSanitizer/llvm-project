#include "bsan.h"
#include "bsan_interceptors.h"
#include "bsan_internal.h"
#include "bsan_rt.h"

using namespace bsan_rt;
using namespace __sanitizer;
using namespace __bsan;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_shadow_copy(void *dst_ptr, void *src_ptr, uptr access_size) {
  BsanShadowCopy((uptr)dst_ptr, (uptr)src_ptr, access_size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_shadow_clear(void *ptr, uptr access_size) {
  BsanShadowClear((uptr)ptr, access_size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_preinit() {
  BsanInitFromRtl();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_init() {
  BsanInitFromRtl();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_deinit() {
  BsanDeinitFromRtl();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_push_frame() {
  BsanPushFrame();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_pop_frame() {
  BsanPopFrame();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_retag(Provenance *ptr, u8 retag_kind, u8 place_kind) {
  BsanRetag(ptr, retag_kind, place_kind);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_store_prov(Provenance *prov, void *addr) {
  BsanStoreProv(prov, (uptr)addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_load_prov(Provenance *prov,
                                                               void *addr) {
  return BsanLoadProv(prov, (uptr)addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_alloc(Provenance *prov,
                                                           void *addr,
                                                           uptr size) {
  BsanAlloc(prov, (uptr)addr, size);
}
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_alloc_stack(Provenance *prov, uptr size) {
  BsanAllocStack(prov, size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_dealloc(Provenance *prov) {
  return BsanDealloc(prov);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_expose_tag(Provenance const *prov) {
  BsanExposeTag(prov);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_read(Provenance const *prov, void *ptr, uptr access_size) {
  BsanRead(prov, (uptr)ptr, access_size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_write(Provenance const *prov, void *ptr, uptr access_size) {
  BsanWrite(prov, (uptr)ptr, access_size);
}