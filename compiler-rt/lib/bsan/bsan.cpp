#include "bsan.h"
#include "bsan_interceptors.h"
#include "bsan_internal.h"
#include "bsan_rt.h"

using namespace bsan_rt;
using namespace __sanitizer;
using namespace __bsan;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_shadow_copy(uptr dst_ptr, uptr src_ptr, uptr access_size) {
  BsanShadowCopy(dst_ptr, src_ptr, access_size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_shadow_clear(uptr ptr, uptr access_size) {
  BsanShadowClear(ptr, access_size);
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
__bsan_store_prov(Provenance *prov, uptr addr) {
  BsanStoreProv(prov, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_load_prov(Provenance *prov,
                                                               uptr addr) {
  return BsanLoadProv(prov, addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __bsan_alloc(Provenance *prov,
                                                           uptr size) {
  BsanAlloc(prov, size);
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
__bsan_read(Provenance const *prov, uptr ptr, uptr access_size) {
  BsanRead(prov, ptr, access_size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__bsan_write(Provenance const *prov, uptr ptr, uptr access_size) {
  BsanWrite(prov, ptr, access_size);
}