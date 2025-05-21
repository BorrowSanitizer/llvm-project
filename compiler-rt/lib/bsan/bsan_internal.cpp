#include "bsan.h"
#include "bsan_interceptors.h"
#include "bsan_rt.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
using namespace __sanitizer;
using namespace __bsan;
using namespace bsan_rt;

namespace __bsan {

extern "C" void BsanPrintln(char const *ptr) { Printf("%s\n", ptr); }
extern "C" void BsanExit() { Die(); }


static StaticSpinMutex bsan_inited_mutex;
static atomic_uint8_t bsan_inited = {0};

static void SetBsanInited() {
  atomic_store(&bsan_inited, 1, memory_order_release);
}

static void SetBsanDeinited() {
  atomic_store(&bsan_inited, 0, memory_order_release);
}

bool BsanInited() {
  return atomic_load(&bsan_inited, memory_order_acquire) == 1;
}

bool BsanInitInternal() {
  if (LIKELY(BsanInited()))
    return true;
  SanitizerToolName = "BorrowSanitizer";
  __interception::DoesNotSupportStaticLinking();
  InitializeBsanInterceptors();
  BsanAllocHooks gBsanAllocHooks = BsanAllocHooks{
    .malloc = REAL(malloc),
    .free = REAL(free)
  };
  BsanHooks gBsanHooks = BsanHooks{
    .alloc = gBsanAllocHooks,
    .mmap = REAL(mmap),
    .munmap = REAL(munmap),
    .print = BsanPrintln,
    .exit = BsanExit 
};
  bsan_rt::bsan_init(gBsanHooks);
  SetBsanInited();
  return true;
}

bool BsanDeinitInternal() {
  if (!LIKELY(BsanInited()))
    return true;
  bsan_rt::bsan_deinit();
  SetBsanDeinited();
  return true;
}

void BsanInitFromRtl() {
  if (LIKELY(BsanInited()))
    return;
  SpinMutexLock lock(&bsan_inited_mutex);
  BsanInitInternal();
}

void BsanDeinitFromRtl() {
  if (!LIKELY(BsanInited()))
    return;
  SpinMutexLock lock(&bsan_inited_mutex);
  BsanDeinitInternal();
}

bool TryBsanInitFromRtl() {
  if (LIKELY(BsanInited()))
    return true;
  if (!bsan_inited_mutex.TryLock())
    return false;
  bool result = BsanInitInternal();
  bsan_inited_mutex.Unlock();
  return result;
}

bool TryBsanDeinitFromRtl() {
  if (!LIKELY(BsanInited()))
    return true;
  if (!bsan_inited_mutex.TryLock())
    return false;
  bool result = BsanDeinitInternal();
  bsan_inited_mutex.Unlock();
  return result;
}

void BsanShadowCopy(uptr dst_ptr, uptr src_ptr, uptr access_size) {
  bsan_rt::bsan_shadow_copy(dst_ptr, src_ptr, access_size);
}

void BsanShadowClear(uptr addr, uptr access_size) {
  bsan_rt::bsan_shadow_clear(addr, access_size);
}

void BsanPushFrame() { bsan_rt::bsan_push_frame(GET_CURRENT_PC()); }

void BsanPopFrame() { bsan_rt::bsan_pop_frame(GET_CURRENT_PC()); }

void BsanRetag(Provenance *prov, uptr size, u8 retag_kind, u8 protector_kind, u8 is_freeze, u8 is_unpin) {
  bsan_rt::bsan_retag(GET_CURRENT_PC(), prov, size, retag_kind, protector_kind, is_freeze, is_unpin);
}

void BsanWrite(Provenance const *prov, uptr ptr, uptr access_size) {
  bsan_rt::bsan_write(GET_CURRENT_PC(), prov, ptr, access_size);
}

void BsanRead(Provenance const *prov, uptr ptr, uptr access_size) {
  bsan_rt::bsan_read(GET_CURRENT_PC(), prov, ptr, access_size);
}

void BsanExposeTag(Provenance const *prov) { bsan_rt::bsan_expose_tag(prov); }

void BsanStoreProv(Provenance const *prov, uptr addr) {
  bsan_rt::bsan_store_prov(prov, addr);
}

void BsanLoadProv(Provenance *prov, uptr addr) {
  bsan_rt::bsan_load_prov(prov, addr);
}

void BsanAlloc(Provenance *prov, uptr addr, uptr size) {
  return bsan_rt::bsan_alloc(GET_CURRENT_PC(), prov, addr, size);
}

void BsanAllocStack(Provenance *prov, uptr size) {
  return bsan_rt::bsan_alloc_stack(GET_CURRENT_PC(), prov, size);
}

void BsanDealloc(Provenance *prov) {
  bsan_rt::bsan_dealloc(GET_CURRENT_PC(), prov);
}

} // namespace __bsan
