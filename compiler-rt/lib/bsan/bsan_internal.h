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
bool BsanInited();
void BsanInitFromRtl();
bool TryBsanInitFromRtl();
void BsanDeinitFromRtl();
bool TryBsanDeinitFromRtl();
void BsanShadowClear(uptr addr, uptr access_size);
void BsanShadowCopy(uptr dst_ptr, uptr src_ptr, uptr access_size);
void BsanPushFrame();
void BsanPopFrame();
void BsanRetag(Provenance *prov, uptr size, u8 permission_kind, u8 protector_kind);
void BsanWrite(Provenance const *prov, uptr ptr, uptr access_size);
void BsanRead(Provenance const *prov, uptr ptr, uptr access_size);
void BsanExposeTag(Provenance const *prov);
void BsanLoadProv(Provenance *prov, uptr addr);
void BsanStoreProv(Provenance const *prov, uptr addr);
void BsanAlloc(Provenance *prov, uptr addr, uptr size);
void BsanAllocStack(Provenance *prov, uptr size);
void BsanDealloc(Provenance *prov);
} // namespace __bsan
