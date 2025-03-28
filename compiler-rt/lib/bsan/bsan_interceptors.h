#ifndef BSAN_INTERCEPTORS_H
#define BSAN_INTERCEPTORS_H

#include "bsan.h"
#include "bsan_rt.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_platform_interceptors.h"

namespace __bsan {
struct BsanInterceptorContext {
  const char *interceptor_name;
};
void InitializeBsanInterceptors();
} // namespace __bsan
#if !SANITIZER_APPLE
#define BSAN_INTERCEPT_FUNC(name)                                              \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION(name))                                             \
      VReport(1, "BorrowSanitizer: failed to intercept '%s'\n", #name);        \
  } while (0)
#define BSAN_INTERCEPT_FUNC_VER(name, ver)                                     \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION_VER(name, ver))                                    \
      VReport(1, "BorrowSanitizer: failed to intercept '%s@@%s'\n", #name,     \
              ver);                                                            \
  } while (0)
#define BSAN_INTERCEPT_FUNC_VER_UNVERSIONED_FALLBACK(name, ver)                \
  do {                                                                         \
    if (!INTERCEPT_FUNCTION_VER(name, ver) && !INTERCEPT_FUNCTION(name))       \
      VReport(1, "BorrowSanitizer: failed to intercept '%s@@%s' or '%s'\n",    \
              #name, ver, #name);                                              \
  } while (0)
#else
// OS X interceptors don't need to be initialized with INTERCEPT_FUNCTION.
#define BSAN_INTERCEPT_FUNC(name)
#endif // SANITIZER_APPLE

#define BSAN_MEMCPY_IMPL(ctx, to, from, size)                                  \
  do {                                                                         \
    if (LIKELY(BsanInited())) {                                                \
      uptr __to = (uptr)(to);                                                  \
      uptr __from = (uptr)(from);                                              \
      BsanShadowCopy(__to, __from, size);                                      \
    }                                                                          \
    return REAL(memcpy)(to, from, size);                                       \
  } while (0)
#define BSAN_MEMSET_IMPL(ctx, block, c, size)                                  \
  do {                                                                         \
    if (LIKELY(BsanInited())) {                                                \
      BSAN_WRITE_RANGE(ctx, block, size);                                      \
    }                                                                          \
    return REAL(memset)(block, c, size);                                       \
  } while (0)
#define BSAN_MEMMOVE_IMPL(ctx, to, from, size)                                 \
  do {                                                                         \
    if (LIKELY(BsanInited())) {                                                \
      uptr __to = (uptr)(to);                                                  \
      uptr __from = (uptr)(from);                                              \
      BsanShadowCopy(__to, __from, size);                                      \
    }                                                                          \
    return internal_memmove(to, from, size);                                   \
  } while (0)
#define BSAN_WRITE_RANGE(ctx, offset, size)                                    \
  do {                                                                         \
    uptr __offset = (uptr)(offset);                                            \
    uptr __size = (uptr)(size);                                                \
    BsanShadowClear(__offset, __size);                                         \
  } while (0)
#define BSAN_READ_RANGE(ctx, offset, size)                                     \
  do {                                                                         \
    uptr __offset = (uptr)(offset);                                            \
    uptr __size = (uptr)(size);                                                \
    BsanRead(0, __offset, __size);                                             \
  } while (0)

DECLARE_REAL(void *, memcpy, void *to, const void *from, uptr size)
DECLARE_REAL(void *, memset, void *block, int c, uptr size)

DECLARE_REAL_AND_INTERCEPTOR(void *, malloc, uptr)
DECLARE_REAL_AND_INTERCEPTOR(void, free, void *)
DECLARE_REAL_AND_INTERCEPTOR(void *, mmap, void *, SIZE_T, int, int, int, OFF_T)
DECLARE_REAL_AND_INTERCEPTOR(int, munmap, void *, SIZE_T)

#define BSAN_INTERCEPTOR_ENTER(ctx, func)                                      \
  BsanInterceptorContext _ctx = {#func};                                       \
  ctx = (void *)&_ctx;                                                         \
  (void)ctx;
#define COMMON_INTERCEPT_FUNCTION(name) BSAN_INTERCEPT_FUNC(name)

#endif