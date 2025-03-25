#include "bsan_interceptors.h"
#include "bsan_internal.h"
#include "sanitizer_common/sanitizer_platform.h"

using namespace __bsan;
using namespace __sanitizer;

int BsanOnExit() { return 0; }

INTERCEPTOR(void *, malloc, SIZE_T size) { return REAL(malloc)(size); }
INTERCEPTOR(void, free, void *ptr) { return REAL(free)(ptr); }

#define COMMON_INTERCEPT_FUNCTION_VER(name, ver)                               \
  BSAN_INTERCEPT_FUNC_VER(name, ver)
#define COMMON_INTERCEPT_FUNCTION_VER_UNVERSIONED_FALLBACK(name, ver)          \
  BSAN_INTERCEPT_FUNC_VER_UNVERSIONED_FALLBACK(name, ver)
#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size)                         \
  BSAN_WRITE_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size)                          \
  BSAN_READ_RANGE(ctx, ptr, size)
#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                               \
  BSAN_INTERCEPTOR_ENTER(ctx, func);                                           \
  do {                                                                         \
    if constexpr (SANITIZER_APPLE) {                                           \
      if (UNLIKELY(!BsanInited()))                                             \
        return REAL(func)(__VA_ARGS__);                                        \
    } else {                                                                   \
      if (!TryBsanInitFromRtl())                                               \
        return REAL(func)(__VA_ARGS__);                                        \
    }                                                                          \
  } while (false)
#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path)                              \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd)                                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd)                    \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name)                          \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name)                 \
  do {                                                                         \
  } while (false)
#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)
// Strict init-order checking is dlopen-hostile:
// https://github.com/google/sanitizers/issues/178
#define COMMON_INTERCEPTOR_DLOPEN(filename, flag)                              \
  ({                                                                           \
    CheckNoDeepBind(filename, flag);                                           \
    REAL(dlopen)(filename, flag);                                              \
  })
#define COMMON_INTERCEPTOR_ON_EXIT(ctx) BsanOnExit()
#define COMMON_INTERCEPTOR_LIBRARY_LOADED(filename, handle)
#define COMMON_INTERCEPTOR_LIBRARY_UNLOADED()
#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED (!BsanInited())
#define COMMON_INTERCEPTOR_GET_TLS_RANGE(begin, end) *begin = *end = 0;

template <class Mmap>
static void *mmap_interceptor(Mmap real_mmap, void *addr, SIZE_T length,
                              int prot, int flags, int fd, OFF_T offset) {
  void *res = real_mmap(addr, length, prot, flags, fd, offset);
  return res;
}

template <class Munmap>
static int munmap_interceptor(Munmap real_munmap, void *addr, SIZE_T length) {
  return real_munmap(addr, length);
}

#define COMMON_INTERCEPTOR_MMAP_IMPL(ctx, mmap, addr, length, prot, flags, fd, \
                                     offset)                                   \
  do {                                                                         \
    (void)(ctx);                                                               \
    return mmap_interceptor(REAL(mmap), addr, sz, prot, flags, fd, off);       \
  } while (false)

#define COMMON_INTERCEPTOR_MUNMAP_IMPL(ctx, addr, length)                      \
  do {                                                                         \
    (void)(ctx);                                                               \
    return munmap_interceptor(REAL(munmap), addr, sz);                         \
  } while (false)

#define SIGNAL_INTERCEPTOR_ENTER()                                             \
  do {                                                                         \
    BsanInitFromRtl();                                                         \
  } while (false)

// Syscall interceptors don't have contexts, we don't support suppressions
// for them.
#define COMMON_SYSCALL_PRE_READ_RANGE(p, s) BSAN_READ_RANGE(nullptr, p, s)
#define COMMON_SYSCALL_PRE_WRITE_RANGE(p, s) BSAN_WRITE_RANGE(nullptr, p, s)
#define COMMON_SYSCALL_POST_READ_RANGE(p, s)                                   \
  do {                                                                         \
    (void)(p);                                                                 \
    (void)(s);                                                                 \
  } while (false)
#define COMMON_SYSCALL_POST_WRITE_RANGE(p, s)                                  \
  do {                                                                         \
    (void)(p);                                                                 \
    (void)(s);                                                                 \
  } while (false)

#define COMMON_INTERCEPTOR_MEMMOVE_IMPL(ctx, to, from, size)                   \
  do {                                                                         \
    BSAN_INTERCEPTOR_ENTER(ctx, memmove);                                      \
    BSAN_MEMMOVE_IMPL(ctx, to, from, size);                                    \
  } while (false)

#define COMMON_INTERCEPTOR_MEMCPY_IMPL(ctx, to, from, size)                    \
  do {                                                                         \
    BSAN_INTERCEPTOR_ENTER(ctx, memcpy);                                       \
    BSAN_MEMCPY_IMPL(ctx, to, from, size);                                     \
  } while (false)

#define COMMON_INTERCEPTOR_MEMSET_IMPL(ctx, block, c, size)                    \
  do {                                                                         \
    BSAN_INTERCEPTOR_ENTER(ctx, memset);                                       \
    BSAN_MEMSET_IMPL(ctx, block, c, size);                                     \
  } while (false)

#include "sanitizer_common/sanitizer_common_interceptors.inc"
#include "sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc"
#include "sanitizer_common/sanitizer_common_syscalls.inc"
#include "sanitizer_common/sanitizer_platform_interceptors.h"

// ---------------------- InitializeAsanInterceptors ---------------- {{{1
namespace __bsan {
void InitializeBsanInterceptors() {
  static bool was_called_once;
  CHECK(!was_called_once);
  was_called_once = true;
  InitializeCommonInterceptors();
}

} // namespace __bsan