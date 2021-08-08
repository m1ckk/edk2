#ifndef __MSAN_H__
#define __MSAN_H__

#include <stdint.h>
#include <stddef.h>

typedef UINTN uptr;
typedef UINT8 u8;
typedef UINT16 u16;
typedef UINT32 u32;
typedef UINT64 u64;
typedef UINTN uhwptr;
#define bool int


#define ALWAYS_INLINE __attribute__((always_inline))

#define SMM_BEGIN     0x7F000000UL
#define SMM_END       0x7F800000UL
#define SHADOW_BEGIN  0x7F800000UL
#define SHADOW_END    0x80000000UL
#define AND_MASK      0xffffffffff000000UL
#define MEM_TO_SHADOW(mem) ((mem & ~(AND_MASK)) + (SHADOW_BEGIN))

#define GET_CURRENT_FRAME() (uptr) __builtin_frame_address(0)

#define GET_CALLER_PC() (uptr) __builtin_return_address(0)

extern bool fast_unwind_on_fatal;
extern bool print_stats;

#define GET_CALLER_PC_BP \
  uptr bp = GET_CURRENT_FRAME();              \
  uptr pc = GET_CALLER_PC();

#define GET_CALLER_PC_BP_SP \
  GET_CALLER_PC_BP;                           \
  uptr local_stack;                           \
  uptr sp = (uptr)&local_stack

#define GET_FATAL_STACK_TRACE_PC_BP(pc, bp)              \
  BufferedStackTrace stack;                              \
  BufferedStackTraceInit(&stack);                        \
  if (msan_inited)                                       \
    BufferedStackTraceUnwind2(&stack, pc, bp, NULL, fast_unwind_on_fatal)

// Take off-by-one into account.
#define AddrRangeInSmm(p, s) (AddrIsInMem((uptr)p) && AddrIsInMem((uptr)p + s - 1))

static inline bool AddrIsInMem(uptr a) {
  return (a >= SMM_BEGIN) && (a < SMM_END);
}

extern const int kMsanParamTlsSize;
extern const int kMsanRetvalTlsSize;
extern u64 __msan_va_arg_overflow_size_tls;

extern u64 __msan_param_tls[];
extern u64 __msan_retval_tls[];
extern u64 __msan_va_arg_tls[];


extern int msan_report_count;
// Not much needed to initialize MSan, so for now we just assume it inited.
extern int msan_inited;

void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

#endif
