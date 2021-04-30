#ifndef __MSAN_STACKTRACE_H__
#define __MSAN_STACKTRACE_H__

#include "Msan.h"

static const u32 kStackTraceMax = 256;
#if 0
#if SANITIZER_LINUX && defined(__mips__)
# define SANITIZER_CAN_FAST_UNWIND 0
#elif SANITIZER_WINDOWS
# define SANITIZER_CAN_FAST_UNWIND 0
#elif SANITIZER_OPENBSD
# define SANITIZER_CAN_FAST_UNWIND 0
#else
# define SANITIZER_CAN_FAST_UNWIND 1
#endif

// Fast unwind is the only option on Mac for now; we will need to
// revisit this macro when slow unwind works on Mac, see
// https://github.com/google/sanitizers/issues/137
#if SANITIZER_MAC || SANITIZER_OPENBSD || SANITIZER_RTEMS
# define SANITIZER_CAN_SLOW_UNWIND 0
#else
# define SANITIZER_CAN_SLOW_UNWIND 1
#endif
#else
// For now take over the values that are normally assigned to a Windows
// build, given that this is TianoCore this is likely not correct, so: TODO.
# define SANITIZER_CAN_FAST_UNWIND 0
# define SANITIZER_CAN_SLOW_UNWIND 1
#endif

#define INLINE      __attribute__((always_inline))

// These were static attributes of "struct StackTrace"
static const int STACKTRACE_TAG_UNKNOWN = 0;
static const int STACKTRACE_TAG_ALLOC = 1;
static const int STACKTRACE_TAG_DEALLOC = 2;
static const int STACKTRACE_TAG_CUSTOM = 100; // Tool specific tags start here.

uptr stack_top();
uptr stack_bottom();

// Performance-critical, must be in the header.
static inline uptr GetPreviousInstructionPc(uptr pc) {
#if defined(__arm__)
  // T32 (Thumb) branch instructions might be 16 or 32 bit long,
  // so we return (pc-2) in that case in order to be safe.
  // For A32 mode we return (pc-4) because all instructions are 32 bit long.
  return (pc - 3) & (~1);
#elif defined(__powerpc__) || defined(__powerpc64__) || defined(__aarch64__)
  // PCs are always 4 byte aligned.
  return pc - 4;
#elif defined(__sparc__) || defined(__mips__)
  return pc - 8;
#else
  return pc - 1;
#endif
}

// Check if given pointer points into allocated stack area.
static inline bool IsValidFrame(uptr frame, uptr stack_top, uptr stack_bottom) {
  return frame > stack_bottom && frame < stack_top - 2 * sizeof (uhwptr);
}

static inline bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline uhwptr *GetCanonicFrame(uptr bp,
                                      uptr stack_top,
                                      uptr stack_bottom) {
  return (uhwptr*)bp;
}

/////////////////////////////////////////////////////////////////
//////////  Start of BufferedStackTrace implementation
/////////////////////////////////////////////////////////////////

// StackTrace that owns the buffer used to store the addresses.
typedef struct BufferedStackTrace {
  const uptr *trace;
  u32 size;
  u32 tag;
  uptr trace_buffer[kStackTraceMax];
  uptr top_frame_bp;  // Optional bp of a top frame.

#if 0
  BufferedStackTrace() : StackTrace(trace_buffer, 0), top_frame_bp(0) {}

  void Init(const uptr *pcs, uptr cnt, uptr extra_top_pc = 0);

  // Get the stack trace with the given pc and bp.
  // The pc will be in the position 0 of the resulting stack trace.
  // The bp may refer to the current frame or to the caller's frame.
  void Unwind(uptr pc, uptr bp, void *context, bool request_fast,
              u32 max_depth = kStackTraceMax) {
    top_frame_bp = (max_depth > 0) ? bp : 0;
    // Small max_depth optimization
    if (max_depth <= 1) {
      if (max_depth == 1)
        trace_buffer[0] = pc;
      size = max_depth;
      return;
    }
    UnwindImpl(pc, bp, context, request_fast, max_depth);
  }

  void Unwind(u32 max_depth, uptr pc, uptr bp, void *context, uptr stack_top,
              uptr stack_bottom, bool request_fast_unwind);

  void Reset() {
    *static_cast<StackTrace *>(this) = StackTrace(trace_buffer, 0);
    top_frame_bp = 0;
  }

 private:
  // Every runtime defines its own implementation of this method
  void UnwindImpl(uptr pc, uptr bp, void *context, bool request_fast,
                  u32 max_depth);

  // UnwindFast/Slow have platform-specific implementations
  void UnwindFast(uptr pc, uptr bp, uptr stack_top, uptr stack_bottom,
                  u32 max_depth);
  void UnwindSlow(uptr pc, u32 max_depth);
  void UnwindSlow(uptr pc, void *context, u32 max_depth);

  void PopStackFrames(uptr count);
  uptr LocatePcInTrace(uptr pc);

  BufferedStackTrace(const BufferedStackTrace &) = delete;
  void operator=(const BufferedStackTrace &) = delete;
#endif

} BufferedStackTrace;

void BufferedStackTracePrint(BufferedStackTrace *bst);

void BufferedStackTraceUnwindFast(BufferedStackTrace *bst, uptr pc, uptr bp,
                uptr stack_top, uptr stack_bottom, u32 max_depth);

// We always do the fast unwind, since this only gets called when we error
void BufferedStackTraceUnwind(BufferedStackTrace *bst, u32 max_depth, uptr pc,
                uptr bp, void *context, uptr stack_top, uptr stack_bottom,
                bool request_fast_unwind);

void BufferedStackTraceUnwindImpl(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth);

// Get the stack trace with the given pc and bp.
// The pc will be in the position 0 of the resulting stack trace.
// The bp may refer to the current frame or to the caller's frame.
void BufferedStackTraceUnwind1(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth);

// Get the stack trace with the given pc and bp.
// The pc will be in the position 0 of the resulting stack trace.
// The bp may refer to the current frame or to the caller's frame.
void BufferedStackTraceUnwind2(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast);

void BufferedStackTraceInit(BufferedStackTrace *bst);

/////////////////////////////////////////////////////////////////
//////////  End of BufferedStackTrace implementation
/////////////////////////////////////////////////////////////////

#if 0
// Use this macro if you want to print stack trace with the caller
// of the current function in the top frame.
#define GET_CALLER_PC_BP \
  uptr bp = GET_CURRENT_FRAME();              \
  uptr pc = GET_CALLER_PC();

#define GET_CALLER_PC_BP_SP \
  GET_CALLER_PC_BP;                           \
  uptr local_stack;                           \
  uptr sp = (uptr)&local_stack

// Use this macro if you want to print stack trace with the current
// function in the top frame.
#define GET_CURRENT_PC_BP \
  uptr bp = GET_CURRENT_FRAME();              \
  uptr pc = StackTraceGetCurrentPc()

#define GET_CURRENT_PC_BP_SP \
  GET_CURRENT_PC_BP;                          \
  uptr local_stack;                           \
  uptr sp = (uptr)&local_stack

#endif
#endif  // SANITIZER_STACKTRACE_H
