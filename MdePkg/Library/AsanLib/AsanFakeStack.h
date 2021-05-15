#ifndef __ASAN_FAKESTACK_H__
#define __ASAN_FAKESTACK_H__

static const UINTN FAKE_STACK_START = 0x7F900000ULL;
static const UINTN FAKE_STACK_SIZE = 8192;
static const UINTN NR_FAKE_STACKS = 8;

// Fake stack frame contains local variables of one function.
typedef struct FakeFrame {
  UINTN magic;              // Modified by the instrumented code.
  UINTN descr;              // Modified by the instrumented code.
  UINTN pc;                 // Modified by the instrumented code.
  UINTN flags;              // Flags that determine whether the frame is active or not.
} FakeFrame;

// FakeStack contains FakeFrames and is used to detect return-after-free errors.
typedef struct FakeStack {
  FakeFrame *FakeFrames[NR_FAKE_STACKS];
  int IndexFakeFrame[NR_FAKE_STACKS];
  int NrFakeFrames[NR_FAKE_STACKS];
} FakeStack;

void initFakeStack(void);

#endif
