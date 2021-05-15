#ifndef __ASAN_H__
#define __ASAN_H__

#include <stddef.h>
#include <stdbool.h>
#include <Library/DebugLib.h>

typedef UINT32 u32;
typedef UINT64 u64;
typedef UINT8 u8;
typedef UINTN uptr;

// As defined for SMM, this is according to AddressSanitizer.cpp
static const u64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
#define MEM_START 0x7F000000UL
#define MEM_END 0x7FDFFFFFUL
// Starting at 0x7Fe00000 allows us to map the memory range 0x7F000000
// to 0x7Fdfffff to shadow memory 0x7Fe00000 to 0x80000000
#define SHADOW_OFFSET 0x7Fe00000UL
#define AND_MASK 0xffffffffff000000UL
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define MEM_TO_SHADOW(mem) (((mem & ~(AND_MASK)) >> SHADOW_SCALE) + (SHADOW_OFFSET))

// This structure is used to describe the source location of a place where
// global was defined.
struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};

// This structure describes an instrumented global variable.
typedef struct __asan_global {
  uptr beg;                // The address of the global.
  uptr size;               // The original size of the global.
  uptr size_with_redzone;  // The size with the redzone.
  const char *name;        // Name as a C string.
  const char *module_name; // Module name as a C string. This pointer is a
                           // unique identifier of a module.
  uptr has_dynamic_init;   // Non-zero if the global has dynamic initializer.
  struct __asan_global_source_location *location;  // Source location of a global,
                                            // or NULL if it is unknown.
  uptr odr_indicator;      // The address of the ODR indicator symbol.
} __asan_global;

// These magic values are written to shadow for better error reporting.
static const int kAsanHeapLeftRedzoneMagic = 0xfa;
static const int kAsanHeapFreeMagic = 0xfd;
static const int kAsanStackLeftRedzoneMagic = 0xf1;
static const int kAsanStackMidRedzoneMagic = 0xf2;
static const int kAsanStackRightRedzoneMagic = 0xf3;
static const int kAsanStackAfterReturnMagic = 0xf5;
static const int kAsanInitializationOrderMagic = 0xf6;
static const int kAsanUserPoisonedMemoryMagic = 0xf7;
static const int kAsanContiguousContainerOOBMagic = 0xfc;
static const int kAsanStackUseAfterScopeMagic = 0xf8;
static const int kAsanGlobalRedzoneMagic = 0xf9;
static const int kAsanInternalHeapMagic = 0xfe;
static const int kAsanArrayCookieMagic = 0xac;
static const int kAsanIntraObjectRedzone = 0xbb;
static const int kAsanAllocaLeftMagic = 0xca;
static const int kAsanAllocaRightMagic = 0xcb;

extern bool __asan_option_detect_stack_use_after_return;
extern void *__asan_shadow_memory_dynamic_address;
extern bool __asan_inited;
extern bool __asan_in_runtime;
extern bool __asan_can_poison_memory;

static inline void _memset(void *p, int value, size_t sz) {
  for (size_t i = 0; i < sz; ++i)
    ((char*)p)[i] = (char)value;
}

static inline void _memcpy(void *dst, void *src, size_t sz) {
  char *dst_c = (char*)dst,
       *src_c = (char*)src;
  for (size_t i = 0; i < sz; ++i)
    dst_c[i] = src_c[i];
}

static inline uptr RoundUpTo(uptr size, uptr boundary) {
  return (size + boundary - 1) & ~(boundary - 1);
}

static inline uptr RoundDownTo(uptr x, uptr boundary) {
  return x & ~(boundary - 1);
}

static inline bool AddrIsInMem(uptr a) {
  return (a >= MEM_START) && (a < MEM_END);
}

static inline uptr MemToShadow(uptr p) {
  if (!AddrIsInMem(p)) {
    DEBUG ((DEBUG_INFO, "MemToShadow(): not in SMRAM: %p\n", p));
  }
  return MEM_TO_SHADOW(p);
}

static inline uptr LeastSignificantSetBitIndex(uptr x) {
  ASSERT(x != 0U);
  unsigned long up;
  up = __builtin_ctzll(x);
  return up;
}

static inline bool IsPowerOfTwo(uptr x) {
  return (x & (x - 1)) == 0;
}

static inline uptr Log2(uptr x) {
  ASSERT(IsPowerOfTwo(x));
  return LeastSignificantSetBitIndex(x);
}

static inline bool AddrIsAlignedByGranularity(uptr a) {
  return (a & (SHADOW_GRANULARITY - 1)) == 0;
}


bool CanPoisonMemory(void);
void PoisonShadow(uptr addr, uptr size, u8 value);

#endif
