#include "Asan.h"
#include "AsanPoisoning.h"

void __asan_set_shadow_00(uptr addr, uptr size) {
  _memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size) {
  _memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size) {
  _memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size) {
  _memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size) {
  _memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size) {
  _memset((void *)addr, 0xf8, size);
}

// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
__attribute__((always_inline)) void FastPoisonShadow(uptr aligned_beg, uptr aligned_size,
                                    u8 value) {
    uptr shadow_beg = MemToShadow(aligned_beg);
    uptr shadow_end = MemToShadow(
    aligned_beg + aligned_size - SHADOW_GRANULARITY) + 1;
/*
    DEBUG((DEBUG_INFO, "  shadow_beg = %p\n", (void *)shadow_beg));
    DEBUG((DEBUG_INFO, "  shadow_end = %p\n", (void *)shadow_end));
*/
    _memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

// Is called when the global.size is unequal to alignment_size
__attribute__((always_inline)) void FastPoisonShadowPartialRightRedzone(
    uptr aligned_addr, uptr size, uptr redzone_size, u8 value) {
    unsigned poison_partial = 1; // flags()->poison_partial;
    u8 *shadow = (u8*)MemToShadow(aligned_addr);
    for (uptr i = 0; i < redzone_size; i += SHADOW_GRANULARITY, shadow++) {
        if (i + SHADOW_GRANULARITY <= size) {
            *shadow = 0;  // fully addressable
        } else if (i >= size) {
            *shadow = (SHADOW_GRANULARITY == 128) ? 0xff : value;  // unaddressable
        } else {
            // first size-i bytes are addressable
            *shadow = poison_partial ? (u8)(size - i) : 0;
        }
    }
}

void PoisonShadow(uptr addr, uptr size, u8 value) {
  if (value && !CanPoisonMemory()) return;
  ASSERT(AddrIsAlignedByGranularity(addr));
  ASSERT(AddrIsInMem(addr));
  ASSERT(AddrIsAlignedByGranularity(addr + size));
  ASSERT(AddrIsInMem(addr + size - SHADOW_GRANULARITY));
  FastPoisonShadow(addr, size, value);
}

void PoisonRedZones(const struct __asan_global g) {
    uptr aligned_size = RoundUpTo(g.size, SHADOW_GRANULARITY);
    FastPoisonShadow(g.beg + aligned_size, g.size_with_redzone - aligned_size,
                     kAsanGlobalRedzoneMagic);
    if (g.size != aligned_size) {
        FastPoisonShadowPartialRightRedzone(
            g.beg + RoundDownTo(g.size, SHADOW_GRANULARITY),
            g.size % SHADOW_GRANULARITY,
            SHADOW_GRANULARITY,
            kAsanGlobalRedzoneMagic);
    }
}

