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
// Check whether the region [beg, beg + size) is poisoned.
uptr __asan_region_is_poisoned(uptr beg, uptr size) {
  if (!size) return 0;
  uptr end = beg + size;
  if (!AddrIsInMem(beg)) return beg;
  if (!AddrIsInMem(end)) return end;
  uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
  uptr aligned_e = RoundDownTo(end, SHADOW_GRANULARITY);
  uptr shadow_beg = MEM_TO_SHADOW(aligned_b);
  uptr shadow_end = MEM_TO_SHADOW(aligned_e);
  // First check the first and the last application bytes,
  // then check the SHADOW_GRANULARITY-aligned region by calling
  // mem_is_zero on the corresponding shadow.
  if (!AddressIsPoisoned(beg) &&
      !AddressIsPoisoned(end - 1) &&
      (shadow_end <= shadow_beg ||
       mem_is_zero((const char *)shadow_beg,
                                shadow_end - shadow_beg)))
    return 0;
  // The fast check failed, so we have a poisoned byte somewhere.
  // Find it slowly.
  for (; beg < end; beg++)
    if (AddressIsPoisoned(beg))
      return beg;
  // mem_is_zero returned false, but poisoned byte was not found
  asm volatile("hlt");
  return 0;
}

