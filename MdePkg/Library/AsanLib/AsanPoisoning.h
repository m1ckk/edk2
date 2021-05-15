#ifndef __ASAN_POISONING_H__
#define __ASAN_POISONING_H__

#include "Asan.h"

__attribute__((always_inline)) void FastPoisonShadow(uptr aligned_beg,
                                                      uptr aligned_size,
                                                      u8 value);
__attribute__((always_inline)) void FastPoisonShadowPartialRightRedzone(
                                                      uptr aligned_addr,
                                                      uptr size,
                                                      uptr redzone_size,
                                                      u8 value);
void PoisonShadow(uptr addr, uptr size, u8 value);
void PoisonRedZones(const struct __asan_global g) ;

#endif
