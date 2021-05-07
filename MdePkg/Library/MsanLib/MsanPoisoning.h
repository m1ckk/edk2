#ifndef __MSAN_POISONING_H__
#define __MSAN_POISONING_H__


#include "Msan.h"

void SetShadow(const void *ptr, uptr size, u8 value);
void __msan_unpoison_param(uptr n);
void __msan_unpoison(const void *a, uptr size);
void __msan_poison(const void *a, uptr size);
void __msan_poison_section(CHAR8 *DriverName, CHAR8 *SectionName, uptr BaseAddress, uptr Size);

#endif
