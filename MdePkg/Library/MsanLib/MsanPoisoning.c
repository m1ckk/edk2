#include "MsanPoisoning.h"
#include "MsanInternal.h"
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

void SetShadow(const void *ptr, uptr size, u8 value) {
  uptr shadow_beg = MEM_TO_SHADOW((uptr)ptr);
  uptr shadow_end = shadow_beg + size;
  DEBUG ((DEBUG_INFO, "ptr = %p\n", ptr));
  DEBUG ((DEBUG_INFO, "size = %d\n", size));
  DEBUG ((DEBUG_INFO, "shadow_beg = %p\n", shadow_beg));
  DEBUG ((DEBUG_INFO, "shadow_end = %p\n", shadow_end));

  ASSERT (shadow_beg >= SHADOW_BEGIN);
  ASSERT (shadow_end < SHADOW_END);
  ASSERT ((uptr)ptr < SHADOW_BEGIN);
  ASSERT ((uptr)ptr >= SHADOW_BEGIN - 0x800000UL);
  memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void __msan_unpoison_param(uptr n) {
  memset(__msan_param_tls, 0, n * sizeof(*__msan_param_tls));
}


void __msan_unpoison(const void *a, uptr size) {
  SetShadow(a, size, 0);
}

void __msan_poison(const void *a, uptr size) {
  SetShadow(a, size, -1);
}

// Poison section SectionName which starts at BaseAddress until BaseAddress + Size.
void PoisonSection(CHAR8 *DriverName, CHAR8 *SectionName, uptr BaseAddress, uptr Size) {
  DEBUG ((DEBUG_INFO, "PoisonSection()@%p\n", PoisonSection));
  DEBUG ((DEBUG_INFO, "  DriverName = %a\n", DriverName));
  DEBUG ((DEBUG_INFO, "  SectionName = %a\n", SectionName));
  DEBUG ((DEBUG_INFO, "  BaseAddress = %p\n", BaseAddress));
  DEBUG ((DEBUG_INFO, "  Size = 0x%x\n", Size));
  DEBUG ((DEBUG_INFO, "  AsciiStrSize(DriverName) = %d\n", AsciiStrSize(DriverName)));
  DEBUG ((DEBUG_INFO, "__msan_param_tls@%p\n", __msan_param_tls));
  DEBUG ((DEBUG_INFO, "__msan_retval_tls@%p\n", __msan_retval_tls));
  DEBUG ((DEBUG_INFO, "__msan_va_arg_tls@%p\n", __msan_va_arg_tls));
  DEBUG ((DEBUG_INFO, "&(__msan_param_tls[0])@%p\n", &(__msan_param_tls[0])));
  DEBUG ((DEBUG_INFO, "&(__msan_retval_tls[0])@%p)\n", &(__msan_retval_tls[0])));
  DEBUG ((DEBUG_INFO, "&(__msan_va_arg_tls[0])@%p\n", &(__msan_va_arg_tls[0])));

  // .text is initialized
  if (AsciiStrCmp((CHAR8 *)SectionName, ".text") == 0) {
    DEBUG ((DEBUG_INFO, "  Applying poisoning to section %a...\n", SectionName));
    __msan_unpoison((void *)BaseAddress, Size);
  }
  // .rdata is also initialized
  else if (AsciiStrCmp((CHAR8 *)SectionName, ".rdata") == 0) {
    DEBUG ((DEBUG_INFO, "  Applying poisoning to section %a...\n", SectionName));
    __msan_unpoison((void *)BaseAddress, Size);
  }
  // .data is also initialized
  else if (AsciiStrCmp((CHAR8 *)SectionName, ".data") == 0) {
    DEBUG ((DEBUG_INFO, "  Applying poisoning to section %a...\n", SectionName));
    __msan_unpoison((void *)BaseAddress, Size);
  }
  // .reloc do nothing
  else if (AsciiStrCmp((CHAR8 *)SectionName, ".reloc") == 0) {
    DEBUG ((DEBUG_INFO, "  Doing nothing for section %a...\n", SectionName));
  }
  else {
    DEBUG ((DEBUG_INFO, "  Not poisoning section %a.\n", SectionName));
    ASSERT(0);
  }
  //__msan_unpoison((void *)(SHADOW_OFFSET - SHADOW_SIZE), SHADOW_SIZE - 1);
}



void TransferShadow(uptr dst, uptr src, uptr size) {
  
}
