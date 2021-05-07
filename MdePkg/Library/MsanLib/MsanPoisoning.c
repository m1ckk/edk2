#include "MsanPoisoning.h"
#include "MsanInternal.h"
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

void SetShadow(const void *ptr, uptr size, u8 value) {
  uptr shadow_beg = MEM_TO_SHADOW((uptr)ptr);

  if (!((uptr)ptr >= SMM_BEGIN && (((uptr)ptr + size) < SMM_END))) {
    DEBUG ((DEBUG_INFO, "SetShadow() out of range.\n"));
    DEBUG ((DEBUG_INFO, "ptr =          %p\n", ptr));
    DEBUG ((DEBUG_INFO, "size =         %d\n", size));
    return;
  }
  memset((void *)shadow_beg, value, size);
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
void __msan_poison_section(CHAR8 *DriverName, CHAR8 *SectionName, uptr BaseAddress, uptr Size) {
  DEBUG ((DEBUG_INFO, "__msan_poison_section()@%p\n", __msan_poison_section));
  DEBUG ((DEBUG_INFO, "  DriverName = %a\n", DriverName));
  DEBUG ((DEBUG_INFO, "  SectionName = %a\n", SectionName));
  DEBUG ((DEBUG_INFO, "  BaseAddress = %p\n", BaseAddress));
  DEBUG ((DEBUG_INFO, "  Size = 0x%x\n", Size));
  DEBUG ((DEBUG_INFO, "  AsciiStrSize(DriverName) = %d\n", AsciiStrSize(DriverName)));

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
}



void __msan_transfer_shadow(void *dst, void *src, uptr size) {
  uptr shadow_beg_src = MEM_TO_SHADOW((uptr)src);
  uptr shadow_beg_dst = MEM_TO_SHADOW((uptr)dst);

  if (!(((uptr)src >= SMM_BEGIN) && (((uptr)src + size) < SMM_END))) {
    // src is out of SMRAM.
    if (!(((uptr)dst >= SMM_BEGIN) && (((uptr)dst + size) < SMM_END))) {
      // dst is out of SMRAM.
      DEBUG ((DEBUG_INFO, "__msan_transfer_shadow(): src out dst out\n"));
      return;
    } else {
      // dst is in SMRAM.
      // Use clean shadow, since we assume everything outside of SMRAM to be
      // initialized, and the source is outside of SMRAM.
      DEBUG ((DEBUG_INFO, "__msan_transfer_shadow(): src out dst in\n"));
      __msan_unpoison(dst, size);
    }
  } else {
    // src is in SMRAM.
    if (!(((uptr)dst >= SMM_BEGIN) && (((uptr)dst + size) < SMM_END))) {
      // dst is outside of SMRAM.
      // Do nothing, as we are copying memory to outside of SMRAM.
      DEBUG ((DEBUG_INFO, "__msan_transfer_shadow(): src in dst out\n"));
      return;
    } else {
      // dst is in SMRAM.
      // This is the case in which both src and dst are in SMRAM.
      // Transfer the shadow values to the destination.
      DEBUG ((DEBUG_INFO, "__msan_transfer_shadow(): src in dst in\n"));
      memcpy((void *)shadow_beg_dst, (void *)shadow_beg_src, size);
    }
  }
}
