#include <stddef.h>
#include <stdbool.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "Asan.h"
#include "AsanPoisoning.h"
#include "AsanFakeStack.h"

bool __asan_option_detect_stack_use_after_return = 0;
bool __asan_inited = 0;
bool __asan_in_runtime = 0;
bool __asan_can_poison_memory = 0;
void *__asan_shadow_memory_dynamic_address;

#define ASAN_DECLARATION(type, is_write, size)                              \
void __asan_report_exp_ ## type ## size(uptr addr) {                        \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_report_exp_ ## type##_## size(uptr addr) {                      \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_exp_ ## type ## size(uptr addr) {                               \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_report_ ## type ## size(uptr addr) {                            \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_report_ ## type##_## size(uptr addr) {                          \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_ ## type ## size(uptr addr) {                                   \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
  asm volatile("hlt");                                                      \
}                                                                           \
void __asan_report_ ## type##_## size ##_noabort(uptr addr) {               \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
}                                                                           \
void __asan_report ## type ## size ##_noabort(uptr addr) {                  \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
}                                                                           \
void __asan_report_ ## type ## size##_noabort(uptr addr) {                  \
  if (!__asan_inited || __asan_in_runtime) {return;}                        \
  __asan_in_runtime = 1;                                                    \
  DEBUG ((DEBUG_INFO, "[ASAN] %a\n", __func__));                            \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
  __asan_in_runtime = 0;                                                    \
}                                                                           \

ASAN_DECLARATION(load, false, 1);
ASAN_DECLARATION(load, false, 2);
ASAN_DECLARATION(load, false, 4);
ASAN_DECLARATION(load, false, 8);
ASAN_DECLARATION(load, false, 16);
ASAN_DECLARATION(load, false, n);
ASAN_DECLARATION(load, false, N);
ASAN_DECLARATION(store, true, 1);
ASAN_DECLARATION(store, true, 2);
ASAN_DECLARATION(store, true, 4);
ASAN_DECLARATION(store, true, 8);
ASAN_DECLARATION(store, true, 16);
ASAN_DECLARATION(store, true, n);
ASAN_DECLARATION(store, true, N);

bool CanPoisonMemory(void) {
  return __asan_can_poison_memory;
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
        uptr access_size, u32 exp, bool fatal) {
    u8 *shadow_addr = (u8 *)MemToShadow(addr);
    u8 shadow_val = *shadow_addr;
    //int bug_idx = 0;

    DEBUG ((DEBUG_INFO, "[ASAN] ERROR: pc=%p, sp=%p, addr=%p, shadow value=%x, is_write=%x\n", (void *)pc, (void *)sp, (void *)addr, shadow_val, is_write));
    DEBUG ((DEBUG_INFO, "Stack trace:\n"));
    DEBUG ((DEBUG_INFO, "Return address 0 = %p\n", __builtin_return_address(0)));
    DEBUG ((DEBUG_INFO, "Return address 1 = %p\n", __builtin_return_address(1)));
    DEBUG ((DEBUG_INFO, "Return address 2 = %p\n", __builtin_return_address(2)));
    DEBUG ((DEBUG_INFO, "Return address 3 = %p\n", __builtin_return_address(3)));
}

void __asan_version_mismatch_check_v8(void) {
  DEBUG ((DEBUG_INFO, "[ASAN] __asan_version_mismatch_check_v8()\n"));
}

void __asan_handle_no_return(void) {
  if (!__asan_inited || __asan_in_runtime) {return;}
  __asan_in_runtime = 1;
  DEBUG ((DEBUG_INFO, "__asan_handle_no_return()\n"));
  __asan_in_runtime = 0;
}

void *__asan_memcpy(uptr dst, uptr src, size_t size) {
  ASAN_READ_RANGE(src, size);
  ASAN_WRITE_RANGE(dst, size);
  _memcpy((void *)dst, (void *)src, size);
  return (void *)dst;
}

void *__asan_memset(void *s, int c, size_t n) {
  ASAN_WRITE_RANGE(s, n);
  _memset(s, c, n);
  return s;
}

void __asan_register_globals(const struct __asan_global *globals, uptr n) {
    int i;
    for (i = 0; i < n; i++) {
        PoisonRedZones(globals[i]);
    }
}

// For COFF, globals are put in ASAN$GL, we then add two sections below
// and above ASAN$GL, due to sorting after the dollar sign and compute the 
// amount of __asan_global structs that way.
#pragma section(".ASAN$GA", read, write)
#pragma section(".ASAN$GZ", read, write)
__asan_global __asan_globals_start __attribute__ ((section (".ASAN$GA"))) = {};
__asan_global __asan_globals_end __attribute__ ((section (".ASAN$GZ")))= {};
#pragma comment(linker, "/merge:.ASAN=.data")

static void callOnGlobals(void) {
  __asan_global *start = &__asan_globals_start + 1;
  __asan_global *end = &__asan_globals_end;
  uptr bytediff = (uptr)end - (uptr)start;
  if (bytediff % sizeof(__asan_global) != 0) {
    DEBUG((DEBUG_INFO, "[ASAN] corrupt asan global array\n"));
  }
  // We know end >= start because the linker sorts the portion after the dollar
  // sign alphabetically.
  uptr n = end - start;
  __asan_register_globals(start, n);
}

// Poison globals and possibly setup the FakeStack.
void __asan_init(void) {
  __asan_in_runtime = 1;
  DEBUG ((DEBUG_INFO, "[ASAN] __asan_init(): started\n"));
  __asan_shadow_memory_dynamic_address = (void *)(uptr)SHADOW_OFFSET;
  callOnGlobals();

// Only use the FakeStack if enabled.
#ifdef SANITIZE_SMM_ASAN_FAKESTACK
  initFakeStack();
  __asan_option_detect_stack_use_after_return = 1;
#endif
  initFakeStack();
  __asan_inited = 1;
  __asan_option_detect_stack_use_after_return = 1;
  __asan_can_poison_memory = 1;
  DEBUG ((DEBUG_INFO, "[ASAN] __asan_init(): finished\n"));
  __asan_in_runtime = 0;
}

EFI_STATUS
EFIAPI
AsanLibConstructor (
IN EFI_HANDLE ImageHandle,
IN EFI_SYSTEM_TABLE *SystemTable
) {
    __asan_init();
    return EFI_SUCCESS;
}
