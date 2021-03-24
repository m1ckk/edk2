#include <stddef.h>
#include <stdbool.h>
#include <Library/DebugLib.h>

typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned char u8;
typedef UINTN uptr;

int __asan_option_detect_stack_use_after_return;
void *__asan_shadow_memory_dynamic_address;

// As defined for SMM, this is according to AddressSanitizer.cpp
static const u64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
#define SHADOW_OFFSET 0x7F800000UL
#define AND_MASK 0xffffffffff000000UL
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define MEM_TO_SHADOW(mem) (((mem & ~(AND_MASK)) >> SHADOW_SCALE) + (SHADOW_OFFSET))

// These magic values are written to shadow for better error reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapFreeMagic = 0xfd;
const int kAsanStackLeftRedzoneMagic = 0xf1;
const int kAsanStackMidRedzoneMagic = 0xf2;
const int kAsanStackRightRedzoneMagic = 0xf3;
const int kAsanStackAfterReturnMagic = 0xf5;
const int kAsanInitializationOrderMagic = 0xf6;
const int kAsanUserPoisonedMemoryMagic = 0xf7;
const int kAsanContiguousContainerOOBMagic = 0xfc;
const int kAsanStackUseAfterScopeMagic = 0xf8;
const int kAsanGlobalRedzoneMagic = 0xf9;
const int kAsanInternalHeapMagic = 0xfe;
const int kAsanArrayCookieMagic = 0xac;
const int kAsanIntraObjectRedzone = 0xbb;
const int kAsanAllocaLeftMagic = 0xca;
const int kAsanAllocaRightMagic = 0xcb;



#define GET_CALLER_PC() (uptr) __builtin_return_address(0)
#define GET_CURRENT_FRAME() (uptr) __builtin_frame_address(0)

// Use this macro if you want to print stack trace with the caller
// of the current function in the top frame.
#define GET_CALLER_PC_BP \
  uptr bp = GET_CURRENT_FRAME();              \
  uptr pc = GET_CALLER_PC();

#define GET_CALLER_PC_BP_SP \
  GET_CALLER_PC_BP;                           \
  uptr local_stack;                           \
  uptr sp = (uptr)&local_stack


void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
        uptr access_size, u32 exp, bool fatal) {
    u8 *shadow_addr = (u8 *)MEM_TO_SHADOW(addr);
    u8 shadow_val = *shadow_addr;
    //int bug_idx = 0;

    DEBUG ((DEBUG_INFO, "ERROR: pc=%p, sp=%p, addr=%p, shadow value=%x, is_write=%x\n", (void *)pc, (void *)sp, (void *)addr, shadow_val, is_write));
    asm volatile("hlt");
}


#define ASAN_DECLARATION(type, is_write, size)                              \
void __asan_report_exp_ ## type ## size(uptr addr) {                        \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_exp_ ## type##_## size(uptr addr) {                      \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_exp_ ## type ## size(uptr addr) {                               \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_ ## type ## size(uptr addr) {                            \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_ ## type##_## size(uptr addr) {                          \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_ ## type ## size(uptr addr) {                                   \
  DEBUG ((DEBUG_INFO, "%a", __func__));                                     \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}

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

#define DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(class_id)                   \
  void *__asan_stack_malloc_##class_id(uptr size) {                         \
    return NULL;                                                            \
  }                                                                         \
  void __asan_stack_free_##class_id(uptr ptr, uptr size) {                  \
  }

DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(0);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(1);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(2);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(3);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(4);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(5);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(6);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(7);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(8);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(9);
DECLARE_STACK_MALLOC_FREE_WITH_CLASS_ID(10);

// This structure is used to describe the source location of a place where
// global was defined.
struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};

// This structure describes an instrumented global variable.
struct __asan_global {
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
};

void __asan_init(void) {
  DEBUG ((DEBUG_INFO, "__asan_init()\n"));
  __asan_shadow_memory_dynamic_address = (void *)(uptr)0x7F800000;
/*
  // To test whether paging is setup for the upper half of the 16MB TSEG.
  char *buf = __asan_shadow_memory_dynamic_address;
  buf[0] = 'a';
  buf[0x1000] = 'b';
  buf[0x10000] = 'c';
  buf[0x100000] = 'd';
  DEBUG ((DEBUG_INFO, "buf[0] = %c\n", buf[0]));
  DEBUG ((DEBUG_INFO, "buf[0x1000] = %c\n", buf[0x1000]));
  DEBUG ((DEBUG_INFO, "buf[0x10000] = %c\n", buf[0x10000]));
  DEBUG ((DEBUG_INFO, "buf[0x100000] = %c\n", buf[0x100000]));
  // To test whether paging is setup for the lower half of the 16MB TSEG.
  buf = (void *)(uptr)0x7F000000;
  buf[0] = 'a';
  buf[0x1000] = 'b';
  buf[0x10000] = 'c';
  buf[0x100000] = 'd';
  DEBUG ((DEBUG_INFO, "buf[0] = %c\n", buf[0]));
  DEBUG ((DEBUG_INFO, "buf[0x1000] = %c\n", buf[0x1000]));
  DEBUG ((DEBUG_INFO, "buf[0x10000] = %c\n", buf[0x10000]));
  DEBUG ((DEBUG_INFO, "buf[0x100000] = %c\n", buf[0x100000]));
*/
}

void __asan_before_dynamic_init(const char *module_name) {
  DEBUG ((DEBUG_INFO, "__asan_before_dynamic_init()\n"));
  DEBUG ((DEBUG_INFO, "    module_name = %s\n", module_name));
}

void __asan_after_dynamic_init() {
  DEBUG ((DEBUG_INFO, "__asan_after_dynamic_init()\n"));
}

void __asan_version_mismatch_check_v8(void) {
  DEBUG ((DEBUG_INFO, "__asan_version_mismatch_check_v8()\n"));
}

void __asan_register_globals(const struct __asan_global *globals, uptr n) {
  DEBUG ((DEBUG_INFO, "__asan_register_globals()\n"));
}

void __asan_unregister_globals(const struct __asan_global *globals, uptr n) {
  DEBUG ((DEBUG_INFO, "__asan_unregister_globals()\n"));
}

void __asan_register_image_globals(uptr *flag) {
  DEBUG ((DEBUG_INFO, "__asan_register_image_globals()\n"));
}

void __asan_unregister_image_globals(uptr *flag) {
  DEBUG ((DEBUG_INFO, "__asan_unregister_image_globals()\n"));
}

void __asan_register_elf_globals() {
  DEBUG ((DEBUG_INFO, "__asan_register_elf_globals()\n"));
}

void __asan_unregister_elf_globals() {
  DEBUG ((DEBUG_INFO, "__asan_unregister_elf_globals()\n"));
}

void __asan_handle_no_return(void) {
}

////////////////////////////////////////////////////////////////
////// Copied from /mnt/part5/llvm-project/compiler-rt/lib/interception/interception_win.cc
////////////////////////////////////////////////////////////////

/*
static uptr RoundUpTo(uptr size, uptr boundary) {
  return (size + boundary - 1) & ~(boundary - 1);
}


// FIXME: internal_str* and internal_mem* functions should be moved from the
// ASan sources into interception/.

static size_t _strlen(const char *str) {
  const char* p = str;
  while (*p != '\0') ++p;
  return p - str;
}

static char* _strchr(char* str, char c) {
  while (*str) {
    if (*str == c)
      return str;
    ++str;
  }
  return NULL;
}
*/

static void _memset(void *p, int value, size_t sz) {
  for (size_t i = 0; i < sz; ++i)
    ((char*)p)[i] = (char)value;
}

static void _memcpy(void *dst, void *src, size_t sz) {
  char *dst_c = (char*)dst,
       *src_c = (char*)src;
  for (size_t i = 0; i < sz; ++i)
    dst_c[i] = src_c[i];
}

////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////

void *__asan_memcpy(uptr dst, uptr src, size_t size) {
  _memcpy((void *)dst, (void *)src, size);
  return (void *)dst;
}

/*
void *__asan_memmove(void *dest, const void *src, size_t n) {
    return memmove(dest, src, n);
}
*/

void *__asan_memset(void *s, int c, size_t n) {
  _memset(s, c, n);
  return s;
}
void __sanitizer_ptr_sub(void *a, void *b) {
}

void __sanitizer_ptr_cmp(void *a, void *b) {
}

void __asan_set_shadow_00(uptr addr, uptr size) {
}

void __asan_set_shadow_f1(uptr addr, uptr size) {
}

void __asan_set_shadow_f2(uptr addr, uptr size) {
}

void __asan_set_shadow_f3(uptr addr, uptr size) {
}

void __asan_set_shadow_f5(uptr addr, uptr size) {
}

void __asan_set_shadow_f8(uptr addr, uptr size) {
}

void __asan_allocas_unpoison() {
}

void __asan_alloca_poison() {
}

void __asan_poison_stack_memory() {
}

void __asan_unpoison_stack_memory() {
}

/*
uptr RoundDownTo(uptr size, uptr boundary) {
    return 0;
}
void PoisonRedZones(const struct __asan_global g) {
}

void FastPoisonShadowPartialRightRedzone(
        uptr aligned_addr, uptr size, uptr redzone_size, u8 value) {
}

void FastPoisonShadow(uptr aligned_beg, uptr aligned_size,
        u8 value) {
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
        uptr access_size, u32 exp, bool fatal) {
}

*/
