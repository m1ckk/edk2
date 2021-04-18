#include <stddef.h>
#include <stdbool.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
//

typedef UINT32 u32;
typedef UINT64 u64;
typedef UINT8 u8;
typedef UINTN uptr;

int __asan_option_detect_stack_use_after_return = 1;
void *__asan_shadow_memory_dynamic_address;

// As defined for SMM, this is according to AddressSanitizer.cpp
static const u64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
// Starting at 0x7Fe00000 allows us to map the memory range 0x7F000000
// to 0x7Fdfffff to shadow memory 0x7Fe00000 to 0x80000000
#define SHADOW_OFFSET 0x7Fe00000UL
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

    DEBUG ((DEBUG_INFO, "[ASAN] ERROR: pc=%p, sp=%p, addr=%p, shadow value=%x, is_write=%x\n", (void *)pc, (void *)sp, (void *)addr, shadow_val, is_write));
    asm volatile("hlt");
}


#define ASAN_DECLARATION(type, is_write, size)                              \
void __asan_report_exp_ ## type ## size(uptr addr) {                        \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_exp_ ## type##_## size(uptr addr) {                      \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_exp_ ## type ## size(uptr addr) {                               \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_ ## type ## size(uptr addr) {                            \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_report_ ## type##_## size(uptr addr) {                          \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
  GET_CALLER_PC_BP_SP;                                                      \
  ReportGenericError(pc, bp, sp, addr, is_write, -1, 0, true);              \
}                                                                           \
void __asan_ ## type ## size(uptr addr) {                                   \
  DEBUG ((DEBUG_INFO, "[ASAN] %a", __func__));                              \
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

void __asan_version_mismatch_check_v8(void) {
  DEBUG ((DEBUG_INFO, "[ASAN] __asan_version_mismatch_check_v8()\n"));
}

void __asan_handle_no_return(void) {
  DEBUG ((DEBUG_INFO, "__asan_handle_no_return()\n"));
  asm volatile("hlt");
}

static uptr RoundUpTo(uptr size, uptr boundary) {
  return (size + boundary - 1) & ~(boundary - 1);
}

static uptr RoundDownTo(uptr x, uptr boundary) {
  return x & ~(boundary - 1);
}

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
    uptr shadow_beg = MEM_TO_SHADOW(aligned_beg);
    uptr shadow_end = MEM_TO_SHADOW(
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
    u8 *shadow = (u8*)MEM_TO_SHADOW(aligned_addr);
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

void __asan_register_globals(const struct __asan_global *globals, uptr n) {
    int i;
    for (i = 0; i < n; i++) {
        DEBUG ((DEBUG_INFO, "[ASAN] global.beg = 0x%lx\n", globals[i].beg));
        DEBUG ((DEBUG_INFO, "[ASAN] global.size = 0x%lx\n", globals[i].size));
        DEBUG ((DEBUG_INFO, "[ASAN] global.size_with_redzone = 0x%lx\n", globals[i].size_with_redzone));
        DEBUG ((DEBUG_INFO, "[ASAN] global.name = 0x%p\n", globals[i].name));
        DEBUG ((DEBUG_INFO, "[ASAN] global.module_name = 0x%p\n", globals[i].module_name));
        DEBUG ((DEBUG_INFO, "[ASAN] global.name = %a\n", globals[i].name));
        DEBUG ((DEBUG_INFO, "[ASAN] global.module_name = %a\n", globals[i].module_name));
        DEBUG ((DEBUG_INFO, "[ASAN] global.location->filename = %a\n", globals[i].location->filename));
        DEBUG ((DEBUG_INFO, "[ASAN] global.location->line_no = %d\n", globals[i].location->line_no));
        DEBUG ((DEBUG_INFO, "[ASAN] global.location->column_no = %d\n", globals[i].location->column_no));
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

static void call_on_globals(void) {
  __asan_global *start = &__asan_globals_start + 1;
  __asan_global *end = &__asan_globals_end;
  uptr bytediff = (uptr)end - (uptr)start;
  if (bytediff % sizeof(__asan_global) != 0) {
#if defined(SANITIZER_DLL_THUNK) || defined(SANITIZER_DYNAMIC_RUNTIME_THUNK)
    __debugbreak();
#else
    DEBUG((DEBUG_INFO, "[ASAN] corrupt asan global array\n"));
#endif
  }
  // We know end >= start because the linker sorts the portion after the dollar
  // sign alphabetically.
  uptr n = end - start;
  __asan_register_globals(start, n);
}


//////////////////////////////////////////////////////////////////////////////
///////         START - FakeStack implementation
//////////////////////////////////////////////////////////////////////////////
const UINTN FAKE_STACK_START = 0x7F900000ULL;
const UINTN FAKE_STACK_SIZE = 8192;
const UINTN NR_FAKE_STACKS = 8;

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

FakeStack __asan_fs;

// Given an index and class ID, return a pointer to Nth FakeFrame that belongs
// to the given class ID. The corresponding FakeStack is computed by adding
// the base address (FAKE_STACK_START) to the ID multiplied by the size of a 
// single FakeStack size (FAKE_STACK_SIZE * id), then find the corresponding
// FakeFrame, by computing the size of a single FakeFrame and multiplying that
// with the given index ((64 << id) * index).
#define GET_FRAME(index, id) (FakeFrame *)(FAKE_STACK_START + \
    (FAKE_STACK_SIZE * id) + (64 << id) * index)

static void init_fake_stack(void) {
    for (int i = 0; i < NR_FAKE_STACKS; i++) {
        __asan_fs.IndexFakeFrame[i] = 0;
        __asan_fs.NrFakeFrames[i] = FAKE_STACK_SIZE / (64 << i);
        __asan_fs.FakeFrames[i] = (FakeFrame *)(FAKE_STACK_START + 
            i * FAKE_STACK_SIZE);
        // Zero out the memory, so all flags are 0.
        _memset((void *)FAKE_STACK_START, 0, FAKE_STACK_SIZE * NR_FAKE_STACKS);
/*
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.IndexFakeFrame[%d] =  %d\n", i, __asan_fs.IndexFakeFrame[i]));
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.NrFakeFrames[%d] =    %d\n", i, __asan_fs.NrFakeFrames[i]));
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.FakeFrames[%d] =      %p\n", i, __asan_fs.FakeFrames[i]));
*/
    }
}

static FakeFrame *allocFakeFrame(UINTN class_id) {
    FakeFrame *ff;
    int nr_fake_frames = __asan_fs.NrFakeFrames[class_id];
    // We start with the saved index, which is the index after the most 
    // recently allocated frame, to delay reusing the frame that was just
    // deallocated.
    int index = __asan_fs.IndexFakeFrame[class_id];
    int i = 0;
/*
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): class_id =       %lu\n", class_id));
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): nr_fake_frames = %lu\n", nr_fake_frames));
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): index =          %d\n", index));
*/
    while (i < nr_fake_frames) {
        ff = GET_FRAME(index, class_id);
/*
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff =         %p\n", ff));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff->flags =  %x\n", ff->flags));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff->magic =  %p\n", ff->magic));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): index =      %d\n", index));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): i =          %d\n", i));
*/
        // Allocate the frame if it is inactive.
        if (!ff->flags) {
            ff->flags = 1;
            // That way we begin looking for new frames after the most recently
            // allocated frame.
            __asan_fs.IndexFakeFrame[class_id] = (index + 1) % nr_fake_frames;
            FastPoisonShadow((UINTN)ff, 64 << class_id, 0);
            return ff;
        }
        i++;
        index = (index + 1) % nr_fake_frames;
    }
    // No FakeFrames left for class_id
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): ERROR\n"));
    asm volatile("hlt");
    return NULL;
}

static void freeFakeFrame(UINTN ptr, UINTN class_id) {
    ASSERT ((UINTN)__asan_fs.FakeFrames[class_id] <= ptr);
    ASSERT (ptr < (UINTN)(__asan_fs.FakeFrames[class_id] + FAKE_STACK_SIZE));

    FakeFrame *ff = (FakeFrame *)ptr;
/*
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): ff =         %p\n", ff));
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): class_id =   %lu\n", class_id));
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): ptr =        %p\n", ptr));
*/
    ff->flags = 0;
    FastPoisonShadow((UINTN)ff, 64 << class_id, kAsanStackAfterReturnMagic);
}


#define DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(class_id)                    \
void *__asan_stack_malloc_##class_id(uptr size) {                           \
    return allocFakeFrame(class_id);                                        \
}                                                                           \
void __asan_stack_free_##class_id(uptr ptr, uptr size) {                    \
    freeFakeFrame(ptr, class_id);                                           \
}

DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(0);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(1);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(2);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(3);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(4);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(5);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(6);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(7);


//////////////////////////////////////////////////////////////////////////////
///////         END - FakeStack implementation
//////////////////////////////////////////////////////////////////////////////




void __asan_init(void) {
  DEBUG ((DEBUG_INFO, "[ASAN] __asan_init()\n"));
  __asan_shadow_memory_dynamic_address = (void *)(uptr)SHADOW_OFFSET;
  call_on_globals();
  init_fake_stack();
}

