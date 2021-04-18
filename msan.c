#include <stdint.h>
#include <stddef.h>
#include <Library/BaseLib.h>
#include <Protocol/SmmBase2.h>
#include <Library/DebugLib.h> // ASSERT
#include <Library/BaseMemoryLib.h> // functions on memory
#include <Msan.h> // SmmInformation

#define SHADOW_OFFSET 0x7F800000UL
#define SHADOW_BEGIN SHADOW_OFFSET
#define SHADOW_END SHADOW_BEGIN + 0x800000UL
#define AND_MASK 0xffffffffff000000UL
#define MEM_TO_SHADOW(mem) ((mem & ~(AND_MASK)) + (SHADOW_OFFSET))

#define GET_CURRENT_FRAME() (__sanitizer::uptr) __builtin_frame_address(0)

#define GET_CALLER_PC() (__sanitizer::uptr) __builtin_return_address(0)

#define GET_CALLER_PC_BP \
  uptr bp = GET_CURRENT_FRAME();              \
  uptr pc = GET_CALLER_PC();

#define GET_CALLER_PC_BP_SP \
  GET_CALLER_PC_BP;                           \
  UINTN local_stack;                           \
  UINTN sp = (UINTN)&local_stack

#define GET_FATAL_STACK_TRACE_PC_BP(pc, bp)              \
  BufferedStackTrace stack;                              \
  if (msan_inited)                                       \
    stack.Unwind(pc, bp, nullptr, common_flags()->fast_unwind_on_fatal)

const int kMsanParamTlsSize = 800;
const int kMsanRetvalTlsSize = 800;
uint64_t __msan_va_arg_overflow_size_tls;

uint64_t __msan_param_tls[kMsanParamTlsSize / sizeof(uint64_t)];
uint64_t __msan_retval_tls[kMsanRetvalTlsSize / sizeof(uint64_t)];
uint64_t __msan_va_arg_tls[kMsanParamTlsSize / sizeof(uint64_t)];

/*

Based on macros in CryptoPkg/Library/Include/CrtLibSupport.h

#define memcpy(dest,source,count)         CopyMem(dest,source,(UINTN)(count))
#define memset(dest,ch,count)             SetMem(dest,(UINTN)(count),(UINT8)(ch))
#define memchr(buf,ch,count)              ScanMem8(buf,(UINTN)(count),(UINT8)ch)
#define memcmp(buf1,buf2,count)           (int)(CompareMem(buf1,buf2,(UINTN)(count)))
#define memmove(dest,source,count)        CopyMem(dest,source,(UINTN)(count))
#define strlen(str)                       (size_t)(AsciiStrnLenS(str,MAX_STRING_SIZE))
#define strcpy(strDest,strSource)         AsciiStrCpyS(strDest,MAX_STRING_SIZE,strSource)
#define strncpy(strDest,strSource,count)  AsciiStrnCpyS(strDest,MAX_STRING_SIZE,strSource,(UINTN)count)
#define strcat(strDest,strSource)         AsciiStrCatS(strDest,MAX_STRING_SIZE,strSource)
#define strncmp(string1,string2,count)    (int)(AsciiStrnCmp(string1,string2,(UINTN)(count)))
#define strcasecmp(str1,str2)             (int)AsciiStriCmp(str1,str2)
#define sprintf(buf,...)                  AsciiSPrint(buf,MAX_STRING_SIZE,__VA_ARGS__)
#define localtime(timer)                  NULL
#define assert(expression)
#define atoi(nptr)                        AsciiStrDecimalToUintn(nptr)
#define gettimeofday(tvp,tz)              do { (tvp)->tv_sec = time(NULL); (tvp)->tv_usec = 0; } while (0)

void *memcpy(void *dest, const void *src, size_t n) {
  return CopyMem(dest,src,(UINTN)(n));
}
*/

void *memset(void *s, int c, size_t n)
{
  unsigned char *d;

  d = s;

  while (n-- != 0) {
    *d++ = (unsigned char)c;
  }

  return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
  unsigned char *d;
  unsigned char const *s;

  d = dest;
  s = src;

  while (n-- != 0) {
    *d++ = *s++;
  }

  return dest;
}

void *__msan_memcpy(void *dst, const void *src, size_t n) {
  void *res = memcpy(dst, src, n);
  memcpy((void *)MEM_TO_SHADOW((UINTN)dst),
    (void *)MEM_TO_SHADOW((UINTN)src), n);

  return res;
}

void SetShadow(const void *ptr, UINTN size, UINT8 value) {
  UINTN shadow_beg = MEM_TO_SHADOW((UINTN)ptr);
  UINTN shadow_end = shadow_beg + size;
  ASSERT (shadow_beg >= SHADOW_BEGIN);
  ASSERT (shadow_end < SHADOW_END);
  memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

void __msan_unpoison(const void *a, UINTN size) {
  SetShadow(a, size, 0);
}

void __msan_poison(const void *a, UINTN size) {
  SetShadow(a, size, -1);
}

// Poison section SectionName which starts at BaseAddress until BaseAddress + Size.
void PoisonSection(CHAR8 *DriverName, CHAR8 *SectionName, UINTN BaseAddress, UINTN Size) {
  DEBUG ((DEBUG_INFO, "PoisonSection()@%p\n", PoisonSection));
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
  // .data is not initialized
  else if (AsciiStrCmp((CHAR8 *)SectionName, ".data") == 0) {
    DEBUG ((DEBUG_INFO, "  Applying poisoning to section %a...\n", SectionName));
    __msan_poison((void *)BaseAddress, Size);
  }
  else {
    DEBUG ((DEBUG_INFO, "  Not poisoning section %a.\n", SectionName));
  }
}

void __msan_init(void) {
  DEBUG ((DEBUG_INFO, "__msan_init()@%p\n", __msan_init));
  asm volatile ("hlt");
}

void __msan_warning_noreturn(void) {
  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn()\n"));
  asm volatile("hlt");
}

void __msan_noreturn_tianocore(char *f) {
  int i = 0;
  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn() for function: "));
  while (f[i] != 0) {
    DEBUG((DEBUG_INFO, "%c", f[i]));
    i++;
  }
  DEBUG((DEBUG_INFO, "\n"));
  //asm volatile("hlt");
}
