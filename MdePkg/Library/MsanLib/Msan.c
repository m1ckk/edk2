#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include "Msan.h"
#include "SanitizerStackTrace.h"
#include "MsanReport.h"
#include "MsanInternal.h"

bool fast_unwind_on_fatal = 1;
bool print_stats = 1;

const int kMsanParamTlsSize = 800;
const int kMsanRetvalTlsSize = 800;
u64 __msan_va_arg_overflow_size_tls;

u64 __msan_param_tls[kMsanParamTlsSize / sizeof(u64)];
u64 __msan_retval_tls[kMsanRetvalTlsSize / sizeof(u64)];
u64 __msan_va_arg_tls[kMsanParamTlsSize / sizeof(u64)];

int msan_report_count = 0;
// Not much needed to initialize MSan, so for now we just assume it inited.
int msan_inited = 1;


/*

Based on macros in CryptoPkg/Library/Include/CrtLibSupport.h

#define memcpy(dest,source,count)         CopyMem(dest,source,(uptr)(count))
#define memset(dest,ch,count)             SetMem(dest,(uptr)(count),(UINT8)(ch))
#define memchr(buf,ch,count)              ScanMem8(buf,(uptr)(count),(UINT8)ch)
#define memcmp(buf1,buf2,count)           (int)(CompareMem(buf1,buf2,(uptr)(count)))
#define memmove(dest,source,count)        CopyMem(dest,source,(uptr)(count))
#define strlen(str)                       (size_t)(AsciiStrnLenS(str,MAX_STRING_SIZE))
#define strcpy(strDest,strSource)         AsciiStrCpyS(strDest,MAX_STRING_SIZE,strSource)
#define strncpy(strDest,strSource,count)  AsciiStrnCpyS(strDest,MAX_STRING_SIZE,strSource,(uptr)count)
#define strcat(strDest,strSource)         AsciiStrCatS(strDest,MAX_STRING_SIZE,strSource)
#define strncmp(string1,string2,count)    (int)(AsciiStrnCmp(string1,string2,(uptr)(count)))
#define strcasecmp(str1,str2)             (int)AsciiStriCmp(str1,str2)
#define sprintf(buf,...)                  AsciiSPrint(buf,MAX_STRING_SIZE,__VA_ARGS__)
#define localtime(timer)                  NULL
#define assert(expression)
#define atoi(nptr)                        AsciiStrDecimalToUintn(nptr)
#define gettimeofday(tvp,tz)              do { (tvp)->tv_sec = time(NULL); (tvp)->tv_usec = 0; } while (0)

void *memcpy(void *dest, const void *src, size_t n) {
  return CopyMem(dest,src,(uptr)(n));
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
  memcpy((void *)MEM_TO_SHADOW((uptr)dst),
    (void *)MEM_TO_SHADOW((uptr)src), n);

  return res;
}

void __msan_init(void) {
  asm volatile ("hlt");
  DEBUG ((DEBUG_INFO, "__msan_init()@%p\n", __msan_init));
}

size_t UMRCounter = 0;

void __msan_warning_tianocore(char *func, uptr call_id) {
    UMRCounter++;
    DEBUG ((DEBUG_INFO, "__msan_warning_tianocore(): UMRCounter = %u\n", UMRCounter));
}


void __msan_warning_noreturn(void) {
  asm volatile("hlt");
  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn()\n"));
}

void PrintWarningWithOrigin(uptr pc, uptr bp, u32 origin) {
#if 0
  if (msan_expect_umr) {
    // Printf("Expected UMR\n");
    __msan_origin_tls = origin;
    msan_expected_umr_found = 1;
    return;
  }
#endif

  ++msan_report_count;

  GET_FATAL_STACK_TRACE_PC_BP(pc, bp);
  u32 report_origin =
#if 0
    (__msan_get_track_origins() && Origin::isValidId(origin)) ? origin : 0;
#else
    0;
#endif
  ReportUMR(&stack, report_origin);

#if 0
  if (__msan_get_track_origins() && !Origin::isValidId(origin)) {
    Printf(
        "  ORIGIN: invalid (%x). Might be a bug in MemorySanitizer origin "
        "tracking.\n    This could still be a bug in your code, too!\n",
        origin);
  }
#endif
}

void PrintWarning(uptr pc, uptr bp) {
#if 0
  PrintWarningWithOrigin(pc, bp, __msan_origin_tls);
#else
  PrintWarningWithOrigin(pc, bp, 0);
#endif
}

void __msan_noreturn_tianocore(char *f, uptr call_id) {
/*
  for (int i = 0; i < call_id; i++)
    asm volatile ("nop");
  asm volatile ("hlt");
*/
  GET_CALLER_PC_BP_SP;
  (void)sp;

  PrintWarning(pc, bp);
  if (print_stats)
    ReportStats();

  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn() for function: "));
  int i = 0;
  while (f[i] != 0) {
    DEBUG((DEBUG_INFO, "%c", f[i]));
    i++;
  }
  DEBUG((DEBUG_INFO, "\n"));
  UMRCounter++;
  DEBUG ((DEBUG_INFO, "UMRCounter = %ul\n", UMRCounter));


  //asm volatile ("hlt");
}

void __msan_print_shadow(void *ptr, int size) {
  int i = 0;
  uptr shadow_ptr = MEM_TO_SHADOW((uptr)ptr);
  unsigned char *c = (unsigned char *)shadow_ptr;
  
  DEBUG ((DEBUG_INFO, "Shadow variables:\n"));

  for (i = 0; i < 8; i++)
    DEBUG ((DEBUG_INFO, "__msan_param_tls[%d] = 0x%x\n", i, __msan_param_tls[i]));
  for (i = 0; i < 8; i++)
    DEBUG ((DEBUG_INFO, "__msan_retval_tls[%d] = 0x%x\n", i, __msan_retval_tls[i]));
  
  DEBUG ((DEBUG_INFO, "Shadow memory:\n"));
  for (i = 0; i < size; i++)
    DEBUG ((DEBUG_INFO, "0x%p %x\n", &c[i], c[i]));
}

EFI_STATUS
EFIAPI
MsanLibConstructor (
IN EFI_HANDLE ImageHandle,
IN EFI_SYSTEM_TABLE *SystemTable
) { 
    return EFI_SUCCESS;
}

