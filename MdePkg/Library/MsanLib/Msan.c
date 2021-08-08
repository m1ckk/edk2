#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include "Msan.h"
#include "MsanReport.h"
#include "MsanPoisoning.h"

bool fast_unwind_on_fatal = 1;
bool print_stats = 1;

const int kMsanParamTlsSize = 800;
const int kMsanRetvalTlsSize = 800;
u64 __msan_va_arg_overflow_size_tls;

// Used to indicate whether return addresses or parameters are initialized.
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
  __msan_unpoison_param(3);
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
  DEBUG ((DEBUG_INFO, "__msan_warning_tianocore(): UMRCounter = %u, call_id = %u\n", UMRCounter, call_id));
  DEBUG ((DEBUG_INFO, "  in function: "));
  while (*func != 0) {
    DEBUG ((DEBUG_INFO, "%c", *func));
    func++;
  }
  DEBUG ((DEBUG_INFO, "\n"));
  ReportUMR();
}

/*
void __msan_warning_noreturn(void) {
  asm volatile("hlt");
  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn()\n"));
}
*/

void __msan_noreturn_tianocore(char *f, uptr call_id) {
  DEBUG ((DEBUG_INFO, "__msan_warning_noreturn() for function: "));
  int i = 0;
  while (f[i] != 0) {
    DEBUG((DEBUG_INFO, "%c", f[i]));
    i++;
  }
  DEBUG((DEBUG_INFO, "\n"));
  UMRCounter++;
  DEBUG ((DEBUG_INFO, "UMRCounter = %ul\n", UMRCounter));
  ReportUMR();

  asm volatile ("hlt");
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

// Weak function definition since the SMM_CORE doesn't need memory logging.
// MsanLib shares its code with SMM_CORE and SMM_DRIVER.
#ifndef SANITIZE_SMM_MEMORY_FOOTPRINT
void check_stack_size(void) {}
#endif

// The initialization is done when VariableSmm is loaded, i.e. poisoning of sections.
EFI_STATUS
EFIAPI
MsanLibConstructor (
IN EFI_HANDLE ImageHandle,
IN EFI_SYSTEM_TABLE *SystemTable
) { 
    return EFI_SUCCESS;
}

