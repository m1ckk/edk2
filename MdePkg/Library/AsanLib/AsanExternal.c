#include "Asan.h"
#include "AsanPoisoning.h"

void __asan_read_range(void *Buf, UINTN Size) {
  ASAN_READ_RANGE((uptr)Buf, Size);
}

void __asan_write_range(void *Buf, UINTN Size) {
  ASAN_WRITE_RANGE((uptr)Buf, Size);
}

// CopyMem implementation which is not instrumented, used when copying data
// to or from outside of SMRAM.
VOID *CopyMemNoAsan (
  OUT VOID       *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{ 
  if (Length == 0) {
    return DestinationBuffer;
  } 
  ASSERT ((Length - 1) <= (MAX_ADDRESS - (UINTN)DestinationBuffer));
  ASSERT ((Length - 1) <= (MAX_ADDRESS - (UINTN)SourceBuffer));
  
  
  char *dst_c = (char*)DestinationBuffer,
       *src_c = (char*)SourceBuffer;
  for (size_t i = 0; i < Length; ++i)
    dst_c[i] = src_c[i]; 

  return DestinationBuffer;
}   
