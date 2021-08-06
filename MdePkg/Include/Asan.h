void __asan_read_range(const void *Buf, UINTN Size);
void __asan_write_range(const void *Buf, UINTN Size);

// The memcpy used to copy memory from outside to inside SMM.
VOID *CopyMemNoAsan (
  OUT VOID       *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  );

