#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

UINTN fakestack_size;

typedef struct {
  UINT32            Signature;
  BOOLEAN           Available;
  EFI_MEMORY_TYPE   Type;
  UINTN             Size;
} POOL_HEADER;

typedef struct {
  POOL_HEADER  Header;
  LIST_ENTRY   Link;
} FREE_POOL_HEADER;


UINTN peak_heap_size, heap_size;

EFI_STATUS check_heap_SmmAllocatePool (
    IN  EFI_MEMORY_TYPE       PoolType,
    IN  UINTN                 Size,
    OUT VOID                  **Buffer
) {
  heap_size += Size;
  if (heap_size > peak_heap_size)
    peak_heap_size = heap_size;

  return EFI_SUCCESS;
}

EFI_STATUS check_heap_SmmFreePool (
    IN VOID                   *Buffer
) {
  FREE_POOL_HEADER  *FreePoolHdr;
  FreePoolHdr = (FREE_POOL_HEADER*)((POOL_HEADER*)Buffer - 1);
  UINTN Size = FreePoolHdr->Header.Size;

  heap_size -= Size;
  return EFI_SUCCESS;
}

UINTN highest_sp, lowest_sp, peak_stack_size;

void check_stack_size(void) {
  UINTN sp;
  asm volatile ("movq %%rsp, %0;" 
   :"=r"(sp)        /* output */
   :
   :
   );
  if (sp < lowest_sp)
    lowest_sp = sp;
  if (sp > highest_sp)
    highest_sp = sp;
  if ((highest_sp - lowest_sp) > peak_stack_size)
    peak_stack_size = highest_sp - lowest_sp;
}

EFI_STATUS
EFIAPI
MemoryFootprintLibConstructor (
IN EFI_HANDLE ImageHandle,
IN EFI_SYSTEM_TABLE *SystemTable
) { 
  peak_heap_size = heap_size = peak_stack_size = highest_sp = fakestack_size = 0;
  lowest_sp = 0xffffffffUL;
  return EFI_SUCCESS;
}

