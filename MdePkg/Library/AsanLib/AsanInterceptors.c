#include <Library/DebugLib.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmBase2.h>
#include "AsanAlloc.h"


/*
Things which I have looked for when (un)poisoning are:
 - Poison parameters accordingly when they are initialized
 - Poison buffers that are allocated if possible
   - For allocations which can happen outside of SMRAM we cannot implement the
   - the shadowing, we have to see if this will result in errors in the future.
 - Poison buffers that are freed, though this is not always possible
   - It seems that sometimes (maybe always) only a pointer is provided, which 
     then implies the size of the buffer, since we have no access to this data
     structure that maps pointers to sizes of buffers, we don't know how much 
     we should poison.
 - Unpoison the addresses that are initialized by the indirect function call
 - Unpoison the addresses of addresses, e.g., when a stack address is given,
   where the stack address is initialized with a pointer, where the pointer
   points to initialized memory. In this case we have to poison twice, one
   time for the stack variable that gets initialized and one time for the
   data structure that gets initialized by the external function call. See
   for example MdePkg/Library/SmmMemoryAllocationLib/MemoryAllocationLib.c:513.

*/

/////////////////////////////////////
/////  _EFI_SMM_SYSTEM_TABLE2 struct
/////////////////////////////////////

EFI_STATUS __asan__EFI_SMM_SYSTEM_TABLE2_SmmRegisterProtocolNotify(
    IN  CONST EFI_GUID        *Protocol,
    IN  EFI_SMM_NOTIFY_FN     Function,
    OUT VOID                  **Registration,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmRegisterProtocolNotify (Protocol, Function, Registration);
  return Status;
}

EFI_STATUS __asan__EFI_SMM_SYSTEM_TABLE2_SmmAllocatePool(
    IN  EFI_MEMORY_TYPE       PoolType,
    IN  UINTN                 Size,
    OUT VOID                  **Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  return __asan_SmmAllocatePool(PoolType, Size, Buffer, gSmst);
}

// TODO: We don't have a size of the buffer, therefore, we have to manually
// add the poisoning I reckon.
EFI_STATUS __asan__EFI_SMM_SYSTEM_TABLE2_SmmFreePool(
    IN VOID                   *Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  return __asan_SmmFreePool(Buffer, gSmst);
}

EFI_STATUS __asan__EFI_SMM_SYSTEM_TABLE2_SmmAllocatePages(
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory,
  IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmAllocatePages(Type, MemoryType, NumberOfPages, Memory);
  return Status;
}

EFI_STATUS __asan__EFI_SMM_SYSTEM_TABLE2_SmmFreePages(
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages,
  IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmFreePages(Memory, NumberOfPages);
  return Status;
}

/////////////////////////////////////
/////  _EFI_SMM_BASE2_PROTOCOL struct
/////////////////////////////////////

EFI_STATUS __asan__EFI_SMM_BASE2_PROTOCOL_GetSmstLocation(
    IN CONST EFI_SMM_BASE2_PROTOCOL *This,
    OUT      EFI_SMM_SYSTEM_TABLE2  **Smst,
    IN EFI_SMM_BASE2_PROTOCOL       *mSmmBase2
) {
  EFI_STATUS Status;
  Status = mSmmBase2->GetSmstLocation(This, Smst);
  return Status;
}
