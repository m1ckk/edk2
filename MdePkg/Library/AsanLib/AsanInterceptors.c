#include <Library/DebugLib.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmBase2.h>
#include "AsanAlloc.h"

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
