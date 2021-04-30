#include <Library/DebugLib.h>
#include <Protocol/SmmAccess2.h>
#include <Pi/PiSmmCis.h>

#include "Msan.h"
#include "MsanPoisoning.h"

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
///// EFI_BOOT_SERVICES struct
/////////////////////////////////////
EFI_STATUS __msan_EFI_BOOT_SERVICES_LocateProtocol(
    IN  EFI_GUID  *Protocol,
    IN  VOID      *Registration, OPTIONAL
    OUT VOID      **Interface,
    IN  EFI_BOOT_SERVICES *gBS
) {
  EFI_STATUS Status;
  Status = gBS->LocateProtocol(Protocol,
                      Registration,
                      Interface);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Interface, sizeof(*Interface));
    // *Interface points to some data structure containing the functions of
    // the protocol.
    //__msan_unpoison(*Interface, sizeof(void *));
  }
  return Status;
}

// This function is to free memory outside of SMRAM, therefore, we shouldn't
// perform any shadow propagation for now.
void __msan_EFI_BOOT_SERVICES_FreePool(
    IN VOID   *Buffer,
    IN  EFI_BOOT_SERVICES *gBS
  ) {
  gBS->FreePool(Buffer);
}

// This function is to free memory outside of SMRAM, therefore, we shouldn't
// perform any shadow propagation for now.
EFI_STATUS __msan_EFI_BOOT_SERVICES_AllocatePool(
    IN EFI_MEMORY_TYPE  PoolType,
    IN UINTN            Size,
    OUT VOID            **Buffer,
    IN  EFI_BOOT_SERVICES *gBS
  ) {
  EFI_STATUS Status;
  Status = gBS->AllocatePool(PoolType, Size, Buffer);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    // Though *Buffer likely points outside of SMRAM, we should still unpoison
    // the variable which points to *Buffer.
    __msan_unpoison(Buffer, sizeof *Buffer);
  }
  return Status;
}

EFI_STATUS __msan_EFI_BOOT_SERVICES_GetMemoryMap(
    IN OUT UINTN                  *MemoryMapSize,
    IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
    OUT UINTN                     *MapKey,
    OUT UINTN                     *DescriptorSize,
    OUT UINT32                    *DescriptorVersion,
    IN  EFI_BOOT_SERVICES         *gBS
) {
  EFI_STATUS Status;
  Status = gBS->GetMemoryMap(
            MemoryMapSize,
            MemoryMap,
            MapKey,
            DescriptorSize,
            DescriptorVersion
            );
  // All parameters seem to be initialized: MdeModulePkg/Core/Dxe/Mem/Page.c
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(5);
    __msan_unpoison(MemoryMapSize, sizeof *MemoryMapSize);
    __msan_unpoison(MemoryMap, *MemoryMapSize);
    __msan_unpoison(MapKey, sizeof *MapKey);
    __msan_unpoison(DescriptorSize, sizeof *DescriptorSize);
    __msan_unpoison(DescriptorVersion, sizeof *DescriptorVersion);
  }
  return Status;
}

/////////////////////////////////////
/////  _EFI_MM_ACCESS_PROTOCOL struct
/////////////////////////////////////
EFI_STATUS __msan__EFI_MM_ACCESS_PROTOCOL_GetCapabilities(
    IN CONST EFI_MM_ACCESS_PROTOCOL  *This,
    IN OUT UINTN                       *SmramMapSize,
    IN OUT EFI_SMRAM_DESCRIPTOR        *SmramMap,
    IN EFI_MM_ACCESS_PROTOCOL *SmmAccess
) {
  EFI_STATUS Status;
  Status = SmmAccess->GetCapabilities (This, SmramMapSize, SmramMap);

  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(SmramMap, *SmramMapSize);
    __msan_unpoison(SmramMapSize, sizeof *SmramMapSize);
  }
  return Status;
}

/////////////////////////////////////
/////  _EFI_SMM_SYSTEM_TABLE2 struct
/////////////////////////////////////
EFI_STATUS __msan__EFI_SMM_SYSTEM_TABLE2_SmmRegisterProtocolNotify(
    IN  CONST EFI_GUID     *Protocol,
    IN  EFI_SMM_NOTIFY_FN  Function,
    OUT VOID               **Registration,
    IN EFI_SMM_SYSTEM_TABLE2 *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmRegisterProtocolNotify (Protocol, Function, Registration);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Registration, sizeof(*Registration));
    __msan_unpoison(*Registration, sizeof(void *));
  }
  return Status;
}

EFI_STATUS __msan__EFI_SMM_SYSTEM_TABLE2_SmmAllocatePool(
    IN  EFI_MEMORY_TYPE              PoolType,
    IN  UINTN                        Size,
    OUT VOID                         **Buffer,
    IN EFI_SMM_SYSTEM_TABLE2 *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmAllocatePool(PoolType, Size, Buffer);
  DEBUG ((DEBUG_INFO, "__msan__EFI_SMM_SYSTEM_TABLE2_SmmAllocatePool(): Buffer = %p\n", Buffer));
  DEBUG ((DEBUG_INFO, "__msan__EFI_SMM_SYSTEM_TABLE2_SmmAllocatePool(): *Buffer = %p\n", *Buffer));
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Buffer, sizeof *Buffer);
    __msan_poison(*Buffer, Size);
  }
  return Status;
}

// TODO: We don't have a size of the buffer, therefore, we have to manually
// add the poisoning I reckon.
EFI_STATUS __msan__EFI_SMM_SYSTEM_TABLE2_SmmFreePool(
    IN VOID  *Buffer,
    IN EFI_SMM_SYSTEM_TABLE2 *gSmst
) {
  return gSmst->SmmFreePool(Buffer);
}


/////////////////////////////////////
/////  DXE_SERVICES struct
/////////////////////////////////////
EFI_STATUS __msan_DXE_SERVICES_GetMemorySpaceMap(
    OUT UINTN                            *NumberOfDescriptors,
    OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR  **MemorySpaceMap,
    DXE_SERVICES *gDS
) {
  EFI_STATUS Status;
  Status = gDS->GetMemorySpaceMap(
            NumberOfDescriptors,
            MemorySpaceMap
            );
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(2);
    __msan_poison(MemorySpaceMap, sizeof *MemorySpaceMap);
    __msan_poison(*MemorySpaceMap, sizeof (EFI_GCD_MEMORY_SPACE_DESCRIPTOR) * (*NumberOfDescriptors));
    __msan_poison(NumberOfDescriptors, sizeof *NumberOfDescriptors);
  }
  return Status;
}
