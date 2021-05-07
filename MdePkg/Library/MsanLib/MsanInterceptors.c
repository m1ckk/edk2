#include <Library/DebugLib.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/MmBase.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/FaultTolerantWrite.h>
#include <Protocol/Pcd.h>
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
    IN  EFI_GUID          *Protocol,
    IN  VOID              *Registration, OPTIONAL
    OUT VOID              **Interface,
    IN  EFI_BOOT_SERVICES *gBS
) {
  EFI_STATUS Status;
  Status = gBS->LocateProtocol(Protocol, Registration, Interface);
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
    IN VOID               *Buffer,
    IN  EFI_BOOT_SERVICES *gBS
  ) {
  gBS->FreePool(Buffer);
}

// This function is to free memory outside of SMRAM, therefore, we shouldn't
// perform any shadow propagation for now.
EFI_STATUS __msan_EFI_BOOT_SERVICES_AllocatePool(
    IN EFI_MEMORY_TYPE    PoolType,
    IN UINTN              Size,
    OUT VOID              **Buffer,
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

EFI_STATUS __msan_EFI_BOOT_SERVICES_InstallProtocolInterface(
    IN OUT EFI_HANDLE     *UserHandle,
    IN EFI_GUID           *Protocol,
    IN EFI_INTERFACE_TYPE InterfaceType,
    IN VOID               *Interface,
    IN  EFI_BOOT_SERVICES *gBS
) {
  EFI_STATUS Status;
  Status = gBS->InstallProtocolInterface(
            UserHandle,
            Protocol,
            InterfaceType,
            Interface
  );
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(5);
    __msan_unpoison(UserHandle, sizeof *UserHandle);
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
    IN CONST EFI_MM_ACCESS_PROTOCOL *This,
    IN OUT UINTN                    *SmramMapSize,
    IN OUT EFI_SMRAM_DESCRIPTOR     *SmramMap,
    IN EFI_MM_ACCESS_PROTOCOL       *SmmAccess
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
    IN  CONST EFI_GUID        *Protocol,
    IN  EFI_SMM_NOTIFY_FN     Function,
    OUT VOID                  **Registration,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
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
    IN  EFI_MEMORY_TYPE       PoolType,
    IN  UINTN                 Size,
    OUT VOID                  **Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->SmmAllocatePool(PoolType, Size, Buffer);
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
    IN VOID                   *Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  return gSmst->SmmFreePool(Buffer);
}

/////////////////////////////////////
/////  _EFI_SMM_BASE2_PROTOCOL struct
/////////////////////////////////////

EFI_STATUS __msan__EFI_SMM_BASE2_PROTOCOL_GetSmstLocation(
    IN CONST EFI_SMM_BASE2_PROTOCOL *This,
    OUT      EFI_SMM_SYSTEM_TABLE2  **Smst,
    IN EFI_SMM_BASE2_PROTOCOL       *mSmmBase2
) {
  EFI_STATUS Status;
  Status = mSmmBase2->GetSmstLocation(This, Smst);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Smst, sizeof *Smst);
    __msan_unpoison(*Smst, sizeof **Smst);
  }
  return Status;
}

/////////////////////////////////////
/////  _EFI_MM_BASE_PROTOCOL struct
/////////////////////////////////////

EFI_STATUS __msan__EFI_MM_BASE_PROTOCOL_GetMmstLocation(
    IN CONST EFI_MM_BASE_PROTOCOL *This,
    IN OUT EFI_MM_SYSTEM_TABLE    **Mmst,
    IN EFI_MM_BASE_PROTOCOL       *mMmBase
) {
  EFI_STATUS Status;
  Status = mMmBase->GetMmstLocation(This, Mmst);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Mmst, sizeof *Mmst);
    __msan_unpoison(*Mmst, sizeof **Mmst);
  }
  return Status;
}

/////////////////////////////////////
/////  DXE_SERVICES struct
/////////////////////////////////////
EFI_STATUS __msan_DXE_SERVICES_GetMemorySpaceMap(
    OUT UINTN                           *NumberOfDescriptors,
    OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR **MemorySpaceMap,
    DXE_SERVICES                        *gDS
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

/////////////////////////////////////
/////  _EFI_MM_SYSTEM_TABLE struct
/////////////////////////////////////
EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmInstallProtocolInterface(
    IN OUT EFI_HANDLE       *UserHandle,
    IN EFI_GUID             *Protocol,
    IN EFI_INTERFACE_TYPE   InterfaceType,
    IN VOID                 *Interface,
    IN EFI_MM_SYSTEM_TABLE  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmInstallProtocolInterface(
                    UserHandle,
                    Protocol,
                    InterfaceType,
                    Interface
  );
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(5);
    __msan_unpoison(UserHandle, sizeof *UserHandle);
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmAllocatePool(
    IN EFI_MEMORY_TYPE      PoolType,
    IN UINTN                Size,
    OUT VOID                **Buffer,
    IN EFI_MM_SYSTEM_TABLE  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmAllocatePool(
                    PoolType,
                    Size,
                    Buffer
  );
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(Buffer, sizeof *Buffer);
    __msan_unpoison(*Buffer, Size);
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmiHandlerRegister(
    IN  EFI_MM_HANDLER_ENTRY_POINT  Handler,
    IN  CONST EFI_GUID              *HandlerType  OPTIONAL,
    OUT EFI_HANDLE                  *DispatchHandle,
    IN EFI_MM_SYSTEM_TABLE          *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmiHandlerRegister(Handler, HandlerType, DispatchHandle);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(DispatchHandle, sizeof *DispatchHandle);
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmRegisterProtocolNotify(
    IN  CONST EFI_GUID      *Protocol,
    IN  EFI_MM_NOTIFY_FN    Function,
    OUT VOID                **Registration,
    IN EFI_MM_SYSTEM_TABLE  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmRegisterProtocolNotify(Protocol, Function, Registration);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(Registration, sizeof *Registration);
    __msan_unpoison(*Registration, sizeof(void *));
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmLocateProtocol(
    IN  EFI_GUID            *Protocol,
    IN  VOID                *Registration OPTIONAL,
    OUT VOID                **Interface,
    IN EFI_MM_SYSTEM_TABLE  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmLocateProtocol(Protocol, Registration, Interface);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(Interface, sizeof *Interface);
    __msan_unpoison(*Interface, sizeof(void *));
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmLocateHandle(
    IN     EFI_LOCATE_SEARCH_TYPE SearchType,
    IN     EFI_GUID               *Protocol   OPTIONAL,
    IN     VOID                   *SearchKey  OPTIONAL,
    IN OUT UINTN                  *BufferSize,
    OUT    EFI_HANDLE             *Buffer,
    IN EFI_MM_SYSTEM_TABLE        *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmLocateHandle(
                  SearchType,
                  Protocol,
                  SearchKey,
                  BufferSize,
                  Buffer
  );
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(6);
    __msan_unpoison(Buffer, *BufferSize);
  }
  return Status;
}

EFI_STATUS __msan__EFI_MM_SYSTEM_TABLE_MmHandleProtocol (
    IN  EFI_HANDLE          UserHandle,
    IN  EFI_GUID            *Protocol,
    OUT VOID                **Interface,
    IN EFI_MM_SYSTEM_TABLE  *gSmst
) {
  EFI_STATUS Status;
  Status = gSmst->MmHandleProtocol(UserHandle, Protocol, Interface);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(Interface, sizeof *Interface);
    __msan_unpoison(Interface, sizeof(void *));
  }
  return Status;
}

/////////////////////////////////////
/////  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL struct
/////////////////////////////////////

EFI_STATUS __msan__EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL_GetAttributes(
    IN CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
    OUT EFI_FVB_ATTRIBUTES_2                    *Attributes,
    IN EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL       *Fvb
) {
  EFI_STATUS Status;
  Status = Fvb->GetAttributes(This, Attributes);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(Attributes, sizeof *Attributes);
  }
  return Status;
}

EFI_STATUS __msan__EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL_GetBlockSize(
    IN CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
    IN CONST EFI_LBA                            Lba,
    OUT UINTN                                   *BlockSize,
    OUT UINTN                                   *NumOfBlocks,
    IN EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL       *Fvb
) {
  EFI_STATUS Status;
  Status = Fvb->GetBlockSize(This, Lba, BlockSize, NumOfBlocks);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(5);
    __msan_unpoison(BlockSize, sizeof *BlockSize);
    __msan_unpoison(NumOfBlocks, sizeof *NumOfBlocks);
  }
  return Status;
}

EFI_STATUS __msan__EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL_Write(
    IN CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
    IN       EFI_LBA                            Lba,
    IN       UINTN                              Offset,
    IN OUT   UINTN                              *NumBytes,
    IN       UINT8                              *Buffer,
    IN EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL       *Fvb
) {
  EFI_STATUS Status;
  Status = Fvb->Write(This, Lba, Offset, NumBytes, Buffer);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(6);
    __msan_unpoison(NumBytes, sizeof *NumBytes);
  }
  return Status;
}

EFI_STATUS __msan__EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL_GetPhysicalAddress(
    IN CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *This,
    OUT EFI_PHYSICAL_ADDRESS                    *Address,
    IN EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL       *Fvb
) {
  EFI_STATUS Status;
  Status = Fvb->GetPhysicalAddress(This, Address);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(4);
    __msan_unpoison(Address, sizeof *Address);
  }
  return Status;
}

/////////////////////////////////////
/////  EFI_FAULT_TOLERANT_WRITE_PROTOCOL struct
/////////////////////////////////////

EFI_STATUS __msan__EFI_FAULT_TOLERANT_WRITE_PROTOCOL_GetMaxBlockSize(
  IN EFI_FAULT_TOLERANT_WRITE_PROTOCOL  *This,
  OUT UINTN                             *BlockSize,
  IN EFI_FAULT_TOLERANT_WRITE_PROTOCOL  *Ftw
) {
  EFI_STATUS Status;
  Status = Ftw->GetMaxBlockSize(This, BlockSize);
  if (Status == EFI_SUCCESS) {
    __msan_unpoison_param(3);
    __msan_unpoison(BlockSize, sizeof *BlockSize);
  }
  return Status;
}

EFI_STATUS __msan__EFI_FAULT_TOLERANT_WRITE_PROTOCOL_Write(
  IN EFI_FAULT_TOLERANT_WRITE_PROTOCOL  *This,
  IN EFI_LBA                            Lba,
  IN UINTN                              Offset,
  IN UINTN                              Length,
  IN VOID                               *PrivateData,
  IN EFI_HANDLE                         FvBlockHandle,
  IN VOID                               *Buffer,
  IN EFI_FAULT_TOLERANT_WRITE_PROTOCOL  *Ftw
) {
  // Nothing to do, see MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteSmmDxe.c
  return Ftw->Write(This, Lba, Offset, Length, PrivateData, FvBlockHandle, Buffer);
}

/////////////////////////////////////
/////  EFI_FAULT_TOLERANT_WRITE_PROTOCOL struct
/////////////////////////////////////

UINT16 __msan_PCD_PROTOCOL_Get16(
  IN UINTN        TokenNumber,
  IN PCD_PROTOCOL *mPcd
) {
  return mPcd->Get16(TokenNumber);
}
