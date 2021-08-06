#ifndef __ASAN_ALLOC_H__
#define __ASAN_ALLOC_H__

#include <Pi/PiSmmCis.h>

EFI_STATUS __asan_SmmAllocatePool(
    IN  EFI_MEMORY_TYPE       PoolType,
    IN  UINTN                 Size,
    OUT VOID                  **Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
);

EFI_STATUS __asan_SmmFreePool(
    IN VOID                   *Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
);

#endif
