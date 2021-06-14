#include <Pi/PiSmmCis.h>
#include <Library/DebugLib.h>
#include "Asan.h"

uptr min_alignment = SHADOW_GRANULARITY;
// It should be Max(16, (int)SHADOW_GRANULARITY), but we always have
// SHADOW_GRANULARITY = 8.
uptr min_redzone =  16;
uptr max_redzone = 2048;

typedef struct ChunkHeader {
  // 1-st 8 bytes.
  u32 chunk_state       : 8;  // Must be first.
  u32 alloc_tid         : 24;

  u32 free_tid          : 24;
  u32 from_memalign     : 1;
  u32 alloc_type        : 2;
  u32 rz_log            : 3;
  u32 lsan_tag          : 2;
  // 2-nd 8 bytes
  // This field is used for small sizes. For large sizes it is equal to
  // SizeClassMap::kMaxSize and the actual size is stored in the
  // SecondaryAllocator's metadata.
  u32 user_requested_size : 29;
  // align < 8 -> 0
  // else      -> log2(min(align, 512)) - 2
  u32 user_requested_alignment_log : 3;
  u32 alloc_context_id;
} ChunkHeader;

uptr kChunkHeaderSize = sizeof (ChunkHeader);


static uptr Min(uptr a, uptr b) {
  if (a < b)
    return a;
  return b;
}

static uptr Max(uptr a, uptr b) {
  if (a < b)
    return b;
  return a;
}

// Valid redzone sizes are 16, 32, 64, ... 2048, so we encode them in 3 bits.
// We use adaptive redzones: for larger allocation larger redzones are used.
static u32 RZLog2Size(u32 rz_log) {
  return 16 << rz_log;
}

static u32 RZSize2Log(u32 rz_size) {
  ASSERT(rz_size >= 16);
  ASSERT(rz_size <= 2048);
  // - 4, since redzones start at 16 bytes.
  u32 res = Log2(rz_size) - 4;
  ASSERT(rz_size == RZLog2Size(res));
  return res; 
}

bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

uptr ComputeRZLog(uptr user_requested_size) {
  u32 rz_log =
    user_requested_size <= 64        - 16   ? 0 :
    user_requested_size <= 128       - 32   ? 1 :
    user_requested_size <= 512       - 64   ? 2 :
    user_requested_size <= 4096      - 128  ? 3 :
    user_requested_size <= (1 << 14) - 256  ? 4 :
    user_requested_size <= (1 << 15) - 512  ? 5 :
    user_requested_size <= (1 << 16) - 1024 ? 6 : 7;
  //u32 min_rz = atomic_load(&min_redzone, memory_order_acquire);
  //u32 max_rz = atomic_load(&max_redzone, memory_order_acquire);
  u32 min_rz = min_redzone;
  u32 max_rz = max_redzone;
  return Min(Max(rz_log, RZSize2Log(min_rz)), RZSize2Log(max_rz));
}

EFI_STATUS __asan_SmmAllocatePool(
    IN  EFI_MEMORY_TYPE       PoolType,
    IN  UINTN                 Size,
    OUT VOID                  **Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  EFI_STATUS Status;
  void *allocated;

  uptr alignment = 8;
  uptr rz_log = ComputeRZLog(Size);
  uptr rz_size = RZLog2Size(rz_log);
  //uptr rounded_size = RoundUpTo(Max(Size, kChunkHeader2Size), alignment);
  uptr rounded_size = RoundUpTo(Max(Size, 16), alignment);
  uptr needed_size = rounded_size + rz_size;

  if (alignment > min_alignment)
    needed_size += alignment;

  // Normally in ASan, there are automatic redzones to the right, however,
  // we do not have a customer allocator, therefore we also force the right
  // redzone to be there.
  needed_size += rz_size;

  // Allocate the pool with the added size for the redzones left and right.
  Status = gSmst->SmmAllocatePool(PoolType, needed_size, &allocated);

  if (Status != EFI_SUCCESS) {
    return Status;
  }

  // Poison the full range that we just allocated, later we unpoison the
  // user-allocated buffer.
  PoisonShadow((uptr)allocated, needed_size, kAsanHeapLeftRedzoneMagic);

  // Allocation was successful, so we can add the metadata in the left redzone.
  uptr alloc_beg = (uptr)allocated;
  uptr alloc_end = alloc_beg + needed_size;
  uptr beg_plus_redzone = alloc_beg + rz_size;
  uptr user_beg = beg_plus_redzone;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + Size;
  ASSERT(user_end <= alloc_end);
  uptr chunk_beg = user_beg - kChunkHeaderSize;

  // Fill in the metadata ASan uses for the allocated blocks.
  ChunkHeader *m = (ChunkHeader *)chunk_beg;
  // m->alloc_type = alloc_type;
  m->rz_log = rz_log;
  m->user_requested_size = Size;
  // u32 alloc_tid = t ? t->tid() : 0;
  // m->alloc_tid = alloc_tid;
  // CHECK_EQ(alloc_tid, m->alloc_tid);  // Does alloc_tid fit into the bitfield?
  // m->free_tid = kInvalidTid;
  m->from_memalign = user_beg != beg_plus_redzone;

/*
  if (alloc_beg != chunk_beg) {
    reinterpret_cast<uptr *>(alloc_beg)[0] = kAllocBegMagic;
    reinterpret_cast<uptr *>(alloc_beg)[1] = chunk_beg;
  }
  m->user_requested_alignment_log = user_requested_alignment_log;

  m->alloc_context_id = StackDepotPut(*stack);
*/

  uptr size_rounded_down_to_granularity =
      RoundDownTo(Size, SHADOW_GRANULARITY);
  // Unpoison the bulk of the memory region.
  if (size_rounded_down_to_granularity)
    PoisonShadow(user_beg, size_rounded_down_to_granularity, 0);
  // Deal with the end of the region if size is not aligned to granularity.
  if (Size != size_rounded_down_to_granularity && CanPoisonMemory()) {
    u8 *shadow =
        (u8 *)MemToShadow(user_beg + size_rounded_down_to_granularity);
    //*shadow = fl.poison_partial ? (Size & (SHADOW_GRANULARITY - 1)) : 0;
    *shadow = (Size & (SHADOW_GRANULARITY - 1));
  }

/*
  AsanStats &thread_stats = GetCurrentThreadStats();
  thread_stats.mallocs++;
  thread_stats.malloced += size;
  thread_stats.malloced_redzones += needed_size - size;
  if (needed_size > SizeClassMap::kMaxSize)
    thread_stats.malloc_large++;
  else
    thread_stats.malloced_by_size[SizeClassMap::ClassID(needed_size)]++;

  void *res = (void *)user_beg;

  if (can_fill && fl.max_malloc_fill_size) {
    uptr fill_size = Min(size, (uptr)fl.max_malloc_fill_size);
    REAL(memset)(res, fl.malloc_fill_byte, fill_size);
  }
  // Must be the last mutation of metadata in this function.
  atomic_store((atomic_uint8_t *)m, CHUNK_ALLOCATED, memory_order_release);
  ASAN_MALLOC_HOOK(res, Size);
*/
  *Buffer = (void *)user_beg;
  return EFI_SUCCESS;
}

EFI_STATUS __asan_SmmFreePool(
    IN VOID                   *Buffer,
    IN EFI_SMM_SYSTEM_TABLE2  *gSmst
) {
  uptr p = (uptr)Buffer;
  ASSERT(AddrIsInMem(p));
  uptr chunk_beg = (uptr)Buffer - kChunkHeaderSize;
  ChunkHeader *m = (ChunkHeader *)(chunk_beg);

  // The original pointer that should be freed is the address of the left redzone.
  uptr original_ptr = p - RZLog2Size(m->rz_log);

  // Poison the region, we only unpoison the user requested size of bytes.
  PoisonShadow(p,
         RoundUpTo(m->user_requested_size, SHADOW_GRANULARITY),
         kAsanHeapFreeMagic);
  return gSmst->SmmFreePool((void *)original_ptr);
}
