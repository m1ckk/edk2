#include "Asan.h"
#include "AsanFakeStack.h"
#include "AsanPoisoning.h"

FakeStack __asan_fs;

// Given an index and class ID, return a pointer to Nth FakeFrame that belongs
// to the given class ID. The corresponding FakeStack is computed by adding
// the base address (FAKE_STACK_START) to the ID multiplied by the size of a 
// single FakeStack size (FAKE_STACK_SIZE * id), then find the corresponding
// FakeFrame, by computing the size of a single FakeFrame and multiplying that
// with the given index ((64 << id) * index).
#define GET_FRAME(index, id) (FakeFrame *)(FAKE_STACK_START + \
    (FAKE_STACK_SIZE * id) + (64 << id) * index)

void initFakeStack(void) {
    for (int i = 0; i < NR_FAKE_STACKS; i++) {
        __asan_fs.IndexFakeFrame[i] = 0;
        __asan_fs.NrFakeFrames[i] = FAKE_STACK_SIZE / (64 << i);
        __asan_fs.FakeFrames[i] = (FakeFrame *)(FAKE_STACK_START + 
            i * FAKE_STACK_SIZE);
        // Zero out the memory, so all flags are 0.
        _memset((void *)FAKE_STACK_START, 0, FAKE_STACK_SIZE * NR_FAKE_STACKS);
/*
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.IndexFakeFrame[%d] =  %d\n", i, __asan_fs.IndexFakeFrame[i]));
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.NrFakeFrames[%d] =    %d\n", i, __asan_fs.NrFakeFrames[i]));
        DEBUG ((DEBUG_INFO, "init_fake_stack(): __asan_fs.FakeFrames[%d] =      %p\n", i, __asan_fs.FakeFrames[i]));
*/
    }
}

static FakeFrame *allocFakeFrame(UINTN class_id) {
    __asan_in_runtime = 1;
    FakeFrame *ff;
    int nr_fake_frames = __asan_fs.NrFakeFrames[class_id];
    // We start with the saved index, which is the index after the most 
    // recently allocated frame, to delay reusing the frame that was just
    // deallocated.
    int index = __asan_fs.IndexFakeFrame[class_id];
    int i = 0;
/*
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): class_id =       %lu\n", class_id));
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): nr_fake_frames = %lu\n", nr_fake_frames));
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): index =          %d\n", index));
*/
    while (i < nr_fake_frames) {
        ff = GET_FRAME(index, class_id);
/*
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff =         %p\n", ff));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff->flags =  %x\n", ff->flags));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): ff->magic =  %p\n", ff->magic));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): index =      %d\n", index));
        DEBUG ((DEBUG_INFO, "allocFakeFrame(): i =          %d\n", i));
*/
        // Allocate the frame if it is inactive.
        if (!ff->flags) {
            ff->flags = 1;
            // That way we begin looking for new frames after the most recently
            // allocated frame.
            __asan_fs.IndexFakeFrame[class_id] = (index + 1) % nr_fake_frames;
            FastPoisonShadow((UINTN)ff, 64 << class_id, 0);
            __asan_in_runtime = 0;
            return ff;
        }
        i++;
        index = (index + 1) % nr_fake_frames;
    }
    // No FakeFrames left for class_id
    DEBUG ((DEBUG_INFO, "allocFakeFrame(): ERROR\n"));
    __asan_in_runtime = 0;
    asm volatile("hlt");
    return NULL;
}

static void freeFakeFrame(UINTN ptr, UINTN class_id) {
    ASSERT ((UINTN)__asan_fs.FakeFrames[class_id] <= ptr);
    ASSERT (ptr < (UINTN)(__asan_fs.FakeFrames[class_id] + FAKE_STACK_SIZE));

    FakeFrame *ff = (FakeFrame *)ptr;
/*
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): ff =         %p\n", ff));
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): class_id =   %lu\n", class_id));
    DEBUG ((DEBUG_INFO, "freeFakeFrame(): ptr =        %p\n", ptr));
*/
    ff->flags = 0;
    FastPoisonShadow((UINTN)ff, 64 << class_id, kAsanStackAfterReturnMagic);
}


#define DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(class_id)                    \
void *__asan_stack_malloc_##class_id(uptr size) {                           \
    return allocFakeFrame(class_id);                                        \
}                                                                           \
void __asan_stack_free_##class_id(uptr ptr, uptr size) {                    \
    freeFakeFrame(ptr, class_id);                                           \
}

DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(0);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(1);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(2);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(3);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(4);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(5);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(6);
DEFINE_STACK_MALLOC_FREE_WITH_CLASS_ID(7);
