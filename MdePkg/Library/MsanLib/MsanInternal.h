#include "Msan.h"

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *__msan_memcpy(void *dst, const void *src, size_t n);
