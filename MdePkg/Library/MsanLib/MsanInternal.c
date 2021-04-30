#include "Msan.h"

void *memset(void *s, int c, size_t n)
{
  unsigned char *d;

  d = s;

  while (n-- != 0) {
    *d++ = (unsigned char)c;
  }

  return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
  unsigned char *d;
  unsigned char const *s;

  d = dest;
  s = src;

  while (n-- != 0) {
    *d++ = *s++;
  }

  return dest;
}

void *__msan_memcpy(void *dst, const void *src, size_t n) {
  void *res = memcpy(dst, src, n);
  memcpy((void *)MEM_TO_SHADOW((UINTN)dst),
    (void *)MEM_TO_SHADOW((UINTN)src), n);

  return res;
}


