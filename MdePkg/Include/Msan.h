void __msan_poison_section(CHAR8 *DriverName, CHAR8 *SectionName, UINTN BaseAddress, UINTN Size);
void __msan_print_shadow(void *ptr, int size);
void __msan_transfer_shadow(void *dst, void *src, int size);
void __msan_unpoison_param(unsigned long long n);
void __msan_unpoison(const void *a, unsigned long long size);
