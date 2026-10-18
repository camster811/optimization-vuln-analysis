#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    volatile unsigned short destination[4] = {0};
#if VARIANT_FIXED
    size_t count = sizeof(destination) / sizeof(destination[0]);
#else
    size_t count = sizeof(destination);
#endif
    for (size_t i = 0; i < count; ++i) {
        destination[i] = (unsigned short)(i + 1);
    }
    printf("%u\n", (unsigned)destination[0]);
}

int main(void) {
    target();
    return 0;
}

