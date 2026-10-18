#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    volatile unsigned int *destination = calloc(4, sizeof(*destination));
#else
    volatile unsigned int *destination = calloc(4, 1);
#endif
    if (destination == NULL) {
        exit(-1);
    }
    for (size_t i = 0; i < 4; ++i) {
        destination[i] = (unsigned int)(i + 1);
    }
    printf("%u\n", destination[0]);
    free((void *)destination);
}

int main(void) {
    target();
    return 0;
}

