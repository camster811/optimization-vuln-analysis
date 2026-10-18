#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    volatile unsigned char *destination = malloc(8);
    if (destination == NULL) {
        exit(-1);
    }
#if VARIANT_FIXED
    for (size_t i = 0; i < 4; ++i) {
#else
    for (size_t i = 0; i <= 4; ++i) {
#endif
        destination[2 * i] = (unsigned char)(i + 1);
    }
    printf("%u\n", (unsigned)destination[0]);
    free((void *)destination);
}

int main(void) {
    target();
    return 0;
}

