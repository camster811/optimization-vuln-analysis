#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    volatile char *destination = malloc(8);
    if (destination == NULL) {
        exit(-1);
    }
    for (size_t i = 0; i < 8; ++i) {
        destination[i] = 'A';
    }
#if VARIANT_FIXED
    destination[7] = '\0';
#else
    destination[8] = '\0';
#endif
    printf("%c\n", destination[0]);
    free((void *)destination);
}

int main(void) {
    target();
    return 0;
}

