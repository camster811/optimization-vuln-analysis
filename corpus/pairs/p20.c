#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    char *destination = malloc(12);
    if (destination == NULL) {
        exit(-1);
    }
    memcpy(destination, "ABCDEFGHIJK", 12);
#if VARIANT_FIXED
    memmove(destination + 2, destination, 10);
#else
    memmove(destination + 2, destination, 12);
#endif
    destination[11] = '\0';
    puts(destination);
    free(destination);
}

int main(void) {
    target();
    return 0;
}

