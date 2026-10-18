#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    char *first = malloc(8);
    char *second = malloc(16);
    if (first == NULL || second == NULL) {
        exit(-1);
    }
#if VARIANT_FIXED
    char *destination = second;
#else
    char *destination = first;
#endif
    memcpy(destination, "ABCDEFGHIJK", 12);
    puts(destination);
    free(second);
    free(first);
}

int main(void) {
    target();
    return 0;
}

