#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    char destination[16];
    memcpy(destination, "ABCDEFGH", 8);
#if VARIANT_FIXED
    memcpy(destination + 8, "12345678", 8);
#else
    memcpy(destination + 8, "12345678", 9);
#endif
    destination[15] = '\0';
    puts(destination);
}

int main(void) {
    target();
    return 0;
}

