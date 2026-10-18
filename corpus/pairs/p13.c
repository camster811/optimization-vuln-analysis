#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    char destination[16] = "ABCD";
#if VARIANT_FIXED
    memcpy(destination + 4, "abcdefghijkl", 12);
#else
    memcpy(destination + 4, "abcdefghijkl", 13);
#endif
    destination[15] = '\0';
    puts(destination);
}

int main(void) {
    target();
    return 0;
}

