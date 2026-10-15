#include <stdio.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    char destination[11];
#else
    char destination[10];
#endif

    destination[0] = '\0';

    char source[11] = "AAAAAAAAAA";

    strncpy(destination, source, strlen(source) + 1);
    puts(destination);
}

int main(void) {
    target();
    return 0;
}
