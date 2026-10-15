#include <stdio.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    char destination[100];
#else
    char destination[50];
#endif

    destination[0] = '\0';

    char source[100];
    memset(source, 'C', 100 - 1);
    source[100 - 1] = '\0';

    strncat(destination, source, 100);
    puts(destination);
}

int main(void) {
    target();
    return 0;
}
