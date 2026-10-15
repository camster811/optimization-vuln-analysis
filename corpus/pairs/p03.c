#include <alloca.h>
#include <stdio.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    char *destination = alloca(11 * sizeof(char));
#else
    char *destination = alloca(10 * sizeof(char));
#endif

    destination[0] = '\0';

    char source[11] = "AAAAAAAAAA";

    size_t source_length = strlen(source);
    for (size_t i = 0; i < source_length + 1; i++) {
        destination[i] = source[i];
    }
    puts(destination);
}

int main(void) {
    target();
    return 0;
}
