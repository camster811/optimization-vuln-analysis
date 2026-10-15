#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    char *destination = malloc(11 * sizeof(char));
#else
    char *destination = malloc(10 * sizeof(char));
#endif

    if (destination == NULL) {
        exit(-1);
    }

    {
        char *destination_copy = destination;
        char *destination = destination_copy;

        char source[11] = "AAAAAAAAAA";

        strncpy(destination, source, strlen(source) + 1);
        puts(destination);
        free(destination);
    }
}

int main(void) {
    target();
    return 0;
}
