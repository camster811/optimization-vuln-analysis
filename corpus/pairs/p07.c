#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
#if VARIANT_FIXED
    char *destination = malloc(100 * sizeof(char));
#else
    char *destination = malloc(50 * sizeof(char));
#endif

    if (destination == NULL) {
        exit(-1);
    }

    destination[0] = '\0';

    char source[100];
    memset(source, 'C', 100 - 1);
    source[100 - 1] = '\0';

    strcpy(destination, source);
    puts(destination);
    free(destination);
}

int main(void) {
    target();
    return 0;
}
