#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    volatile unsigned char destination[8] = {0};
    size_t index = 8;
#if VARIANT_FIXED
    if (index >= sizeof(destination)) {
#else
    if (index > sizeof(destination)) {
#endif
        index = sizeof(destination) - 1;
    }
    destination[index] = 42;
    char output[2] = {(char)('0' + destination[0]), '\0'};
    puts(output);
}

int main(void) {
    target();
    return 0;
}

