#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void target(void) {
    volatile unsigned char destination[8] = {0};
#if VARIANT_FIXED
    for (int i = 7; i >= 0; --i) {
#else
    for (int i = 7; i >= -1; --i) {
#endif
        destination[i] = (unsigned char)(i + 2);
    }
    char output[2] = {(char)('0' + destination[0]), '\0'};
    puts(output);
}

int main(void) {
    target();
    return 0;
}

