#include <stdio.h>
#include <string.h>

#ifndef VARIANT_FIXED
#error "VARIANT_FIXED must be defined as 0 or 1"
#endif

__attribute__((noinline, noclone, used))
void copy_message(void) {
#if VARIANT_FIXED
    char destination[11];
#else
    char destination[10];
#endif

    strcpy(destination, "AAAAAAAAAA");
    puts(destination);
}

int main(void) {
    copy_message();
    return 0;
}
