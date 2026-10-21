#include <stdlib.h>
#include <string.h>
#include <wchar.h>
extern void apply(char*);int main(void){struct{wchar_t buffer[2];volatile int marker;} s;s.marker=1;apply((char*)s.buffer);return s.marker;}
