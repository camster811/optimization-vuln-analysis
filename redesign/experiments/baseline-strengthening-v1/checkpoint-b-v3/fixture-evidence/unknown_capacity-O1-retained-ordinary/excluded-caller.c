#include <stdlib.h>
#include <string.h>
#include <wchar.h>
extern void apply(char*);
int main(void){char*p=malloc(16);if(!p)return 1;apply(p);free(p);return 0;}
