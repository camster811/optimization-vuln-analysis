#include <stdlib.h>
#include <string.h>
#include <wchar.h>
extern void apply(char*);
int main(void){char*p=malloc(6);if(!p)return 1;strcpy(p,"hi\0paddingpadding");apply(p);free(p);return 0;}
