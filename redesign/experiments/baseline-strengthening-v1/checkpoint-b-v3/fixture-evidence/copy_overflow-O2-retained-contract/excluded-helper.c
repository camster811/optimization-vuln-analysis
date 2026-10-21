#include <stdlib.h>
#include <string.h>
#include <wchar.h>
void apply(char*p){wcscpy((wchar_t*)p,L"AB\0");}
