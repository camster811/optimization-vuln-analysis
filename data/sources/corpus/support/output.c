#include <inttypes.h>              
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>
#include "runtime.h"

#ifndef _WIN32
#include <wchar.h>
#endif

void printLine (const char * line)
{
    if(line != NULL) 
    {
        printf("%s\n", line);
    }
}

void printWLine (const wchar_t * line)
{
    if(line != NULL) 
    {
        wprintf(L"%ls\n", line);
    }
}

void printIntLine (int intNumber)
{
    printf("%d\n", intNumber);
}

void printShortLine (short shortNumber)
{
    printf("%hd\n", shortNumber);
}

void printFloatLine (float floatNumber)
{
    printf("%f\n", floatNumber);
}

void printLongLine (long longNumber)
{
    printf("%ld\n", longNumber);
}

void printLongLongLine (int64_t longLongIntNumber)
{
    printf("%" PRId64 "\n", longLongIntNumber);
}

void printSizeTLine (size_t sizeTNumber)
{
    printf("%zu\n", sizeTNumber);
}

void printHexCharLine (char charHex)
{
    printf("%02x\n", charHex);
}

void printWcharLine(wchar_t wideChar) 
{
                                                                                  
                                 
    wchar_t s[2];
        s[0] = wideChar;
        s[1] = L'\0';
    printf("%ls\n", s);
}

void printUnsignedLine(unsigned unsignedNumber) 
{
    printf("%u\n", unsignedNumber);
}

void printHexUnsignedCharLine(unsigned char unsignedCharacter) 
{
    printf("%02x\n", unsignedCharacter);
}

void printDoubleLine(double doubleNumber) 
{
    printf("%g\n", doubleNumber);
}

void printStructLine (const twoIntsStruct * structTwoIntsStruct)
{
    printf("%d -- %d\n", structTwoIntsStruct->intOne, structTwoIntsStruct->intTwo);
}

void printBytesLine(const unsigned char * bytes, size_t numBytes)
{
    size_t i;
    for (i = 0; i < numBytes; ++i)
    {
        printf("%02x", bytes[i]);
    }
    puts("");	                    
}

                                                                               
                                                                            
                                                        
size_t decodeHexChars(unsigned char * bytes, size_t numBytes, const char * hex)
{
    size_t numWritten = 0;

                                                                                        
                                                                                       
                                                                                    
                                                                  
    while (numWritten < numBytes && isxdigit(hex[2 * numWritten]) && isxdigit(hex[2 * numWritten + 1]))
    {
        int byte;
        sscanf(&hex[2 * numWritten], "%02x", &byte);
        bytes[numWritten] = (unsigned char) byte;
        ++numWritten;
    }

    return numWritten;
}

                                                                               
                                                                            
                                                        
 size_t decodeHexWChars(unsigned char * bytes, size_t numBytes, const wchar_t * hex)
 {
    size_t numWritten = 0;

                                                                                         
                                                                                       
                                                                                     
                                                                  
    while (numWritten < numBytes && iswxdigit(hex[2 * numWritten]) && iswxdigit(hex[2 * numWritten + 1]))
    {
        int byte;
        swscanf(&hex[2 * numWritten], L"%02x", &byte);
        bytes[numWritten] = (unsigned char) byte;
        ++numWritten;
    }

    return numWritten;
}

                                                                       
                                                                           
int globalReturnsTrue() 
{
    return 1;
}

int globalReturnsFalse() 
{
    return 0;
}

int globalReturnsTrueOrFalse() 
{
    return (rand() % 2);
}

                                                             
                                                                    
                         
const int GLOBAL_CONST_TRUE = 1;           
const int GLOBAL_CONST_FALSE = 0;            
const int GLOBAL_CONST_FIVE = 5; 

                                                                
                                                                      
                                                                 
int globalTrue = 1;           
int globalFalse = 0;            
int globalFive = 5; 

                                                                            
                                                                 
void unused_hook_10() { }
void unused_hook_11() { }
void unused_hook_12() { }
void unused_hook_13() { }
void unused_hook_14() { }
void unused_hook_15() { }
void unused_hook_16() { }
void unused_hook_17() { }
void unused_hook_18() { }

                                         
void unused_hook_01() { }
void unused_hook_02() { }
void unused_hook_03() { }
void unused_hook_04() { }
void unused_hook_05() { }
void unused_hook_06() { }
void unused_hook_07() { }
void unused_hook_08() { }
void unused_hook_09() { }

                                 

#ifdef __cplusplus
extern "C" {
#endif

int globalArgc = 0;
char** globalArgv = NULL;

#ifdef __cplusplus
}
#endif
