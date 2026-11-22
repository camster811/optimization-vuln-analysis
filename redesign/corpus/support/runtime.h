#ifndef RUNTIME_SUPPORT_H
#define RUNTIME_SUPPORT_H

                                
                                                       
                                                             
                                                                                
                                    
  
                                                                                
                                  
   

#ifdef _WIN32
                                                           
                                                          
   
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_SECURE_NO_WARNING 1

                                                                             
                                                                              
                                                                           
                   
#define ALLOCA _alloca

                                                                       
                                                                     
#pragma warning(disable:4996)

#else
                                                                                    
# define __STDC_LIMIT_MACROS 1

#define ALLOCA alloca
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#ifndef _WIN32
                                                       
# include <stdint.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>                         
#endif

#ifdef __cplusplus
#include <new>                     

                                                      
class TwoIntsClass 
{
    public:                                               
        int intOne;
        int intTwo;
};

class OneIntClass 
{
    public:                                               
        int intOne;
};

#endif

#ifndef __cplusplus
                                                                    
#define true 1
#define false 0

#endif                             

                                                                                                                       
                                                         
#define URAND31() (((unsigned)rand()<<30) ^ ((unsigned)rand()<<15) ^ rand())
                                                                                                  
#define RAND32() ((int)(rand() & 1 ? URAND31() : -URAND31() - 1))

                                                                                                                       
                                                         
#define URAND63() (((uint64_t)rand()<<60) ^ ((uint64_t)rand()<<45) ^ ((uint64_t)rand()<<30) ^ ((uint64_t)rand()<<15) ^ rand())
                                                                                                  
#define RAND64() ((int64_t)(rand() & 1 ? URAND63() : -URAND63() - 1))

                                                     
typedef struct _twoIntsStruct
{
    int intOne;
    int intTwo;
} twoIntsStruct;

#ifdef __cplusplus
extern "C" {
#endif

                                                             
                                                                    
                         
extern const int GLOBAL_CONST_TRUE;           
extern const int GLOBAL_CONST_FALSE;            
extern const int GLOBAL_CONST_FIVE;        

                                                                
                                                                      
                                                                 
extern int globalTrue;           
extern int globalFalse;            
extern int globalFive;        

#ifdef __cplusplus
}
#endif

#include "output.h"

#endif
