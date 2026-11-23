                                   
                                                                           
                                                                           
                                     
  
  
               
                                       
                                                                                    
                                                                               
             
                                               
                                                                                                              
  
     

#include "runtime.h"

#ifndef _WIN32
#include <wchar.h>
#endif

                                                                     
#define SOURCE_TEXT "AAAAAAAAAA"

#ifndef EXCLUDE_BRANCH_ALPHA

void write_buffer(char * data)
{
    {
        char source[10+1] = SOURCE_TEXT;
        size_t i, sourceLen;
        sourceLen = strlen(source);
                                                                   
                                                                           
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printLine(data);
    }
}

void process_case()
{
    char * data;
    char buffer_first[10];
    char buffer_second[10+1];
                                                                                                     
                                     
    data = buffer_first;
    data[0] = '\0';                     
    write_buffer(data);
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

void write_buffer(char * data)
{
    {
        char source[10+1] = SOURCE_TEXT;
        size_t i, sourceLen;
        sourceLen = strlen(source);
                                                                   
                                                                           
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printLine(data);
    }
}

                                                  
static void process_case()
{
    char * data;
    char buffer_first[10];
    char buffer_second[10+1];
                                                                                            
                                     
    data = buffer_second;
    data[0] = '\0';                     
    write_buffer(data);
}

void run_paths()
{
    process_case();
}

#endif               

                                                                      
                                                                        
                                                                         
                                                                   
   

#ifdef BUILD_STANDALONE

int main(int argc, char * argv[])
{
                         
    srand( (unsigned)time(NULL) );
#ifndef EXCLUDE_BRANCH_BETA
    printLine("Starting operation");
    run_paths();
    printLine("Operation finished");
#endif               
#ifndef EXCLUDE_BRANCH_ALPHA
    printLine("Starting operation");
    process_case();
    printLine("Operation finished");
#endif              
    return 0;
}

#endif
