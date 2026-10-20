                                   
                                                                          
                                                                                   
                                     
  
  
               
                                      
                                                                             
                                                                             
                
                                                 
                            
  
     

#include "runtime.h"

#include <wchar.h>

#ifndef EXCLUDE_BRANCH_ALPHA

void process_case()
{
    wchar_t * data;
    data = NULL;
                                                                                                                 
    data = (wchar_t *)malloc(50*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';                     
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1);                      
        source[100-1] = L'\0';                     
                                                                                    
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0';                                                       
        printWLine(data);
        free(data);
    }
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                  
static void process_case()
{
    wchar_t * data;
    data = NULL;
                                                                                                                       
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';                     
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1);                      
        source[100-1] = L'\0';                     
                                                                                    
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0';                                                       
        printWLine(data);
        free(data);
    }
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
