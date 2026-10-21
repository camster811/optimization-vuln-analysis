                                   
                                                                             
                                                                           
                                     
  
  
               
                                       
                                                
                                                
               
                                                
                            
  
     

#include "runtime.h"

#include <wchar.h>

#ifndef EXCLUDE_BRANCH_ALPHA

void process_case()
{
    char * data;
    char dataBuffer[100];
    data = dataBuffer;
                                                                                                       
    memset(data, 'A', 100-1);                     
    data[100-1] = '\0';                     
    {
        char dest[50] = "";
                                                                                  
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0';                                                       
        printLine(data);
    }
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                  
static void process_case()
{
    char * data;
    char dataBuffer[100];
    data = dataBuffer;
                                                                                                                
    memset(data, 'A', 50-1);                     
    data[50-1] = '\0';                     
    {
        char dest[50] = "";
                                                                                  
        memcpy(dest, data, strlen(data)*sizeof(char));
        dest[50-1] = '\0';                                                       
        printLine(data);
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
