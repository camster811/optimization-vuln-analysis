                                   
                                                                                 
                                                                           
                                     
  
  
               
                                       
                                                
                                                
                
                                                 
                                                                                                                            
  
     

#include "runtime.h"

#include <wchar.h>

#ifndef EXCLUDE_BRANCH_ALPHA

                                                                                    
static int flow_component_01 = 0;

static wchar_t * flow_component_00(wchar_t * data)
{
    if(flow_component_01)
    {
                                                                                                           
        wmemset(data, L'A', 100-1);                      
        data[100-1] = L'\0';                     
    }
    return data;
}

void process_case()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    flow_component_01 = 1;           
    data = flow_component_00(data);
    {
        wchar_t dest[50] = L"";
                                                                                  
        memmove(dest, data, wcslen(data)*sizeof(wchar_t));
        dest[50-1] = L'\0';                                                       
        printWLine(data);
    }
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                                                        
static int flow_component_03 = 0;
static int flow_component_06 = 0;

                                                                                                     
static wchar_t * flow_component_02(wchar_t * data)
{
    if(flow_component_03)
    {
                                                                          
        printLine("Status message");
    }
    else
    {
                                                                                                                    
        wmemset(data, L'A', 50-1);                      
        data[50-1] = L'\0';                     
    }
    return data;
}

static void process_case()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    flow_component_03 = 0;            
    data = flow_component_02(data);
    {
        wchar_t dest[50] = L"";
                                                                                  
        memmove(dest, data, wcslen(data)*sizeof(wchar_t));
        dest[50-1] = L'\0';                                                       
        printWLine(data);
    }
}

                                                                                                      
static wchar_t * flow_component_05(wchar_t * data)
{
    if(flow_component_06)
    {
                                                                                                                    
        wmemset(data, L'A', 50-1);                      
        data[50-1] = L'\0';                     
    }
    return data;
}

static void flow_component_04()
{
    wchar_t * data;
    wchar_t dataBuffer[100];
    data = dataBuffer;
    flow_component_06 = 1;           
    data = flow_component_05(data);
    {
        wchar_t dest[50] = L"";
                                                                                  
        memmove(dest, data, wcslen(data)*sizeof(wchar_t));
        dest[50-1] = L'\0';                                                       
        printWLine(data);
    }
}

void run_paths()
{
    process_case();
    flow_component_04();
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
