                                   
                                                                      
                                                                                   
                                     
  
  
               
                                      
                                                                             
                                                                             
               
                                                
                                                                                                                            
  
     

#include "runtime.h"

#include <wchar.h>

#ifndef EXCLUDE_BRANCH_ALPHA

                                                                                    
static int flow_component_01 = 0;

static char * flow_component_00(char * data)
{
    if(flow_component_01)
    {
                                                                                                                     
        data = (char *)malloc(50*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0';                     
    }
    return data;
}

void process_case()
{
    char * data;
    data = NULL;
    flow_component_01 = 1;           
    data = flow_component_00(data);
    {
        char source[100];
        memset(source, 'C', 100-1);                     
        source[100-1] = '\0';                     
                                                                                    
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0';                                                       
        printLine(data);
        free(data);
    }
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                                                        
static int flow_component_03 = 0;
static int flow_component_06 = 0;

                                                                                                     
static char * flow_component_02(char * data)
{
    if(flow_component_03)
    {
                                                                          
        printLine("Status message");
    }
    else
    {
                                                                                                                           
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0';                     
    }
    return data;
}

static void process_case()
{
    char * data;
    data = NULL;
    flow_component_03 = 0;            
    data = flow_component_02(data);
    {
        char source[100];
        memset(source, 'C', 100-1);                     
        source[100-1] = '\0';                     
                                                                                    
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0';                                                       
        printLine(data);
        free(data);
    }
}

                                                                                                      
static char * flow_component_05(char * data)
{
    if(flow_component_06)
    {
                                                                                                                           
        data = (char *)malloc(100*sizeof(char));
        if (data == NULL) {exit(-1);}
        data[0] = '\0';                     
    }
    return data;
}

static void flow_component_04()
{
    char * data;
    data = NULL;
    flow_component_06 = 1;           
    data = flow_component_05(data);
    {
        char source[100];
        memset(source, 'C', 100-1);                     
        source[100-1] = '\0';                     
                                                                                    
        memcpy(data, source, 100*sizeof(char));
        data[100-1] = '\0';                                                       
        printLine(data);
        free(data);
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
