                                   
                                                                        
                                                                            
                                     
  
  
               
                                      
                                                                             
                                                                             
               
                                                             
                                                                                                                            
  
     

#include "runtime.h"

#ifndef EXCLUDE_BRANCH_ALPHA

                                                                                    
static int flow_component_01 = 0;

static twoIntsStruct * flow_component_00(twoIntsStruct * data)
{
    if(flow_component_01)
    {
                                                                                                                     
        data = (twoIntsStruct *)malloc(50*sizeof(twoIntsStruct));
        if (data == NULL) {exit(-1);}
    }
    return data;
}

void process_case()
{
    twoIntsStruct * data;
    data = NULL;
    flow_component_01 = 1;           
    data = flow_component_00(data);
    {
        twoIntsStruct source[100];
        {
            size_t i;
                                  
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
                                                                    
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
        free(data);
    }
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                                                        
static int flow_component_03 = 0;
static int flow_component_06 = 0;

                                                                                                     
static twoIntsStruct * flow_component_02(twoIntsStruct * data)
{
    if(flow_component_03)
    {
                                                                          
        printLine("Status message");
    }
    else
    {
                                                                                                                           
        data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
        if (data == NULL) {exit(-1);}
    }
    return data;
}

static void process_case()
{
    twoIntsStruct * data;
    data = NULL;
    flow_component_03 = 0;            
    data = flow_component_02(data);
    {
        twoIntsStruct source[100];
        {
            size_t i;
                                  
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
                                                                    
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
        free(data);
    }
}

                                                                                                      
static twoIntsStruct * flow_component_05(twoIntsStruct * data)
{
    if(flow_component_06)
    {
                                                                                                                           
        data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
        if (data == NULL) {exit(-1);}
    }
    return data;
}

static void flow_component_04()
{
    twoIntsStruct * data;
    data = NULL;
    flow_component_06 = 1;           
    data = flow_component_05(data);
    {
        twoIntsStruct source[100];
        {
            size_t i;
                                  
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
                                                                    
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
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
