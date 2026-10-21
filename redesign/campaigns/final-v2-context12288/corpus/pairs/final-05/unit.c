                                   
                                                               
                                                                           
                                      
  
  
               
                                       
                                                               
                                                
         
                                               
                                                                                
                                                                                                                            
  
     

#include "runtime.h"

#ifndef EXCLUDE_BRANCH_ALPHA

                                                                                  
static int flow_component_01 = 0;

static void flow_component_00(int data)
{
    if(flow_component_01)
    {
        {
            int i;
            int buffer[10] = { 0 };
                                                                                                      
                                                                           
            if (data >= 0)
            {
                buffer[data] = 1;
                                            
                for(i = 0; i < 10; i++)
                {
                    printIntLine(buffer[i]);
                }
            }
            else
            {
                printLine("ERROR: Array index is negative.");
            }
        }
    }
}

void process_case()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_component_01 = 1;           
    flow_component_00(data);
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                                                      
static int flow_component_03 = 0;
static int flow_component_06 = 0;
static int flow_component_09 = 0;

                                                                                                     
static void flow_component_02(int data)
{
    if(flow_component_03)
    {
                                                                          
        printLine("Status message");
    }
    else
    {
        {
            int i;
            int buffer[10] = { 0 };
                                                                                      
            if (data >= 0 && data < (10))
            {
                buffer[data] = 1;
                                            
                for(i = 0; i < 10; i++)
                {
                    printIntLine(buffer[i]);
                }
            }
            else
            {
                printLine("ERROR: Array index is out-of-bounds");
            }
        }
    }
}

static void process_case()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_component_03 = 0;            
    flow_component_02(data);
}

                                                                                                    
static void flow_component_05(int data)
{
    if(flow_component_06)
    {
        {
            int i;
            int buffer[10] = { 0 };
                                                                                      
            if (data >= 0 && data < (10))
            {
                buffer[data] = 1;
                                            
                for(i = 0; i < 10; i++)
                {
                    printIntLine(buffer[i]);
                }
            }
            else
            {
                printLine("ERROR: Array index is out-of-bounds");
            }
        }
    }
}

static void flow_component_04()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_component_06 = 1;           
    flow_component_05(data);
}

                                            
static void flow_component_08(int data)
{
    if(flow_component_09)
    {
        {
            int i;
            int buffer[10] = { 0 };
                                                                                                      
                                                                           
            if (data >= 0)
            {
                buffer[data] = 1;
                                            
                for(i = 0; i < 10; i++)
                {
                    printIntLine(buffer[i]);
                }
            }
            else
            {
                printLine("ERROR: Array index is negative.");
            }
        }
    }
}

static void flow_component_07()
{
    int data;
                         
    data = -1;
                                                                               
                                                                        
    data = 7;
    flow_component_09 = 1;           
    flow_component_08(data);
}

void run_paths()
{
    process_case();
    flow_component_04();
    flow_component_07();
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
