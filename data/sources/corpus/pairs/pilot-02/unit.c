                                   
                                                                
                                                                            
                                      
  
  
               
                                      
                                                               
                                                
         
                                               
                                                                                
                                                                                                                            
  
     

#include "runtime.h"

#ifndef EXCLUDE_BRANCH_ALPHA

                                                                                  
static int flow_gate = 0;

static void write_buffer(int data)
{
    if(flow_gate)
    {
        {
            int i;
            int * buffer = (int *)malloc(10 * sizeof(int));
            if (buffer == NULL) {exit(-1);}
                                   
            for (i = 0; i < 10; i++)
            {
                buffer[i] = 0;
            }
                                                                                                      
                                                                            
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
            free(buffer);
        }
    }
}

void process_case()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_gate = 1;           
    write_buffer(data);
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                                                      
static int flow_gate = 0;
static int flow_gate_second = 0;
static int flow_gate_third = 0;

                                                                                                     
static void write_buffer(int data)
{
    if(flow_gate)
    {
                                                                          
        printLine("Status message");
    }
    else
    {
        {
            int i;
            int * buffer = (int *)malloc(10 * sizeof(int));
            if (buffer == NULL) {exit(-1);}
                                   
            for (i = 0; i < 10; i++)
            {
                buffer[i] = 0;
            }
                                                                                      
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
            free(buffer);
        }
    }
}

static void process_case()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_gate = 0;            
    write_buffer(data);
}

                                                                                                    
static void write_alternate(int data)
{
    if(flow_gate_second)
    {
        {
            int i;
            int * buffer = (int *)malloc(10 * sizeof(int));
            if (buffer == NULL) {exit(-1);}
                                   
            for (i = 0; i < 10; i++)
            {
                buffer[i] = 0;
            }
                                                                                      
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
            free(buffer);
        }
    }
}

static void process_alternate()
{
    int data;
                         
    data = -1;
                                              
    data = 10;
    flow_gate_second = 1;           
    write_alternate(data);
}

                                            
static void write_secondary(int data)
{
    if(flow_gate_third)
    {
        {
            int i;
            int * buffer = (int *)malloc(10 * sizeof(int));
            if (buffer == NULL) {exit(-1);}
                                   
            for (i = 0; i < 10; i++)
            {
                buffer[i] = 0;
            }
                                                                                                      
                                                                            
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
            free(buffer);
        }
    }
}

static void process_secondary()
{
    int data;
                         
    data = -1;
                                                                               
                                                                       
    data = 7;
    flow_gate_third = 1;           
    write_secondary(data);
}

void run_paths()
{
    process_case();
    process_alternate();
    process_secondary();
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
