                                   
                                                                
                                                                          
                                     
  
  
               
                                      
                                                                       
                                                                                 
        
                                    
                            
  
     

#include "runtime.h"

#ifndef EXCLUDE_BRANCH_ALPHA

void process_case()
{
    int64_t * data;
                         
    data = NULL;
                                                                 
                                                                          
    data = (int64_t *)malloc(sizeof(data));
    if (data == NULL) {exit(-1);}
    *data = 2147483643LL;
                                                                                         
    printLongLongLine(*data);
    free(data);
}

#endif              

#ifndef EXCLUDE_BRANCH_BETA

                                                  
static void process_case()
{
    int64_t * data;
                         
    data = NULL;
                                                     
    data = (int64_t *)malloc(sizeof(*data));
    if (data == NULL) {exit(-1);}
    *data = 2147483643LL;
                                                                                         
    printLongLongLine(*data);
    free(data);
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
