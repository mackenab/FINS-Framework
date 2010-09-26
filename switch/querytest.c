/**
 * @author Syed Amaar Ahmad
 * @data July 13, 2010
 * This function is the main function where (1) table records are created and
 * (2) query requests
 * (3) Table is searched based on the request
 * (4) query replies based on the searched results are generated
 * (5) local cache at the module can be updated with these results
 */


#include <stdlib.h>
#include <stdio.h>
#include "createtable.h"
#include "queryoperation.h"

struct tableRecord *ptrGlobal, *ptrCache;

unsigned int GlobalSerialId;

int main(int argc, char *argv[])
{

  unsigned int ModuleId, M;
  unsigned char md;
  

 struct tableRecord *ptr2, *ptr3, *ptrCache, *ptrCacheptr;
  struct finsFrame QReq;
  struct finsFrame QRep;


  char *string =argv[1];
  /**the config file name is passed as a parameter during run time*/
 
  ProduceTableRecords(string);  /** The file is populated with randomly generated table records*/

  ptrGlobal = createtable(string);
  /**initialize table (i.e. create a dynamic linked list)
  with with the information stored in the named file; ptrGlobal
  is a global pointer to the first element of this linked list*/

  
 
  Printrecords(ptrGlobal);  /**Printing the contents of the Table*/
 
  
  
  ModuleId=1;
  M = 0;
  md = 1;
  
  ptrCache = NULL;
  ptrCacheptr= ptrCache;
  
  while (ModuleId!=0)
  {  
  printf("\nEnter Module Id (`0' to quit) \n ");
  scanf("%d", &ModuleId);
  
  
  QReq= GenerateQuery((unsigned char) ModuleId);  /**generate query based on the entered Module ID*/
  
    
  ptr2= SearchQuery(QReq);
  /**ptr2 returns pointer to the first record of a linked list (containing all the record searched from the table)*/


     printf("\nSearched Query Results\n");

    
  QRep= GenerateReply(QReq, ptr2); /**generate a query reply based on the query request, ptr2 points to the `found' list*/

   Printrecords(QRep.ctrlFrame.replyRecord);  //print the records found in the table


   ptr3=UpdateCache(QRep, ptrCache);   
   /*using the Query reply update the linked list at the Module side,
   ptrCache is the current pointer to the cache
   the return pointer ptr3 is the pointer to the first record at the updated cache side
   At the cache side the dynamic linked list contained in the QRep will be deleted (memory freed)

 */ 
   printf("\nNew Cached List\n");
   Printrecords(ptr3);   //print contents of the cache
 
     
   ptrCache = ptr3;  //the current pointer to the cache is now based on the returned pointer from the UpdateCache function
    
 
  Printrecords(ptrCache);
  
  
  
  }// end read module while loop
  

  
    

return 0;
}
