#include <stdio.h>
#include <stdlib.h>
#include "queryheader.h"
#include "finstypes.h"


/**
@brief generate a queryrequest frame based on search for the module ID
@param ModuleID is the id of the module being searched in the table

*/


struct finsFrame GenerateQuery(unsigned char ModuleId)
{
 extern unsigned int GlobalSerialId;  //incremented every time a request is made ..is a global number
 
  struct finsFrame Req;

  Req.ctrlFrame.senderID = ModuleId;

  Req.ctrlFrame.opcode = (unsigned char) QUERYREQUEST;
  
  Req.destinationID.id = (unsigned char) 0; // SWITCH IS THE DESTINATION
  Req.destinationID.next = NULL;

  Req.dataOrCtrl=CONTROL;


  Req.ctrlFrame.serialNum = GlobalSerialId;

  Req.ctrlFrame.paramterID = 0;
  Req.ctrlFrame.paramterValue = NULL;
  Req.ctrlFrame.replyRecord = NULL;

  GlobalSerialId = GlobalSerialId + 1;
  
  
  return Req;
};

/**
@brief generate a queryreply frame based on the search for the module ID in the Table
@param Req is the queryrequest
@param ptr is a pointer to the first record in the dynamically created linked list which is based on the search
*/

struct finsFrame GenerateReply(struct finsFrame Req, struct tableRecord *ptr)
{
  
 /**ptr points to the first element of the linked list searched from the table*/
 
  struct finsFrame Q;
  
  Q.dataOrCtrl=Req.dataOrCtrl;
  Q.ctrlFrame.opcode= (unsigned char) QUERYREPLY;// Req.ctrlFrame.opcode;
  Q.ctrlFrame.serialNum = Req.ctrlFrame.serialNum;
  
  Q.ctrlFrame.senderID = Req.destinationID.id;
  Q.destinationID.id = Req.ctrlFrame.senderID;
  Q.destinationID.next = NULL;
  
  Q.ctrlFrame.replyRecord = ptr;
  
  return Q;
};



/**
@brief searches for the record in the table, the retun pointer is to the first record of a linked list (based on the search)
@param Req is the queryrequest
*/


struct tableRecord * SearchQuery(struct finsFrame Req)
{
 
  
  
struct tableRecord *ptr, *ptr2;

extern struct tableRecord *ptrGlobal;
/**points to the global variable in the main..need to extern because the global variable is in a different file*/

     
   struct tableRecord *First = (struct tableRecord *) malloc (sizeof(struct tableRecord));
   
   

  
   
   int Found;
   

  
  fprintf(stdout, "\n Inside Search Function \n"); 
  fflush(stdout);
  
 
 
  Found = 0;
   
  
  
  ptr = ptrGlobal;  /** points to the global pointer to the Table ..outside the scope of this function*/
  	 
  ptr2=First;
  
  
  
  while (ptr!=NULL) // while the Table has not been entirely read keep looping
  {
    

      if (Req.ctrlFrame.senderID == ptr->sourceID)
     {
          
      if (Found>0)
      {struct tableRecord *Later = (struct tableRecord *) malloc (sizeof(struct tableRecord));
    
       Later->sourceID = ptr->sourceID;
       Later->destinationID = ptr->destinationID;
       Later->vci = ptr->vci;
       Later->directionFlag = ptr->directionFlag;
       Later->next = NULL;
       
       
       ptr2->next = Later;
       
             
       ptr2 = Later;
 

      }
      else
      {	
       First->sourceID = ptr->sourceID;
       First->destinationID = ptr->destinationID;

       First->vci = ptr->vci;
       First->directionFlag = ptr->directionFlag;
       ptr2=First;
	
      } //end found
       
        Found=Found+1;
     
	  }
    
 ptr=ptr->next;
  
  }//end while loop
  
   
 if (Found==0)  // if no match is found then free memory which had been initially created
 {  free (First);
 
 printf("\nNot Found\n");
 fflush(stdout);
 return NULL;
 }
 
  fprintf(stdout, "\n Search Successful! \n"); 
  fflush(stdout);

return First;  /**return pointer the first element of the new linked list*/
}


/**
@brief removes the dynamic linked list to prevent memory leakage
@param ptr is a pointer to the first record of this list
*/

void Freerecords(struct tableRecord *ptr)
{
 
  
struct tableRecord *ptrd2, *ptrd3;

ptrd2=ptr;
ptrd3=ptr;

    while (ptrd2!=NULL){

       printf("\n Deleting tableRecord with Sender Id %d \n", ptrd3->sourceID);
       fflush(stdout);
      ptrd2=ptrd2->next;

      free(ptrd3);


      ptrd3=ptrd2;
      
}

}


/**
@brief prints the contents of the linked list
@param ptr is a pointer to the first record of this list
*/

void Printrecords(struct tableRecord *ptr)
{
 

struct tableRecord *ptrP;


ptrP=ptr;
printf("\n ********* Start Printing tableRecords **********\n");
    while (ptrP!=NULL){
     printf("\ntableRecord:::::::::::::::::::::::: \n");

      printf("Sender Id %d \n ",ptrP->sourceID);
      printf("vci %d \n",ptrP->vci);
      printf("Direction Flag %d \n",ptrP->directionFlag);
      printf("Destination Id %d \n",ptrP->destinationID);
      
      ptrP=ptrP->next;

}

printf("\n ********* Finished Printing tableRecords **********\n");
fflush(stdout);

}



/**
@brief checks whether the record pointed to by the ptr exists within a linked list which starts by PTRX
@param Pu2 is a pointer to the record being tested for uniqueness
@param Pu1 is a pointer to the first record of the linked list
*/

int UniqueRecord(struct tableRecord *Pu1, struct tableRecord *Pu2)
{

	/** This function determines how many matching records already exist within the linked list
	 *
	 * */


  struct tableRecord *Pu3;
  int U = 0;

  Pu3 = Pu1;

  while (Pu3!=NULL)
  {

	  if (Pu2->destinationID==Pu3->destinationID && Pu2->sourceID==Pu3->sourceID && Pu2->vci==Pu3->vci && Pu2->directionFlag==Pu3->directionFlag)
	  {U = U+1;


	  }
     Pu3= Pu3->next;
  }


return U;
}

/**
@brief connects two linked lists together; the second list is appended after the first list
@param P is a pointer to the first record of the first list
@param P1 is a pointer to the first record of the second list
*/


struct tableRecord* ConnectLists(struct tableRecord *P, struct tableRecord *P1)
{
  //this function simply joins/connects two linked lists P and P1 and returns the pointer to the new list's header

struct tableRecord *P2, *P3;

//P1 is the old list
// P is the new list and needs to be added


if (P1==NULL)  //if old list is null and does not exist


  if (P==NULL)
  {P2= NULL;
  }
    else
  P2 = P;   //new list becomes the current list

else

{
  if (P==NULL)  //if new list is null and does not exist
  P2 = P1;  //return old list only
  else
  {
    P2 = P1;
    P3 = P1;

    while (P3->next !=NULL)   //append the two lists sequentially and return
      P3= P3->next;

    P3->next = P;



    P1 = P2;
  }

}
return P2;
}

/**
@brief updates a linked list at the side of the querying module, also makes use of ConnectLists function (see below)
@param Q is the query reply and has the linked list (which is going to be appended with the module's local cache)
@param PTRX is the pointer to the first element of the local cache at the module side
*/


struct tableRecord* UpdateCache(struct finsFrame Q, struct tableRecord *PTRX)
{
 
  //the QueryReply points to a linked list
  //PTRX is the pointer to the first record in the current cache
  //returns pointer to the new linked list created from the searched linked list...
  

struct tableRecord *ptr, *Ptr, *pUpdatedCache, *pUniqueTest;
  int Found;

  int Unique = 0;
  struct tableRecord *FirstC = (struct tableRecord *) malloc (sizeof(struct tableRecord));

  
  ptr = Q.ctrlFrame.replyRecord;
  
  printf("\n Inside Update Cache which received a Query Reply\n");
  
  
  Found = 0;

  
  if (Q.ctrlFrame.replyRecord!=NULL)   //If at least one record was found from the Table
  { 
  

		//update table cache
	
    Ptr=FirstC;
     
  while (ptr!=NULL)
  {
    
    printf("  Updating Module Cache \n");
	 fflush(stdout);

	 pUniqueTest = PTRX;

     Unique = UniqueRecord(pUniqueTest, ptr); /**check if any such record exists within the current cache itself*/


  if (ptr!=NULL && Unique == 0) /**Update cache with the new list only if the entries are unique*/
      {	 
      
       if (Found>0)
      {struct tableRecord *Later = (struct tableRecord *) malloc (sizeof(struct tableRecord));
    
       Later->sourceID = ptr->sourceID;
       Later->destinationID = ptr->destinationID;
       Later->vci = ptr->vci;
       Later->directionFlag = ptr->directionFlag;
       Later->next = NULL;
       
     
       
       Ptr->next = Later;
       
             
       Ptr = Later;
     fflush(stdout);
       
 
      }
      else
      {	
	
       FirstC->sourceID = ptr->sourceID;
       FirstC->destinationID = ptr->destinationID;
       FirstC->vci = ptr->vci;
       FirstC->directionFlag = ptr->directionFlag;
       FirstC->next = NULL;
       Ptr=FirstC;
   	
	
      } //end elseif 
       
       Found=Found+1;
   
      } //end if (ptr!=NULL && Unique == 0) condition
	
  

	
       ptr=ptr->next;
  
  }//end while loop

   printf("\nExisting Cache Updated with %d entries \n", Found);	

   
   if (Found!=0)
   pUpdatedCache = ConnectLists(FirstC, PTRX);
   else
	   pUpdatedCache = ConnectLists(NULL, PTRX);//if only matched entries were found then the cache stays the same (the elements already exist at the cache)
   
  }
  else
  {
   pUpdatedCache = ConnectLists(NULL, PTRX);//if Query reply sent empty list then the cache stays the same

  }
    

  Freerecords(Q.ctrlFrame.replyRecord);  /*free memory which had been allocated for the initial searching*/


  return pUpdatedCache;  //return pointer to the first record of the updated cache at the module side
}


/**
@brief checks the local cache of a module and return the destination list found within the cache. AKA the crazy function!
@param ptrCache is a pointer to the first record of the cache
@param vc is the VCI
@param DF is the directionFlag
*/

struct destinationList * searchLocalTable(struct tableRecord *ptrCache, unsigned char vc, unsigned char DF)
{

  struct tableRecord *ptr1;

  struct destinationList *a, *c;

  struct destinationList *b = (struct destinationList *) malloc (sizeof(struct destinationList));

  int L = 0;

  ptr1 = ptrCache;



  while (ptr1!=NULL) //while the local cache is still being searched
	 {


	  if ((ptr1->vci == vc) && (ptr1->directionFlag == DF) ) //match the entries
	  {

		  if (L == 0)   //for the very first destination ID
		  {

			  b->id = ptr1->destinationID;
			  b->next = NULL;
			  a = b;
			  c= b;

		  }
		  else  //for all other destination IDs
		  {
			  struct destinationList *b = (struct destinationList *) malloc (sizeof(struct destinationList));
			  b->id = ptr1->destinationID;
						  b->next = NULL;
			  a->next = b;

		  }


		  L= L+1;




	  } //end if of the `match the entries'


	  ptr1= ptr1->next;

	 } //ending the cache searching


if (L==0) free(b); //if no match was found then the memory has to be freed


return c;
}

