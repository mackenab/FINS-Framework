#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "finstypes.h"

//the goal of the following functions is to generate fins control frames and populate a file

struct finsFrame GenFrame(unsigned char senderId, unsigned char destinationID, unsigned short int Opcode, struct tableRecord *E);


/** @brief Populates a binary file with artifically generated FINS control frames, The function can be used to create randomly generated FINS control frame (inbound or outbound) for any module

@param FileName is the name of the file
*/


void PopulateFile(char *FileName)
{


int recordsNum, J, rType, SD, I;
unsigned char SId, DId;


int recType;

struct finsFrame X1;


FILE *ptrmyfile;

		ptrmyfile=fopen(FileName,"w");
		if (!ptrmyfile)                               //open file for writing , exit if it cannot open
		{
			printf("Unable to open file!");
			exit (0);
		}   


printf("How many records to create ?\n");

scanf("%d", &recordsNum);

printf("Which module `1' for IP, `2' for TCP...\n");
scanf("%d", &recType);


srand ( (unsigned)time (0) );

if (recType==1)   //`1' stands for IP
{



for (J=0;J<recordsNum;J++)
{

 //randomly generate a number between  1 and 4


rType = rand()%4;


SD = rand()%2;

rType = rType%4 + 1;
printf("%d ", rType);

SD=SD+1;
printf("%d  ", SD);


if (SD==1)
{
SId = 22;                            //22 is the address of sourceID (i.e. IP module)
DId = (rand()%6+1)*11;                  

   if (DId == 22) DId = 11;             //DId is the destinationID module (randomly chosen)

}
  else
  {
   SId=(rand()%6+1)*11;                //DId is the sourceID module (randomly chosen)
   
   if (SId == 22) SId = 11;
   
   DId = 22;
  }
    
    printf("\n");


    /*Once a random source or destination module have been chosen it is time to generate FINS frame
    The following conditions specify which of the actions has to be carried out
    */
    
if (rType == 1)  // read parameter request

X1= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 111,NULL); 


if (rType==2) //read parameter reply
X1= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 222,NULL);

if (rType==3) //write parameter request
X1= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 333,NULL);

if (rType==4) //write confirmation
X1= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 444,NULL);


fwrite(&X1, sizeof(struct finsFrame), 1, ptrmyfile);     //the FINS control frame is then written to the opened binary file as a structure


}//generate for all the records (ends for loop)



}// (ends the if condition)



fclose(ptrmyfile);    // closes the file


//the following code is only to test whether the written file can be printed on screen or not.

ptrmyfile=fopen(FileName,"r");
    
   if (ptrmyfile)
     
        {
       for (I=0;I<recordsNum;I++){
	        fread(&X1,sizeof(struct finsFrame),1,ptrmyfile);
        printf("Sender ID : %d\n",X1.ctrlFrame.senderID);
     printf("Paramter ID : %d\n",X1.ctrlFrame.paramterID);

		printf("Serial Number : %d\n",X1.ctrlFrame.serialNum);
	        printf("OpCode : %d\n",X1.ctrlFrame.opcode);

        printf("Destination ID : %d\n\n",X1.destinationID.id);}
    }
    fclose(ptrmyfile);
    printf("\n");

};// end function



/** @brief Throws back finsFrame based on its input parameters 
@param senderId is the identity of the sending module
@param destinationID is the identity of the receiving module
@param opcode is the exact operation being carried out (e.g. write parameter request or read parameter reply)
@param E is a table record that is passed and is used only in case of a query request
*/


struct finsFrame GenFrame(unsigned char senderId, unsigned char destinationID, unsigned short int Opcode, struct tableRecord *E)
{


struct finsCtrlFrame A;
struct finsFrame B;
float *f;

A.senderID = senderId;
A.opcode = Opcode;


//serial number, parameter value and parameter ID are randomly generated

A.serialNum = rand() ;


A.paramterID = rand();


f = (float *) rand();

A.paramterValue = f;


if (Opcode==QUERYREPLY)   //if the opcode corresponds to a query reply, the FINS control frame makes a reference to a reply record
A.replyRecord = E;
else
A.replyRecord = NULL;

B.ctrlFrame=A;
B.dataOrCtrl = CONTROL;

B.destinationID.id = destinationID;
B.destinationID.next = NULL;

return B;

};


