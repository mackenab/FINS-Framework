#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"
#include "popfins.h"
#include "ctestharness.h"


/*this main function initializes a binary file with artificially created FINS control frame
then this file is read and printed
*/



int main(int argc, char *argv[])
{
  
  int J, N;
  struct finsFrame A;


char *fileName;

  fileName = argv[1];//file name...it can be changed

  PopulateFile(fileName); //generate control frames and store them within the file named after the string


  
printf("\n\n \n Initializing and Reading from file\n\n");

 InitTestHarn(fileName); //open file

 
 printf("How many records to read from the populated file \n");
 scanf("%d", &N);
 

for (J=0;J<N;J++)
{ 
  
  {
    A = GetFrame();

    printf("Sender ID : %d\n",A.ctrlFrame.senderID);
       printf("Paramter ID : %d\n",A.ctrlFrame.paramterID);

		printf("Serial Number : %d\n",A.ctrlFrame.serialNum);
	       printf("OpCode : %d\n",A.ctrlFrame.opcode);

        printf("Destination ID : %d\n\n",A.destinationID.id);
  }

}

termTestHarn ();


return 0;
}
