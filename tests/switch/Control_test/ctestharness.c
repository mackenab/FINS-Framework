// the include list needed for this function

#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"

//the goal of the following functions is to read from a binary file and produce FINS control frames


FILE *ptr_myfile;

struct finsFrame GenerateFileBasedCtrlFrames();


/** @brief Open the binary file
@param FileName is the name of the file that has been populated with randomly generated FINS control structures
*/

void InitTestHarn(char *FileName)
{
  
 


ptr_myfile =fopen(FileName,"r");  //open file


if (!ptr_myfile)  // exit if file cannot open
      
  
      exit(0);
    
    
       
    
printf("Opening test harness file \n");

}


/** @brief Reads from a file and produces a finsFrame
@param ptr is the pointer to the file
*/
struct finsFrame GetFrame()
{
  
   
  
  struct finsFrame X1;
 
     if (!feof(ptr_myfile)) //neither end of file nor an invalid file
	 {

	   fread(&X1,sizeof(struct finsFrame),1,ptr_myfile);    //read from the binary file which already has FINS control frames stored
       

       }
     
  	return X1;
    
}

/** @brief Closes the file
@param ptr is the pointer to the file
*/


void TermTestHarn ()

{
printf("Closing test harness file \n");

fclose(ptr_myfile);

}
