/**
 * @author Syed Amaar Ahmad
 * @date July 13, 2010
 * This function is the main function where (1) table records are created and
 * (2) query requests
 * (3) Table is searched based on the request
 * (4) query replies based on the searched results are generated
 * (5) local cache at the module can be updated with these results
 * (6) It is used to TEST SWITCH module's capability as well
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include "createtable.h"
#include "queryoperation.h"
#include "switchtask.h"

struct tableRecord *ptrGlobal; /**<This variable points to the first table record*/

struct tableRecord *ptrCache; /**<This variable points to the first record of a module's local cache*/

unsigned int GlobalSerialId; /**<This variable denotes the identity of the generated query*/

int main(int argc, char *argv[])
{

	unsigned int ModuleId; /**<Refers to the module being searched*/

	unsigned vc; /**<refers to the VCI for a module's internal search*/

	int FileORNew; /**<This is used to determine whether the table record is produced from a file
	or altogether anew*/

	int d ; /**<direction flag (i.e. UP or DOWN)*/

	int SwitchORFunctions ; /**<This variable decides whether we want to simply test
	 *query functions (`0') or do we want to test the Switch function (`1')*/


	struct tableRecord *ptr2, *ptr3, *ptrCache, *ptrCacheptr;/**<These variables are used for a variety
	of temporary tasks*/

	struct finsFrame QRequest;
	struct finsFrame QReply;

	struct destinationList *destListTest;
	char *fileN =argv[1];


	/**Choose between reading the file or generating FINS frames here*/

	/**Choose between testing individual functions or testing the Switch*/


	printf("Test Switch ('1') or Functions ('0'):");

	scanf("%d", &SwitchORFunctions);


	printf("Create new file ('1') or use old file ('0'):");

	scanf("%d", &FileORNew);

	if (FileORNew==1)
	ProduceTableFile(fileN);  /** The file is populated with randomly generated table records*/


	/**The following choice enables individual testing of functions*/

	if (SwitchORFunctions==0)
	{


		/**the config file name is passed as a parameter during run time*/


		ptrGlobal = ReadTableFile(fileN);
		/**initialize table (i.e. create a dynamic linked list)
		 *with with the information stored in the named file; ptrGlobal
		 *is a global pointer to the first element of this linked list*/



		PrintRecords(ptrGlobal);  /**Printing the contents of the Table*/



		ModuleId=1;


		ptrCache = NULL;
		ptrCacheptr= ptrCache;

		while (ModuleId!=0)
		{
			printf("\nEnter Module Id (`0' to quit) \n ");
			scanf("%d", &ModuleId);

			if (ModuleId==0)
				exit(0);

			QRequest= GenerateQuery((unsigned char) ModuleId);  /**generate query based on the entered Module ID*/


			ptr2= SearchQuery(QRequest);
			/**ptr2 returns pointer to the first record of a linked list (containing all the record searched from the table)*/


			printf("\nSearched Query Results\n");


			QReply= GenerateReply(QRequest, ptr2); /**generate a query reply based on the query request, ptr2 points to the `found' list*/

			PrintRecords(QReply.ctrlFrame.replyRecord);  //print the records found in the table


			ptr3=UpdateCache(QReply, ptrCache);
			/*using the Query reply update the linked list at the Module side,
			 *ptrCache is the current pointer to the cache
			 *the return pointer ptr3 is the pointer to the first record at the updated cache side
			 *At the cache side the dynamic linked list contained in the QRep will be deleted (memory freed)
			 */

			printf("\nLocal Cache\n");


			ptrCache = ptr3;  /**the current pointer to the cache is now based on the returned pointer from the UpdateCache function*/


			PrintRecords(ptrCache);


			printf("\nEnter VCI for destination List search \n ");
			scanf("%d", &vc);
			fflush(stdout);


			printf("\nEnter Direction Flag '1' for DOWN, '0' for UP \n ");
			scanf("%d", &d);

			fflush(stdout);

			if (d==1)
			destListTest = SearchLocalTable(ptrCache, (unsigned char) vc, (unsigned char) DOWN);
			else if (d==0)
			destListTest = SearchLocalTable(ptrCache, (unsigned char) vc, (unsigned char) UP);

			PrintDestinationList(destListTest);
			FreeDestList(destListTest);

			FreeRecords(ptrGlobal);

		}// end read module while loop

	}

	else if (SwitchORFunctions==1) /**@ Test Switch module*/
	{

		/**@ This side acts as a dummy module
		 *which is accessing the switch and sending query requests to it
		 *and updating its local cache based on the replies. It also offers
		 *the capability to run through the local cache and determine the
		 *list of destinations
		 */


		SwitchInitialize(argv[1]);

		ptrCache = NULL;

		ModuleId = 1;

		PrintRecords(ptrGlobal);


		while (ModuleId != 0)
		{
			printf("\nEnter Module Id (`0' to quit) \n ");
			scanf("%d", &ModuleId);




			if (ModuleId==0)
				exit(0);

			QRequest= GenerateQuery((unsigned char) ModuleId);  /**generate query based on the entered Module ID*/



			QReply = SwitchSearch(QRequest); /**Send the request to the switch for search
			which then returns a reply*/



			ptr3=UpdateCache(QReply, ptrCache);

			ptrCache = ptr3;  /**the current pointer to the cache is now based on the returned pointer from the UpdateCache function*/

			printf("\nPRINTING LOCAL CACHE\n");
			PrintRecords(ptrCache);


			printf("\nEnter VCI for destination List search \n ");
			scanf("%d", &vc);
			fflush(stdout);


			printf("\nEnter Direction Flag '1' for DOWN, '0' for UP \n ");
			scanf("%d", &d);

			fflush(stdout);

			if (d==1)
			destListTest = SearchLocalTable(ptrCache, (unsigned char) vc, (unsigned char) DOWN);
			else if (d==0)
			destListTest = SearchLocalTable(ptrCache, (unsigned char) vc, (unsigned char) UP);

			PrintDestinationList(destListTest);


		}

		SwitchTerminate();

		free(ptrCache);

	}


	return 0;
}
