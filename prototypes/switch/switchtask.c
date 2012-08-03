#include "switchtask.h"
#include "finstypes.h"
#include "queryoperation.h"
#include "createtable.h"


FILE *ptrMyfile; /**< this variable points to the file which contains all the records */
struct tableRecord *ptrTable; /**<this variable points to the first element
 	 	 	 	 	 	 	  * of any temporary linked list of records*/

/**@brief This function initializes the file
 * @ fileName is the name of the file
 */

void SwitchInitialize(char *fileName){

	extern struct tableRecord *ptrGlobal;


	ptrMyfile =fopen(fileName,"r");  //open file


	if (!ptrMyfile)  // exit if file cannot open


		exit(0);


	ptrGlobal = ReadTableFile(fileName);  /**initialize the table from the file*/

}

/**@brief This function closes the file of records
 */

void SwitchTerminate(){

	extern struct tableRecord *ptrGlobal;

	fclose(ptrMyfile);
	free(ptrGlobal);


}

/**@brief This function receives a FINS frame and performs a search based on the query request and passes
 *the request to the SwitchTask which then produces the query reply.
@param qRequest is the query request FINS frame.
*/

struct finsFrame SwitchSearch(struct finsFrame qRequest)
{

	extern struct tableRecord *ptrGlobal;

	/**<A temporary fins frame struct to communicate between modules
	 */
	struct finsFrame qReply;

	struct tableRecord *ptrTable;

	ptrTable = NULL;

	ptrTable= SearchQuery(qRequest);

	qReply = SwitchTask(qRequest, ptrTable);


	return qReply;

}

/**@brief This function receives a frame and then passes it to the target module
 * @param refers to the FINS frame
 * @ptrTable refers to the first element of records (this is needed in generating query reply etc.)
 */

struct finsFrame SwitchTask(struct finsFrame rcvdFrame, struct tableRecord *ptrTable)
{
	/* This function does not receive a finsFrame with opcode QUERYREPLY (e.g. 666) since this is the task of
  the switch is only to produce a query Reply
	 *
	 * */

	struct finsFrame outgoingFrame;
	struct destinationList *dstPtr;

	if (rcvdFrame.dataOrCtrl == (unsigned char) CONTROL)  //control type fins Frame
	{

		if (rcvdFrame.ctrlFrame.opcode == (unsigned char) QUERYREQUEST)  //if this is a query request generate a query reply
		{

			outgoingFrame = GenerateReply(rcvdFrame, ptrTable);  //this ptrTable points to the first entry of the Table


			//send to input_queue_module ()
		}
		else if (rcvdFrame.ctrlFrame.opcode == (unsigned char) READREQUEST)
		{
			//send to input_queue_module ()

		}
		else if (rcvdFrame.ctrlFrame.opcode == (unsigned char) READREPLY)
		{
			//send to input_queue_module ()

		}
		else if (rcvdFrame.ctrlFrame.opcode == (unsigned char) WRITEREQUEST)
		{
			//send to input_queue_module ()

		}
		else if (rcvdFrame.ctrlFrame.opcode == (unsigned char) WRITECONF)
		{
			//send to input_queue_module ()

		}



	}
	else if (rcvdFrame.dataOrCtrl == (unsigned char) DATA)  //data type fins Frame
	{
		/**@check the destination ID and send the frame to the module with this ID*/



		dstPtr = &rcvdFrame.destinationID;

/**@ The received FINS frame is duplicated and send to the modules. However the destination list is
 * pruned for the correct member for this purpose. For example, if the list has three members
 * each module will receive exactly the same frame but without the original destination list which
 * now only has its own ID.
 * */

		while (dstPtr!=NULL){


			if (dstPtr->id == (unsigned char) WIFISTUBID)
			{

				outgoingFrame = rcvdFrame;

				outgoingFrame.destinationID.id = dstPtr->id;
				outgoingFrame.destinationID.next = NULL;

			}
			else if (dstPtr->id == (unsigned char) IPID){


				outgoingFrame = rcvdFrame;

				outgoingFrame.destinationID.id = dstPtr->id;
				outgoingFrame.destinationID.next = NULL;
			}

			else if (dstPtr->id == (unsigned char) TCPID){

				outgoingFrame = rcvdFrame;

				outgoingFrame.destinationID.id = dstPtr->id;
				outgoingFrame.destinationID.next = NULL;

			}
			else if (dstPtr->id == (unsigned char) UDPID)
			{
				outgoingFrame = rcvdFrame;

				outgoingFrame.destinationID.id = dstPtr->id;
				outgoingFrame.destinationID.next = NULL;

			}
			else if (dstPtr->id == (unsigned char) SOCKETSTUBID)
			{
				outgoingFrame = rcvdFrame;

				outgoingFrame.destinationID.id = dstPtr->id;
				outgoingFrame.destinationID.next = NULL;

			}


			dstPtr = dstPtr->next;

			//send to the input queue of the module

		} //end inner while loop

	} //end data condition if


	//send reply
	return outgoingFrame;
}


