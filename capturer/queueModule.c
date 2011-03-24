/*
 * inter_module_queue.c
 *
 *  Created on: Nov 2, 2010
 *      Author: amaar
 */


#include "finstypes.h"
#include "queueModule.h"


/**@brief initializes a queue buffer between the switch and the module
 * @param q_ptr points to this structure
 * */
struct queue * init_queue(){

	struct queue *q = (struct queue*) malloc(sizeof(struct queue));

	q->head = NULL;
	q->tail = NULL;
	q->num_elements = 0;
	sem_init(&(q->locked),0,1);  //semaphore for locking/unlocking the queue
	return q;
}

/**@brief terminates the queue buffer between the switch and the module
 * @param q_ptr points to this structure
 * */
int term_queue(struct queue *q_ptr){
	int status=0;
	struct q_element *ptr1, *ptr2;



	if (q_ptr == NULL)
		return(status);
/**
 * The next check can be skipped because it is already covered in the general case
 * it has been inserted here for debugging purposes only
 */
	if (q_ptr->num_elements == 0)
		{ free(q_ptr);
			status =1 ;
		return(status);
		}

	ptr1 = q_ptr->head;
	ptr2 = ptr1;


	while(ptr2 != NULL){
		ptr2 = ptr2->next;
		free(ptr1);
		ptr1 = ptr2;
	}
	sem_destroy(&(q_ptr->locked));
	free(q_ptr);
	status = 1;
	return(status);
}

/**@brief allows a finsFrame to be enqueued; there is a need to preserve integrity and hence we need to lock in the duration
 * @param fins_in the pointer to the fins frame being written into the queue
 * @param q_ptr points to this queue being accessed
 * FIXED BY Abdallah
 * */
int write_queue(struct finsFrame *fins_in, struct queue *q_ptr){

	int status=0;



	/** Adding the NULL check
	 * Abdallah
	 */
	if ((fins_in == NULL) || (q_ptr->num_elements <0))
	{return(status);}

	struct q_element *node = (struct q_element*) malloc(sizeof(struct q_element));
	struct q_element *curpos = q_ptr->tail;


	//	cpy_fins_to_fins(&node->element, fins_in); // fins frame read from tail
	/** Changed the copying to match the node element which became A POINTER
	 * Done by Abdallah
	 */
	memcpy(node->element, fins_in, sizeof(struct finsFrame));

	if ( (q_ptr->num_elements) ==0){

		node->next = NULL;
		q_ptr->head = node;
		q_ptr->tail = node;
	}


	else if ( (q_ptr->num_elements) > 0){

		q_ptr->tail->next = node;
		node->next = NULL;
		q_ptr->tail = node;

	}
	q_ptr->num_elements = q_ptr->num_elements+1;
	status = 1;

return (status);
} // end of read_queue

/**@brief allows a finsFrame to be dequeued; there is a need to preserve integrity and hence we need to lock in the duration
 * @param fins_in the pointer to the fins frame being read from the queue
 * @param q_ptr points to the queue being accessed
 * */

int read_queue(struct finsFrame *fins_in, struct queue *q_ptr){

	int status;
	struct q_element *ptr;

	status = 0;

	if ( (q_ptr == NULL) || (q_ptr->num_elements <=0) )
		return (status);

		if ( (q_ptr->num_elements) == 1)
		{
			memcpy(fins_in, q_ptr->head->element, sizeof(struct finsFrame));
			free(q_ptr->head);
			q_ptr->head = NULL;
			q_ptr->tail=NULL;
			q_ptr->num_elements = 0;

		}

		else if ( (q_ptr->num_elements) >1 )
		{// it needs to contain more than one element to be read

//		cpy_fins_to_fins(fins_in, &(q_ptr->tail->element)); // fins frame read from head
		memcpy(fins_in, q_ptr->head->element, sizeof(struct finsFrame));
		ptr = q_ptr->head;

		q_ptr->head = ptr->next;
		q_ptr->head->next = ptr->next->next;
		free(ptr);

		}
		q_ptr->num_elements = q_ptr->num_elements-1;

		status = 1;

	return(status);

} // end of read_queue

/**@brief copies the contents of one fins frame into another
 * @param dst is the pointer to the fins frame being written to
 * @param src is the pointer to the source fins frame
 * */
void cpy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src){


	if (src->dataOrCtrl == DATA){

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->dataFrame, &src->dataFrame, sizeof(src->dataFrame));

		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pdu = src->dataFrame.pdu;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->dataFrame.metaData = src->dataFrame.metaData;

	}
	else if (src->dataOrCtrl == CONTROL){

		PRINT_DEBUG("\ncontrol fins frame\n");

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->ctrlFrame, &src->ctrlFrame, sizeof(src->ctrlFrame));
		dst->ctrlFrame.opcode = src->ctrlFrame.opcode;
		dst->ctrlFrame.paramterID = src->ctrlFrame.paramterID;
		dst->ctrlFrame.paramterValue = src->ctrlFrame.paramterValue;
		dst->ctrlFrame.replyRecord = src->ctrlFrame.paramterValue;
		dst->ctrlFrame.senderID = src->ctrlFrame.senderID;
		dst->ctrlFrame.serialNum = src->ctrlFrame.serialNum;
	}

}

/**@brief prints the contents of a fins frame whether data or control type
 * @param fins_in the pointer to the fins frame
 * */
void print_finsFrame(struct finsFrame *fins_in){

	struct destinationList *dest;

	PRINT_DEBUG("Printing FINS frame: \n");

	dest = &(fins_in->destinationID);

	while (dest!=NULL){
	PRINT_DEBUG("\nDestination id %d", dest->id);
	dest=dest->next;
	}

	if (fins_in->dataOrCtrl==DATA){
		PRINT_DEBUG("\nData fins %d \n", fins_in->dataOrCtrl);
		PRINT_DEBUG("Direction flag %d\n", fins_in->dataFrame.directionFlag);
		PRINT_DEBUG("Meta data (first element) %x\n", fins_in->dataFrame.metaData);
		PRINT_DEBUG("PDU (first element value) %x\n", *(unsigned char*)(fins_in->dataFrame.pdu));
		PRINT_DEBUG("PDU size (bytes) %d\n", fins_in->dataFrame.pduLength);
	}
	else if (fins_in->dataOrCtrl==CONTROL){
		PRINT_DEBUG("\nControl fins %d\n", fins_in->dataOrCtrl);
		PRINT_DEBUG("\nOpcode %d\n", fins_in->ctrlFrame.opcode);
		PRINT_DEBUG("\nParameter ID %d\n", fins_in->ctrlFrame.paramterID);
		PRINT_DEBUG("\nParameter Value %d\n", fins_in->ctrlFrame.paramterValue);
		PRINT_DEBUG("\nReply Record (first element) %x\n", fins_in->ctrlFrame.replyRecord);
		PRINT_DEBUG("\nSender Id %d\n", fins_in->ctrlFrame.senderID);
		PRINT_DEBUG("\nSerial number %d\n", fins_in->ctrlFrame.serialNum);
	}
}
