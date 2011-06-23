/**
 *
 * @file queueModule.c FOR COPYRIGHTS This code is a modified version from a code which
 * has been copied from an unknown code exists online. We dont claim the ownership of
 * the original code. But we claim the ownership of the modifications.
 *
 * @author Abdallah Abdallah
 * @date Nov 2, 2010
 *
 */

#include <queueModule.h>

/**@brief initializes a queue buffer between the switch and the module
 * @return pointer to the queue whose default name is Q
 * */
finsQueue init_queue(const char* name, int size) {

	if (name == NULL)
		return (CreateQueue("Q", size));
	else
		return (CreateQueue(name, size));

}

int TerminateFinsQueue(finsQueue Q) {
	PRINT_DEBUG("222");
	int counter = 0;
	int size = Q->Size;
	int i;
	//ElementType X = (ElementType)malloc (sizeof(ElementType));
	int min;
	int max;
	if (Q->Front <= Q->Rear) {
		min = Q->Front;
		max = Q->Rear;

		for (i = min; i <= max; i++) {
			if (freeFinsFrame(Q->Array[i]) == 0) {
				PRINT_DEBUG("333");

				PRINT_DEBUG("Element number %d was already NULL before deleting",i);

			} else {

				counter++;

			}
		}

	} else {

		max = Q->Front;
		min = Q->Rear;

		for (i = max; i < Q->Capacity; i++) {
			if (freeFinsFrame(Q->Array[i]) == 0) {
				PRINT_DEBUG("333");

				PRINT_DEBUG("Element number %d was already NULL before deleting",i);

			} else {

				counter++;

			}
		}

		for (i = 0; i <= min; i++) {
			if (freeFinsFrame(Q->Array[i]) == 0) {
				PRINT_DEBUG("333");

				PRINT_DEBUG("Element number %d was already NULL before deleting",i);

			} else {

				counter++;

			}
		}

	}

	//while (checkEmpty(Q))

	Q->Size = 0;

	if (counter == size)
		return (1);
	else
		return (0);

}

int DisposeFinsQueue(finsQueue Q) {

	if (Q != NULL) {
		// freeFinsFrame(Q->Array );
		free(Q);
	}
	return (1);

}
/**@brief terminates the queue buffer between the switch and the module
 * @param q points to this structure
 * */
int term_queue(finsQueue q) {

	return (TerminateFinsQueue(q) && DisposeFinsQueue(q));
	/**TODO dispose the queue */

}

/**@brief insert a finsFrame into queue q
 * @param ff the pointer to the fins frame being written into the queue
 * @param q points to this queue being accessed
 * @return 1 on success, 0 on failure (most probably due to insufficient memory)
 * @version 2  FIXED BY Abdallah
 * @version 3 Cancel all the previous work and use GDSL , Now we just wrapper the GDSL
 *
 * */
int write_queue(struct finsFrame *ff, finsQueue q) {
	return (Enqueue(ff, q));

} // end of read_queue

/**@brief allows a finsFrame to be dequeued; there is a need to preserve integrity and hence we need to lock in the duration
 * @param ff the pointer to received the fins frame being read from the queue
 * @param q points to the queue being accessed
 * @return 1 on success , 0 on failure
 * */

struct finsFrame * read_queue(finsQueue q) {

	return (FrontAndDequeue(q));

} // end of read_queue

int checkEmpty(finsQueue Q) {
	return (IsEmpty(Q));
}

/** Todo Getrid of the functions below in case they are needed any longer*/

/**@brief copies the contents of one fins frame into another
 * @param dst is the pointer to the fins frame being written to
 * @param src is the pointer to the source fins frame
 * */
void cpy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src) {

	if (src->dataOrCtrl == DATA) {

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->dataFrame, &src->dataFrame, sizeof(src->dataFrame));

		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pdu = src->dataFrame.pdu;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->dataFrame.metaData = src->dataFrame.metaData;

	} else if (src->dataOrCtrl == CONTROL) {

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
void print_finsFrame(struct finsFrame *fins_in) {

	struct destinationList *dest;

	PRINT_DEBUG("Printing FINS frame: \n");

	dest = &(fins_in->destinationID);

	while (dest != NULL) {
		PRINT_DEBUG("\nDestination id %d", dest->id);
		dest = dest->next;
	}

	if (fins_in->dataOrCtrl == DATA) {
		PRINT_DEBUG("\nData fins %d \n", fins_in->dataOrCtrl); PRINT_DEBUG("Direction flag %d\n", fins_in->dataFrame.directionFlag);
		//PRINT_DEBUG("Meta data (first element) %x\n", fins_in->dataFrame.metaData);
		PRINT_DEBUG("PDU size (bytes) %d\n", fins_in->dataFrame.pduLength);
		int i = 0;
		while (i < fins_in->dataFrame.pduLength) {
			PRINT_DEBUG("%d", fins_in->dataFrame.pdu[i]);
			i++;

		}

	} else if (fins_in->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("\nControl fins %d\n", fins_in->dataOrCtrl); PRINT_DEBUG("\nOpcode %d\n", fins_in->ctrlFrame.opcode); PRINT_DEBUG("\nParameter ID %d\n", fins_in->ctrlFrame.paramterID); PRINT_DEBUG("\nParameter Value %d\n", *(int *)(fins_in->ctrlFrame.paramterValue));
		//		PRINT_DEBUG("\nReply Record (first element) %x\n", fins_in->ctrlFrame.replyRecord);
		PRINT_DEBUG("\nSender Id %d\n", fins_in->ctrlFrame.senderID); PRINT_DEBUG("\nSerial number %d\n", fins_in->ctrlFrame.serialNum);
	}

}

struct finsFrame * buildFinsFrame(void) {

	struct finsFrame *f = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	PRINT_DEBUG("2.1");
	int linkvalue = 80211;
	char linkname[] = "linklayer";
	unsigned char fakeDatav[] = "loloa77a7";
	unsigned char *fakeData = fakeDatav;

	metadata *metaptr = (metadata *) malloc(sizeof(metadata));

	//metadata *metaptr;
	PRINT_DEBUG("2.2");
	metadata_create(metaptr);
	PRINT_DEBUG("2.3");
	metadata_addElement(metaptr, linkname, META_TYPE_INT);
	PRINT_DEBUG("2.4");
	metadata_writeToElement(metaptr, linkname, &linkvalue, META_TYPE_INT);
	PRINT_DEBUG("2.5");
	f->dataOrCtrl = DATA;
	f->destinationID.id = (unsigned char) 200;
	f->destinationID.next = NULL;

	(f->dataFrame).directionFlag = UP;
	(f->dataFrame).metaData = metaptr;
	(f->dataFrame).pdu = fakeData;
	(f->dataFrame).pduLength = 10;

	return (f);
}

int freeFinsFrame(struct finsFrame *f) {
	PRINT_DEBUG("4444");

	if (f == NULL)
		return (0);
	if ((f->dataFrame).metaData != NULL) {
		PRINT_DEBUG("6666");

		metadata_destroy((f->dataFrame).metaData);
		PRINT_DEBUG("5555");

	} PRINT_DEBUG("7777");

	free(f);
	PRINT_DEBUG("8888");

	return (1);

}
