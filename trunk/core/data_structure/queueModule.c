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
	PRINT_DEBUG("Entered: Q=%p", Q);

	int counter = 0;
	int empty = 0;
	int size = Q->Size;
	int i;
	//ElementType X = (ElementType)malloc (sizeof(ElementType));
	int min;
	int max;

	PRINT_DEBUG("Front=%d, Rear=%d Cap=%d", Q->Front, Q->Rear, Q->Capacity);

	if (Q->Front <= Q->Rear) {
		min = Q->Front;
		max = Q->Rear;

		for (i = min; i <= max; i++) {
			if (Q->Array[i]) {
				/*
				if (Q->Array[i]->dataOrCtrl == DATA) {
					if (Q->Array[i]->dataFrame.pdu) {
						free(Q->Array[i]->dataFrame.pdu);
					}
				}
				*/

				if (freeFinsFrame(Q->Array[i]) == 0) {
					//PRINT_DEBUG("333");

					//PRINT_DEBUG("Element number %d was already NULL before deleting",i);
					empty++;
				} else {
					counter++;
				}
			}
		}
	} else {

		max = Q->Front;
		min = Q->Rear;

		for (i = max; i < Q->Capacity; i++) {
			if (Q->Array[i]) {
				/*
				if (Q->Array[i]->dataOrCtrl == DATA) {
					if (Q->Array[i]->dataFrame.pdu) {
						free(Q->Array[i]->dataFrame.pdu);
					}
				}
				*/

				if (freeFinsFrame(Q->Array[i]) == 0) {
					//PRINT_DEBUG("333");

					//PRINT_DEBUG("Element number %d was already NULL before deleting",i);
					empty++;
				} else {
					counter++;
				}
			}
		}

		for (i = 0; i <= min; i++) {
			if (Q->Array[i]) {
				/*
				if (Q->Array[i]->dataOrCtrl == DATA) {
					if (Q->Array[i]->dataFrame.pdu) {
						free(Q->Array[i]->dataFrame.pdu);
					}
				}
				*/

				if (freeFinsFrame(Q->Array[i]) == 0) {
					//PRINT_DEBUG("333");

					//PRINT_DEBUG("Element number %d was already NULL before deleting",i);
					empty++;

				} else {
					counter++;
				}
			}
		}
	}

	//while (checkEmpty(Q))

	PRINT_DEBUG("Empty cleared=%d/%d", empty, Q->Capacity);

	Q->Size = 0;

	if (counter == size)
		return (1);
	else
		return (0);

}

int DisposeFinsQueue(finsQueue Q) {
	PRINT_DEBUG("Entered: Q=%p", Q);
	if (Q != NULL) {
		if (Q->Array != NULL) {
			//freeFinsFrame(Q->Array);
			free(Q->Array);
		}

		free(Q);
	}
	return (1);

}
/**@brief terminates the queue buffer between the switch and the module
 * @param q points to this structure
 * */
int term_queue(finsQueue q) {
	PRINT_DEBUG("Entered: q=%p", q);
	if (q != NULL) {
		return (TerminateFinsQueue(q) && DisposeFinsQueue(q));
	} else {
		return 1;
	}
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

/**@brief insert a finsFrame at the front of queue q
 * @param ff the pointer to the fins frame being written into the queue
 * @param q points to this queue being accessed
 * @return 1 on success, 0 on failure (most probably due to insufficient memory)
 * @version 2  FIXED BY Abdallah
 * @version 3 Cancel all the previous work and use GDSL , Now we just wrapper the GDSL
 *
 * */
int write_queue_front(struct finsFrame *ff, finsQueue q) {
	return (EnqueueFront(ff, q));

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
void copy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src) {

	if (src->dataOrCtrl == DATA) {

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->dataFrame, &src->dataFrame, sizeof(src->dataFrame));

		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pdu = src->dataFrame.pdu;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->metaData = src->metaData;

	} else if (src->dataOrCtrl == CONTROL) {

		PRINT_DEBUG("\ncontrol fins frame\n");

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->ctrlFrame, &src->ctrlFrame, sizeof(src->ctrlFrame));
		dst->ctrlFrame.opcode = src->ctrlFrame.opcode;
		dst->ctrlFrame.param_id = src->ctrlFrame.param_id;
		dst->ctrlFrame.data = src->ctrlFrame.data;
		dst->ctrlFrame.replyRecord = (void *) src->ctrlFrame.data;
		dst->ctrlFrame.senderID = src->ctrlFrame.senderID;
		dst->ctrlFrame.serial_num = src->ctrlFrame.serial_num;
	}

}

/**@brief prints the contents of a fins frame whether data or control type
 * @param fins_in the pointer to the fins frame
 * */
void print_finsFrame(struct finsFrame *ff) {

	char *temp;
	struct destinationList *dest;

	PRINT_DEBUG("Printing FINS frame:");

	dest = &(ff->destinationID);

	while (dest != NULL) {
		PRINT_DEBUG("Destination id %d", dest->id);
		dest = dest->next;
	}

	if (ff->dataOrCtrl == DATA) {
		PRINT_DEBUG("Data fins %d", ff->dataOrCtrl);
		PRINT_DEBUG("Direction flag %d", ff->dataFrame.directionFlag);
		//PRINT_DEBUG("Meta data (first element) %x\n", fins_in->metaData);
		PRINT_DEBUG("PDU size (bytes) %d", ff->dataFrame.pduLength);
		int i = 0;
		while (i < ff->dataFrame.pduLength) {
			PRINT_DEBUG("%d", ff->dataFrame.pdu[i]);
			i++;

		}
		temp = (char *) malloc(ff->dataFrame.pduLength + 1);
		memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
		temp[ff->dataFrame.pduLength] = '\0';
		PRINT_DEBUG("pdu=%s", temp);
		free(temp);

	} else if (ff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("Control fins %d", ff->dataOrCtrl);
		PRINT_DEBUG("Opcode %d", ff->ctrlFrame.opcode);
		PRINT_DEBUG("Parameter ID %d", ff->ctrlFrame.param_id);
		PRINT_DEBUG("Parameter Value %d", *(int *) (ff->ctrlFrame.data));
		//		PRINT_DEBUG("\nReply Record (first element) %x\n", fins_in->ctrlFrame.replyRecord);
		PRINT_DEBUG("Sender Id %d", ff->ctrlFrame.senderID);
		PRINT_DEBUG("Serial number %d", ff->ctrlFrame.serial_num);
	}

}

struct finsFrame * buildFinsFrame(void) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
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
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = (unsigned char) 200;
	ff->destinationID.next = NULL;

	ff->dataFrame.directionFlag = UP;
	ff->metaData = metaptr;
	ff->dataFrame.pdu = fakeData;
	ff->dataFrame.pduLength = 10;

	return ff;
}

int freeFinsFrame(struct finsFrame *ff) {
	if (ff == NULL) {
		return (0);
	}

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);
	if (ff->dataOrCtrl == CONTROL) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->ctrlFrame.data) {
			free(ff->ctrlFrame.data);
		}
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->dataFrame.pdu) {
			free(ff->dataFrame.pdu);
		}
	} else {
		//dataOrCtrl uninitialized
		PRINT_ERROR("todo error");
	}

	free(ff);
	return (1);
}

