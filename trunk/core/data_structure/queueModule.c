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

	PRINT_DEBUG("Front=%d, Rear=%d, Cap=%d", Q->Front, Q->Rear, Q->Capacity);

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

