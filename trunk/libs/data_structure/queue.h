/**
 * @file queue.h FOR COPYRIGHTS This code is a modified version from a code which
 * has been copied from an unknown code exists online. We dont claim the ownership of
 * the original code. But we claim the ownership of the modifications.
 */

#ifndef QUEUE_H_
#define QUEUE_H_

#include <finstypes.h>
#include <finsdebug.h>
/** Define the ElementType into the caller file */
//typedef int ElementType;
typedef struct finsFrame* ElementType;

/* START: fig3_57.txt */

//struct QueueRecord;
struct QueueRecord {
	int Capacity;
	int Front;
	int Rear;
	int Size;
	char name[50];
	int ID;

	ElementType *Array;
};

typedef struct QueueRecord *Queue;

int IsEmpty(Queue Q);
int IsFull(Queue Q);
Queue CreateQueue(const char* name, int MaxElements);
int DisposeQueue(Queue Q);
void MakeEmpty(Queue Q);
int Enqueue(ElementType X, Queue Q);
int EnqueueFront(ElementType X, Queue Q);
ElementType Front(Queue Q);
void Dequeue(Queue Q);
ElementType FrontAndDequeue(Queue Q);
int TerminateQueue(Queue Q);

#endif  /* QUEUE_H_ */
/* END */
