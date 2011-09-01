/**
 * @file queue.c FOR COPYRIGHTS This code is a modified version from a code which
 * has been copied from an unknown code exists online. We dont claim the ownership of
 * the original code. But we claim the ownership of the modifications.
 *
 * @author Abdallah Abdallah
 */


#include <queue.h>
#include <fatal.h>
#include <stdlib.h>

#define MinQueueSize ( 5 )

/**   struct QueueRecord
 {
 int Capacity;
 int Front;
 int Rear;
 int Size;
 ElementType *Array;
 };*/

/* START: fig3_58.txt */
int IsEmpty(Queue Q) {
	return Q->Size == 0;
}
/* END */

int IsFull(Queue Q) {
	return Q->Size == Q->Capacity;
}

Queue CreateQueue(const char* name, int MaxElements) {
	Queue Q;

	/* 1*/
	if (MaxElements < MinQueueSize)
		/* 2*/Error( "Queue size is too small" );

	/* 3*/
	Q = malloc(sizeof(struct QueueRecord));
	/* 4*/
	if (Q == NULL)
		/* 5*/FatalError( "Out of space!!!" );

	/* 6*/
	Q->Array = malloc(sizeof(ElementType) * MaxElements);
	/* 7*/
	if (Q->Array == NULL)
		/* 8*/FatalError( "Out of space!!!" );
	/* 9*/
	Q->Capacity = MaxElements;
	strcpy(Q->name, name);
	/*10*/
	MakeEmpty(Q);

	/*11*/return Q;
}

/* START: fig3_59.txt */
void MakeEmpty(Queue Q) {
	Q->Size = 0;
	Q->Front = 1;
	Q->Rear = 0;
}
/* END */

int DisposeQueue(Queue Q) {
	if (Q != NULL) {
		free(Q->Array);
		free(Q);
	}
	return (1);
}

/* START: fig3_60.txt */

static int Succ(int Value, Queue Q) {
	Value++;
	return (Value % Q->Capacity);

	/* if( ++Value == Q->Capacity )
	 Value = 0;
	 return Value;*/
}

int Enqueue(ElementType X, Queue Q) {
	if (IsFull(Q)) {
		Error( "Full queue" );
		return (0);
	} else {
		Q->Size++;
		Q->Rear = Succ(Q->Rear, Q);
		Q->Array[Q->Rear] = X;
		return (1);
	}
}
/* END */

ElementType Front(Queue Q) {
	if (!IsEmpty(Q))
		return Q->Array[Q->Front];
	Error( "Empty queue" );
	return 0; /* Return value used to avoid warning */
}

void Dequeue(Queue Q) {
	if (IsEmpty(Q))
		Error( "Empty queue" );
	else {
		Q->Size--;
		Q->Front = Succ(Q->Front, Q);
	}
}

ElementType FrontAndDequeue(Queue Q) {
	ElementType X = (ElementType) malloc(sizeof(ElementType));

	if (IsEmpty(Q)) {
		//Error( "Empty queue" );
		// PRINT_DEBUG("Empty queue");
		free(X);
		return (NULL);
	} else {
		Q->Size--;
		X = Q->Array[Q->Front];
		Q->Array[Q->Front] = NULL;
		Q->Front = Succ(Q->Front, Q);
		return X;
	}

}

int TerminateQueue(Queue Q) {

	int i = 0;
	for (i = 0; i < Q->Size; i++)
		free(Q->Array[i]);

	Q->Size = 0;

	return (1);

}
