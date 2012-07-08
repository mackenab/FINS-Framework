#include <sys/types.h>
#include <stdio.h>
#include <string.h>


/* START: fig3_6.txt */
        #ifndef _List_H
        #define _List_H


        typedef u_char* ElementType;
        struct Node;

        typedef struct Node *PtrToNode;
        typedef PtrToNode List;
        typedef PtrToNode Position;
        struct Node
               {
                   ElementType Element;
                   Position    Next;
               };


        List MakeEmpty( List L );
        int IsEmpty( List L );
        int IsLast( Position P, List L );
        Position Find( ElementType X, List L );
        void Delete( ElementType X, List L );
        Position FindPrevious( ElementType X, List L );
        void Insert( ElementType X, List L, Position P );
        void DeleteList( List L );
        Position Header( List L );
        Position First( List L );
        Position Advance( Position P );
        ElementType Retrieve( Position P );

        #endif    /* _List_H */
/* END */
