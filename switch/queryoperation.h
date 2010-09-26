#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"


/**
@brief generate a queryrequest frame based on search for the module ID
@param ModuleID is the id of the module being searched in the table

*/

struct finsFrame GenerateQuery(unsigned char ModuleId);

/**
@brief generate a queryreply frame based on search already conducted for the module ID
@param Req is the queryrequet
@param ptr is a pointer to the first record in the table

*/

struct finsFrame GenerateReply(struct finsFrame Req, struct tableRecord *ptr);

/**
@brief searches for the record in the table, the retun pointer is to the first record of a linked list (based on the search)
@param Req is the queryrequet
*/

struct tableRecord * SearchQuery(struct finsFrame Req);

/**
@brief connects two linked lists together; the second list is appended after the first list, returns pointer to the first record of the updated list
@param P is a pointer to the first record of the first list
@param P1 is a pointer to the first record of the second list
*/

struct tableRecord* ConnectLists(struct tableRecord *P, struct tableRecord *P1);

/**
@brief updates a linked list at the side of the querying module
@param Q is the query reply
@param ptrCache is the pointer to the first record of the current cache
*/


struct tableRecord* UpdateCache(struct finsFrame Q, struct tableRecord *PTRX);

/**
@brief checks the local cache of a module and returne the destination list found within
@param ptrCache is a pointer to the first record of the cache
@param vc is the VCI
@param DF is the directionFlag
*/

struct destinationList* searchLocalTable(struct tableRecord *ptrCache, unsigned char vc, unsigned char DF);

/**
@brief removes the dynamic linked list to prevent memory leakage, also makes use of ConnectLists function (see below)
@param ptr is a pointer to the first record of this list
*/

void Freerecords(struct tableRecord *ptr);

/**
@brief prints the contents of the linked list
@param ptr is a pointer to the first record of this list
*/

void Printrecords(struct tableRecord *ptr);


/**
@brief checks whether the record pointed to by the ptr exists within a linked list which starts by PTRX
@param ptr is a pointer to the record being tested for uniqueness
@param P1 is a pointer to the first record of the linked list
*/

int UniqueRecord(struct tableRecord *PTRX, struct tableRecord *ptr);


