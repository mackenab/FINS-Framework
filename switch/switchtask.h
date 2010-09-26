#include "finstypes.h"
/*
 * switchTask.h
 *
 *  Created on: Jul 23, 2010
 *      Author: amaar
 */

#ifndef SWITCHTASK_H_
#define SWITCHTASK_H_


#endif /* SWITCHTASK_H_ */

/**@brief This function initializes the file
 * @ fileName is the name of the file
 */

void SwitchInitialize(char *fileName);

/**@brief This function closes the file

 */

void SwitchTerminate();

/**@brief This function receives a FINS frame and performs a search based on the query request and passes
 *the request to the SwitchTask which then produces the query reply.
@param qRequest is the query request FINS frame.
*/

struct finsFrame SwitchSearch(struct finsFrame qRequest);

/** @brief This function simply acts as a go between modules, the return type is a finsFrame as well
   @param rcvdFrame is the finsFrame which is passed by a module to the switch.
   @param ptrTable is a pointer to a linked list of records (unless needed it may generally be NULL)
   The function also makes multiple copies of the frame for as many destinations stored in
  the destination List and sends them to the respective module queues
   */

struct finsFrame SwitchTask(struct finsFrame rcvdFrame, struct tableRecord *ptrTable);

