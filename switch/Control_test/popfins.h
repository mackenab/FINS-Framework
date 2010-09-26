/*
 * popfins.h
 *
 *  Created on: Jul 13, 2010
 *      Author: amaar
 */

#ifndef POPFINS_H_
#define POPFINS_H_

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "finstypes.h"


void PopulateFile(char *FileName);
struct finsFrame GenFrame(unsigned char senderId, unsigned char destinationID, unsigned short int Opcode, struct tableRecord *E);


#endif /* POPFINS_H_ */
