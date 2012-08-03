/*
 * ctestharness.h
 *
 *  Created on: Jul 13, 2010
 *      Author: amaar
 */

#ifndef CTESTHARNESS_H_
#define CTESTHARNESS_H_

#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"

struct finsFrame GenerateFileBasedCtrlFrames();
void InitTestHarn(char *FileName);
struct finsFrame GetFrame();
void TermTestHarn ();






#endif /* CTESTHARNESS_H_ */
