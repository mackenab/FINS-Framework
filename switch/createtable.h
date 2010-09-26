#include <stdio.h>
#include <stdlib.h>
#include "queryheader.h"

struct tableRecord* createtable(char* string);

void ProduceTableRecords(char *FileName);

struct tableRecord GenRecord(unsigned char sourceId, unsigned char destinationID, unsigned char VCI, unsigned char directionFlag);

