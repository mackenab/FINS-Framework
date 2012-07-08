#include <stdio.h>
#include <stdlib.h>


struct tableRecord* ReadTableFile(char* string);

void ProduceTableFile(char *FileName);

struct tableRecord GenRecord(unsigned char sourceId, unsigned char destinationID, unsigned char VCI, unsigned char directionFlag);

