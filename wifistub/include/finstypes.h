/**
 * @file htoi.c
 *
 * @date July 2, 2010
 * @brief has all the constants definitions and the FDF/FCF , and FinsFrame format.
 * @version 2 fix the define values to be into capital letters
 * @author: Abdallah Abdallah
 */




#ifndef FINSTYPES_H_
#define FINSTYPES_H_

#include "metadata.h"

/* macro to convert IPv4 address from human readable format (_P_resentation) to long int (_N_etwork)*/
#define IP4_ADR_P2N(a,b,c,d) (16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))


/* Definition of the modules IDs */
#define SOCKETSTUBID 55
#define UDPID	44
#define TCPID	33
#define IPID	22
#define WIFISTUBID	11

/* Definition of the possible Opcodes */

#define READREQUEST 111
#define READREPLY	222
#define WRITEREQUEST 333
#define WRITECONF	444
#define QUERYREQUEST	555
#define QUERYREPLY	666

/* Definition of data/control as well as direction flags */
#define DATA 0
#define CONTROL 1
#define UP 0
#define DOWN 1

/*meta data related definitions */
#define MAX_METADATASIZE	200

struct destinationList
{
	unsigned char id;
	struct destinationList *next;
};


struct tableRecord
{
	unsigned char sourceID;
	unsigned char directionFlag;
	unsigned char vci;
	unsigned char destinationID;
	struct tableRecord *next;
};


struct finsDataFrame
{

	/* Only for FINS DATA FRAMES */
	unsigned char directionFlag;
	unsigned int	pduLength;
	unsigned char 	*pdu;
	metadata metaData;

};

struct finsCtrlFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	/* Special fields for control frames depending on the Opcode */
	unsigned int paramterID;
	void *paramterValue;
	struct tableRecord *replyRecord;

};





struct finsFrame
{

/* Common Fields between data and control */
unsigned char dataOrCtrl;
struct destinationList destinationID;
union
{
struct finsDataFrame dataFrame;
struct finsCtrlFrame ctrlFrame;
};

};



struct readRequestFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	unsigned int paramterID;
};

struct readReplyFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	void *paramterValue;
};

struct writeRequestFrame
{
	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

unsigned int paramterID;
void *paramterValue;
};


struct writeConfirmationFrame
{
	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

};

struct queryRequestFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

};



struct queryReplyFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	struct tableRecord *replyRecord;
};



#endif /* FINSTYPES_H_ */
