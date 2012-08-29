/**
 * @file finstypes.h
 *
 * @date July 2, 2010
 * @brief has all the constants definitions and the FDF/FCF , and FinsFrame format.
 * @version 2
 * @version 3 "September 25,2010"
 * +fix the define values to be into capital letters
 * +The destination ID has been modified to be list of destination IDs
 * which is implemented as a linked list grows dynamically
 * + wifistub is renamed to be ETHERSTUB and its ID became ETHERSTUBID
 * + Static MetaData is replaced with The fully functioning MetaData
 * based on the MetaDate Library
 * @author: Abdallah Abdallah
 */

#ifndef FINSTYPES_H_
#define FINSTYPES_H_

/* Include MetaData header File */
#include "metadata.h"		//guicomm need this local
/* Definition of the modules IDs */
#define ARPID 66
#define SOCKETSTUBID 55
#define UDPID 44
#define TCPID 33
#define ICMPID 77
#define IPID 22
#define RTMID 88
#define ETHERSTUBID 11
#define SWITCHID 00

#define IPV4ID IPID
#define DAEMONID SOCKETSTUBID

//following block excluded in vt_mark's code, temp. included for ARP code
/* Definition of the possible Opcodes */
/*
 #define READREQUEST 111
 #define READREPLY 222
 #define WRITEREQUEST 333
 #define WRITECONF 444
 #define QUERYREQUEST 555
 #define QUERYREPLY 666
 */

/* control message types - finsCtrlFrame.opcode values */
#define CTRL_ALERT 	0			// "pushed" messages; not error messages
#define CTRL_ALERT_REPLY 1
#define CTRL_READ_PARAM	2		// read module parameter message
#define CTRL_READ_PARAM_REPLY 3	// reply to the above message; contains param value
#define CTRL_SET_PARAM 4		// set module param message
#define CTRL_SET_PARAM_REPLY 5	// reply to the above message; contains ACK
#define CTRL_EXEC 6				// telling a module to do something; module dependent
#define CTRL_EXEC_REPLY 7		// a reply to the above, if necessary
#define CTRL_ERROR 8 			// error message; ICMP msg for example
/* frame type - finsframe.dataOrCtrl values */
#define DATA 0
#define CONTROL 1

/* frame direction - finsDataFrame.directionFlag values */
#define UP 0	// ingress network data (interface -> app)
#define DOWN 1	// egress network data (app -> interface)
/* this should be removed -MST */
struct destinationList {
	unsigned char id;
	struct destinationList *next;
};

/* this needs a comment */

struct tableRecord {
	unsigned char sourceID;
	unsigned char directionFlag;
	unsigned char vci;
	unsigned char destinationID;
	struct tableRecord *next;
};

struct finsDataFrame {
	/* Only for FINS DATA FRAMES */
	unsigned char directionFlag; // ingress or egress network data; see above
	unsigned int pduLength; // length of pdu array
	unsigned char *pdu; // data!
};

struct finsCtrlFrame {
	/* only for FINS control frames */
	unsigned char senderID; // ID of the src module
	unsigned short int opcode; // type of control message, see CTRL_* values
	unsigned int serialNum; // unique identifier, varies by msg type

	unsigned char * name; // parameter/function/error name
	void * data; // pointer to relevant data; msg type dependent
	// if using a struct for this, define elsewhere
	// such as ICMP data information, define in ICMP
	/* Special fields for control frames depending on the Opcode */

	unsigned int paramterID;
	void *paramterValue;
	unsigned int paramterLen;

	struct tableRecord *replyRecord;
};

struct finsFrame {

	/* Common Fields between data and control */
	unsigned char dataOrCtrl; // data frame or control frame; use #def values above
	struct destinationList destinationID; // destination module ID
	metadata *metaData; // metadata
	union {
		struct finsDataFrame dataFrame;
		struct finsCtrlFrame ctrlFrame;
	};

};

/* I don't think we're going to need this. --MST */
//struct readRequestFrame {
//
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//	unsigned int paramterID;
//
//};
//
//struct readReplyFrame {
//
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//	void *paramterValue;
//
//};
//
//struct writeRequestFrame {
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//	unsigned int paramterID;
//	void *paramterValue;
//
//};
//
//struct writeConfirmationFrame {
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//};
//
//struct queryRequestFrame {
//
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//};
//
//struct queryReplyFrame {
//
//	/* only for FINS control frames */
//	unsigned char senderID;
//	unsigned short int opcode;
//	unsigned int serialNum;
//
//	struct tableRecord *replyRecord;
//};
/* needed function defs */
int serializeCtrlFrame(struct finsFrame *, unsigned char **);
/* serializes a fins control frame for transmission to an external process
 * - pass it the frame (finsFrame) and it will fill in the pointer to the frame, uchar*
 * -- and return the length of the array (return int);
 * - this is used to send a control frame to an external app
 * - we can't send pointers outside of a process
 * - called by the sender
 */

struct finsFrame * unserializeCtrlFrame(unsigned char *, int);
/* does the opposite of serializeCtrlFrame; used to reconstruct a controlFrame
 * - pass it the byte array and the length and it will give you a pointer to the
 * -- struct.
 * - called by the receiver
 */

typedef enum {
	SS_FREE = 0, /* not allocated                */
	SS_UNCONNECTED, /* unconnected to any socket    */
	SS_CONNECTING, /* in process of connecting     */
	SS_CONNECTED, /* connected to socket          */
	SS_DISCONNECTING
/* in process of disconnecting  */
} socket_state;

#ifndef IP4_ADR_P2H
/* macro to convert IPv4 address from human readable format Presentation to long int in Host format*/
#define IP4_ADR_P2H(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))
#endif /* IP4_ADR_P2N */

#ifndef ntohll
#define ntohll(x)
#endif

#ifndef htonll
#define htonll(x)
#endif

#endif /* FINSTYPES_H_ */
