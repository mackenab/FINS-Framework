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
 * + wifistub is renamed to be ETHERSTUB and its ID became INTERFACE_ID
 * + Static MetaData is replaced with The fully functioning MetaData
 * based on the MetaDate Library
 * @author: Abdallah Abdallah
 */

#ifndef FINSTYPES_H_
#define FINSTYPES_H_

//Include MetaData header File
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "finsdebug.h"
#include "metadata.h"

//Definition of the modules IDs
#define SWITCH_ID 0
#define DAEMON_ID 1
#define INTERFACE_ID 2
#define IPV4_ID 3
#define ARP_ID 4
#define UDP_ID 5
#define TCP_ID 6
#define ICMP_ID 7
#define RTM_ID 8
#define LOGGER_ID 9
#define MAX_ID 10

#define IP_ID IPV4_ID //TODO remove?
//control message types - finsCtrlFrame.opcode values
#define CTRL_ALERT 	0			// "pushed" messages; not error messages
#define CTRL_ALERT_REPLY 1
#define CTRL_READ_PARAM	2		// read module parameter message
#define CTRL_READ_PARAM_REPLY 3	// reply to the above message; contains param value
#define CTRL_SET_PARAM 4		// set module param message
#define CTRL_SET_PARAM_REPLY 5	// reply to the above message; contains ACK
#define CTRL_EXEC 6				// telling a module to do something; module dependent
#define CTRL_EXEC_REPLY 7		// a reply to the above, if necessary
#define CTRL_ERROR 8 			// error message; ICMP msg for example
//frame type - finsframe.dataOrCtrl values
#define DATA 0
#define CONTROL 1

//frame direction - finsDataFrame.directionFlag values
#define UP 0	// ingress network data (interface -> app)
#define DOWN 1	// egress network data (app -> interface)
//this should be removed -MST
struct destinationList {
	uint8_t id;
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
	uint8_t directionFlag; // ingress or egress network data; see above
	uint32_t pduLength; // length of pdu array
	uint8_t *pdu; // data!
};

//unsigned int ctrl_serial_count = 0;

struct finsCtrlFrame {
	/* only for FINS control frames */
	uint8_t senderID; //ID of the src module
	uint32_t serial_num; //unique identifier among all FCF, see gen_control_serial_num()

	uint16_t opcode; //type of control message, see CTRL_* values
	uint32_t param_id; //the type of call for EXEC/ERROR/ALERT, param for READ/SET,
	uint32_t ret_val; // NACK (0) / ACK (1)

	uint32_t data_len;
	uint8_t *data;

/* Special fields for control frames depending on the Opcode */
// if using a struct for this, define elsewhere
// such as ICMP data information, define in ICMP
//struct tableRecord *replyRecord; //TODO remove?
};

struct finsFrame {
	/* Common Fields between data and control */
	uint8_t dataOrCtrl; // data frame or control frame; use #def values above
	struct destinationList destinationID; // destination module ID
	metadata *metaData; // metadata
	union {
		struct finsDataFrame dataFrame;
		struct finsCtrlFrame ctrlFrame;
	};

};

#define secure_malloc(len) secure_malloc_full(__FILE__, __FUNCTION__, __LINE__, len)
void *secure_malloc_full(const char *file, const char *func, int line, uint32_t len);

#define secure_sem_wait(sem) secure_sem_wait_full(__FILE__, __FUNCTION__, __LINE__, sem)
void secure_sem_wait_full(const char *file, const char *func, int line, sem_t *sem);

#define secure_metadata_readFromElement(params, target, value) secure_metadata_readFromElement_full(__FILE__, __FUNCTION__, __LINE__, params, target, value)
void secure_metadata_readFromElement_full(const char *file, const char *func, int line, metadata *params, const char *target, void *value);

#define secure_metadata_writeToElement(params, target, value, type) secure_metadata_writeToElement_full(__FILE__, __FUNCTION__, __LINE__, params, target, value, type)
void secure_metadata_writeToElement_full(const char *file, const char *func, int line, metadata *params, char *target, void *value, int type);

#define secure_pthread_create(thread, attr, routine, arg) secure_pthread_create_full(__FILE__, __FUNCTION__, __LINE__, thread, attr, routine, arg)
void secure_pthread_create_full(const char *file, const char *func, int line, pthread_t *thread, pthread_attr_t *attr, void *(*routine)(void *), void *arg);

void uint32_increase(uint32_t *data, uint32_t value, uint32_t max);
void uint32_decrease(uint32_t *data, uint32_t value);

struct data_buf {
	uint32_t len;
	uint8_t *data;
};

struct list_node {
	struct list_node *next;
	struct list_node *prev;
	uint8_t *data;
};

struct linked_list {
	uint32_t max;
	uint32_t len;
	struct list_node *front;
	struct list_node *end;
};

//for use as library, not internal
struct linked_list *list_create(uint32_t max);
void list_prepend(struct linked_list *list, uint8_t *data);
void list_append(struct linked_list *list, uint8_t *data);
void list_insert(struct linked_list *list, uint8_t *data, uint8_t *prev);
int list_check(struct linked_list *list);
int list_contains(struct linked_list *list, uint8_t *data);
uint8_t *list_remove_front(struct linked_list *list);
void list_remove(struct linked_list *list, uint8_t *data);
int list_is_empty(struct linked_list *list); //change some to inline?
int list_is_full(struct linked_list *list);
int list_has_space(struct linked_list *list);
uint32_t list_space(struct linked_list *list);
void list_free(struct linked_list *list);

int list_add(struct linked_list *list, uint8_t *data, int(*comparer)(uint8_t *data1, uint8_t *data2));
uint8_t *list_find(struct linked_list *list, int(*equal)(uint8_t *data));
void list_for_each(struct linked_list *list, void(*apply)(uint8_t *data));

uint32_t gen_control_serial_num(void);

struct finsFrame * buildFinsFrame(void);

void print_finsFrame(struct finsFrame *fins_in);

void copy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src);

struct finsFrame *cloneFinsFrame(struct finsFrame *ff);

int freeFinsFrame(struct finsFrame *f);

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

#ifndef IP4_ADR_P2H
/* macro to convert IPv4 address from human readable format Presentation to long int in Host format*/
#define IP4_ADR_P2H(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))
#endif /* IP4_ADR_P2N */

void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_hex_block(const u_char *payload, int len);

#endif /* FINSTYPES_H_ */
