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
#define NONE_INDEX 0
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
#define DIR_UP 0	// ingress network data (interface -> app)
#define DIR_DOWN 1	// egress network data (app -> interface)
//this should be removed -MST
struct destinationList {
	uint8_t id;
	struct destinationList *next;
};

/* this needs a comment */
struct tableRecord {
	uint8_t sourceID;
	uint8_t directionFlag;
	uint8_t vci;
	uint8_t destinationID;
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
	uint8_t sender_id; //ID of the src module
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
	//struct destinationList destinationID; // destination module ID
	uint32_t destinationID;
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

#define secure_metadata_readFromElement(meta, target, value) secure_metadata_readFromElement_full(__FILE__, __FUNCTION__, __LINE__, meta, target, value)
void secure_metadata_readFromElement_full(const char *file, const char *func, int line, metadata *meta, const char *target, void *value);

#define secure_metadata_writeToElement(meta, target, value, type) secure_metadata_writeToElement_full(__FILE__, __FUNCTION__, __LINE__, meta, target, value, type)
void secure_metadata_writeToElement_full(const char *file, const char *func, int line, metadata *meta, char *target, void *value, int type);

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

#define list_prepend(list, data) list_prepend_full(list, (uint8_t *)data)
void list_prepend_full(struct linked_list *list, uint8_t *data);

#define list_append(list, data) list_append_full(list, (uint8_t *)data)
void list_append_full(struct linked_list *list, uint8_t *data);

#define list_insert(list, data, prev) list_insert_full(list, (uint8_t *)data, (uint8_t *)prev)
void list_insert_full(struct linked_list *list, uint8_t *data, uint8_t *prev);
int list_check(struct linked_list *list);
uint8_t *list_look(struct linked_list *list, uint32_t index);

#define list_contains(list, data) list_contains_full(list, (uint8_t *)data)
int list_contains_full(struct linked_list *list, uint8_t *data);
uint8_t *list_remove_front(struct linked_list *list);

#define list_remove(list, data) list_remove_full(list, (uint8_t *)data)
void list_remove_full(struct linked_list *list, uint8_t *data);
int list_is_empty(struct linked_list *list); //change some to inline?
int list_is_full(struct linked_list *list);
int list_has_space(struct linked_list *list);
uint32_t list_space(struct linked_list *list);

typedef int (*comparer_type)(uint8_t *data1, uint8_t *data2);
#define list_add(list, data, comparer) list_add_full(list, (uint8_t *)data, (comparer_type)comparer)
int list_add_full(struct linked_list *list, uint8_t *data, int (*comparer)(uint8_t *data1, uint8_t *data2));

typedef int (*equal_type)(uint8_t *data);
#define list_find(list, equal) list_find_full(list, (equal_type)equal)
uint8_t *list_find_full(struct linked_list *list, int (*equal)(uint8_t *data));

typedef int (*equal1_type)(uint8_t *data, uint8_t *param);
#define list_find1(list, equal, param) list_find1_full(list, (equal1_type)equal, (uint8_t *)param)
uint8_t *list_find1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param);

typedef int (*equal2_type)(uint8_t *data, uint8_t *param1, uint8_t param2);
#define list_find2(list, equal, param1, param2) list_find2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2)
uint8_t *list_find2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2);

typedef void (*apply_type)(uint8_t *data);
#define list_for_each(list, apply) list_for_each_full(list, (apply_type)apply)
void list_for_each_full(struct linked_list *list, void (*apply)(uint8_t *data));

typedef void (*apply1_type)(uint8_t *data, uint8_t *param);
#define list_for_each1(list, apply, param) list_for_each1_full(list, (apply1_type)apply, (uint8_t *)param)
void list_for_each1_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param), uint8_t *param);

typedef void (*apply2_type)(uint8_t *data, uint8_t *param1, uint8_t *param2);
#define list_for_each2(list, apply, param1, param2) list_for_each2_full(list, (apply2_type)apply, (uint8_t *)param1, (uint8_t *)param2)
void list_for_each2_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2);

typedef uint8_t *(*copy_type)(uint8_t *data);
#define list_filter(list, equal, copy) list_filter_full(list, (equal_type)equal, (copy_type)copy)
struct linked_list *list_filter_full(struct linked_list *list, int (*equal)(uint8_t *data), uint8_t *(*copy)(uint8_t *data));

#define list_filter1(list, equal, param, copy) list_filter1_full(list, (equal1_type)equal, (uint8_t *)param, (copy_type)copy)
struct linked_list *list_filter1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param, uint8_t *(*copy)(uint8_t *data));

#define list_filter2(list, equal, param1, param2, copy) list_filter2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2, (copy_type)copy)
struct linked_list *list_filter2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2,
		uint8_t *(*copy)(uint8_t *data));

typedef void (*release_type)(uint8_t *data);
#define list_free(list, release) list_free_full(list, (release_type)release)
void list_free_full(struct linked_list *list, void (*release)(uint8_t *data));

uint32_t gen_control_serial_num(void);
struct finsFrame *buildFinsFrame(void);
void print_finsFrame(struct finsFrame *fins_in);
void copy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src);
struct finsFrame *cloneFinsFrame(struct finsFrame *ff);
int freeFinsFrame(struct finsFrame *f);

/* needed function defs */
int serializeCtrlFrame(struct finsFrame *, uint8_t **);
/* serializes a fins control frame for transmission to an external process
 * - pass it the frame (finsFrame) and it will fill in the pointer to the frame, uchar*
 * -- and return the length of the array (return int);
 * - this is used to send a control frame to an external app
 * - we can't send pointers outside of a process
 * - called by the sender
 */

struct finsFrame *unserializeCtrlFrame(uint8_t *, int);
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
void print_hex(uint32_t msg_len, uint8_t *msg_pt);

#include <net/if.h>
#include <netinet/in.h>

#define MAX_INTERFACES 30
#define MAX_FAMILIES 64
#define MAX_ADDRESSES 8192
#define MAX_ROUTES 8192

struct addr_record { //for a particular address
	uint32_t if_index;
	uint32_t family;
	struct sockaddr_storage ip; //ip
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	struct sockaddr_storage bdc; //broadcast
	struct sockaddr_storage dst; //end-to-end dst
//union {}; //bdc & dst can be unioned, not done for simplicity
};

void set_addr4(struct sockaddr_storage *addr, uint32_t val);
int addr_is_addr4(struct addr_record *addr);
void set_addr6(struct sockaddr_storage *addr, uint32_t val);
int addr_is_addr6(struct addr_record *addr);

struct if_record { //for an interface
	//inherent
	uint32_t index;
	uint8_t name[IFNAMSIZ]; //SIOCGIFNAME
	uint64_t mac; //SIOCGIFHWADDR
	uint16_t type; //eth/Wifi

	//changeable
	uint8_t status; //up/down
	uint32_t mtu; //SIOCGIFMTU
	uint32_t flags; //TODO use? //SIOCGIFFLAGS

	struct linked_list *addr_list;
};
int ifr_index_test(struct if_record *ifr, uint32_t *index);
void ifr_free(struct if_record *ifr);

struct route_record {
	uint32_t if_index;
	uint32_t family;
	struct sockaddr_storage dst; //end-to-end dst
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	struct sockaddr_storage ip; //ip //TODO remove?

	uint32_t metric; //TODO remove?
	uint32_t timeout; //TODO remove?
	struct timeval *stamp;
};

struct cache_record {
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	struct sockaddr_storage gw;
	uint32_t if_index;

	uint32_t metric; //TODO remove?
	uint32_t timeout; //TODO remove?
	struct timeval *stamp;
};

struct envi_record {
	uint32_t any_ip_addr; //change to sockaddr_storage? or any_ip_addr & any_ip_addr6?
	//struct if_record if_list[MAX_INTERFACES];
	struct linked_list *if_list; //list of if_record, for a list of interfaces
	struct if_record *if_loopback;
	struct if_record *if_main;
	//struct linked_list *addr_list; //list of addr_record, for interfaces

	struct linked_list *route_list; //list of addr_record, for a routing table
//struct linked_list *route_cache; //TODO add in routing cache?
//struct linked_list *foward_list; //TODO add in forwarding table?
//struct linked_list *library_list; //list of open libraries
//struct linked_list *module_list; //list of modules
//struct linked_list *link_list;
};

#endif /* FINSTYPES_H_ */
