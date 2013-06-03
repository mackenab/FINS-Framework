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
#include <unistd.h>

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
#define FF_NONE 	0
#define FF_DATA 	1
#define FF_CONTROL 	2

//frame direction - finsDataFrame.directionFlag values
#define DIR_NONE 	0
#define DIR_UP 		1	// ingress network data (interface -> app)
#define DIR_DOWN 	2	// egress network data (app -> interface)
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
#define FCF_TRUE 1
#define FCF_FALSE 0

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

//NOTE: this structure is meant for only internal use
struct list_node {
	struct list_node *next;
	struct list_node *prev;
	uint8_t *data;
};

//vvvvvvvvvvvvvvvvv Linked list data structure, meant for external use as a library
#define LIST_TRUE 1
#define LIST_FALSE 0

struct linked_list {
	uint32_t max;
	uint32_t len;
	struct list_node *front;
	struct list_node *end;
};

//A test that always returns true
int true_test(uint8_t *data);

//A test that always returns false
int false_test(uint8_t *data);

//A function (apply/release) that does nothing
void nop_func(uint8_t *data);

//<equal> should return:
//1 if equal
//0 if not
typedef int (*equal_type)(uint8_t *data);
typedef int (*equal1_type)(uint8_t *data, uint8_t *param);
typedef int (*equal2_type)(uint8_t *data, uint8_t *param1, uint8_t *param2);
typedef int (*equal4_type)(uint8_t *data, uint8_t *param1, uint8_t *param2, uint8_t *param3, uint8_t *param4);

//<clone> should return a pointer to a copied version of an element, returning the same pointer is permissible but must be handled
typedef uint8_t *(*clone_type)(uint8_t *data);

//<comparer> should return:
//-1 = less than, goes before
//0 = problem don't insert
//1 = greater than, goes after, if is equal but want put in use this
typedef int (*comparer_type)(uint8_t *data1, uint8_t *data2);

//<apply> should do something on the element, removing an element in <apply> is permissible
typedef void (*apply_type)(uint8_t *data);
typedef void (*apply1_type)(uint8_t *data, uint8_t *param);
typedef void (*apply2_type)(uint8_t *data, uint8_t *param1, uint8_t *param2);

//<release> should free the data structure in the element as well as any subcomponents
typedef void (*release_type)(uint8_t *data);

//Return a malloc'd linked_list with 0 elements, & a maximum of <max>
struct linked_list *list_create(uint32_t max);

//Prepend the pointer to the front of the list
#define list_prepend(list, data) list_prepend_full(list, (uint8_t *)data)
void list_prepend_full(struct linked_list *list, uint8_t *data);

//Append the pointer to the end of the list
#define list_append(list, data) list_append_full(list, (uint8_t *)data)
void list_append_full(struct linked_list *list, uint8_t *data);

//Insert the pointer after the pointer given by <prev>
#define list_insert(list, data, prev) list_insert_full(list, (uint8_t *)data, (uint8_t *)prev)
void list_insert_full(struct linked_list *list, uint8_t *data, uint8_t *prev);

//Iterate through the list to check that the total length matches the number of elements
int list_check(struct linked_list *list);

//Return the pointer at the <index> location in the list
uint8_t *list_look(struct linked_list *list, uint32_t index);

//Return true if the list contains the pointer data
#define list_contains(list, data) list_contains_full(list, (uint8_t *)data)
int list_contains_full(struct linked_list *list, uint8_t *data);

//Remove the first element of the list & return it
uint8_t *list_remove_front(struct linked_list *list);

//Remove first instance of the specific pointer <data> from the list
#define list_remove(list, data) list_remove_full(list, (uint8_t *)data)
void list_remove_full(struct linked_list *list, uint8_t *data);

//Iterate through <list> and remove elements for which <equal> returns true, add those elements to a new list that is returned.
//<equal> should return:
//1 if equal
//0 if not
#define list_remove_all(list, equal) list_remove_all_full(list, (equal_type)equal)
struct linked_list *list_remove_all_full(struct linked_list *list, int (*equal)(uint8_t *data));

//See list_remove_all()
#define list_remove_all1(list, equal, param) list_remove_all1_full(list, (equal1_type)equal, (uint8_t *)param)
struct linked_list *list_remove_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param);

//See list_remove_all()
#define list_remove_all2(list, equal, param1, param2) list_remove_all2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2)
struct linked_list *list_remove_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1,
		uint8_t *param2);

//Return true if the list has no elements
int list_is_empty(struct linked_list *list); //change some to inline?

//Return true if the list has reached the limit of elements given by list->max
int list_is_full(struct linked_list *list);

//Return true if the list has space for another element
int list_has_space(struct linked_list *list);

//Return the number of elements the list can add before reaching max
uint32_t list_space(struct linked_list *list);

//Clone the list and return the new list
//<clone> should return a pointer to a cloned version of an element, returning the same pointer is permissible but must be handled
#define list_clone(list, clone) list_clone_full(list, (clone_type)clone)
struct linked_list *list_clone_full(struct linked_list *list, uint8_t *(*clone)(uint8_t *data));

//Append as many elements of <list2> to <list1> up to its max, return true if all of <list2> joined to <list1>
int list_join(struct linked_list *list1, struct linked_list *list2);

//Remove all elements of <list> after <index> & return rest as separate list
struct linked_list *list_split(struct linked_list *list, uint32_t index);

//Add the pointer <data> to the list, using the comparer, returns true if inserts, false if problem
//<comparer> should return:
//-1 = less than, goes before
//0 = problem don't insert
//1 = greater than, goes after, if is equal but want put in use this
#define list_add(list, data, comparer) list_add_full(list, (uint8_t *)data, (comparer_type)comparer)
int list_add_full(struct linked_list *list, uint8_t *data, int (*comparer)(uint8_t *data1, uint8_t *data2));

//Finds & returns the first element that satisfies <equal>
//<equal> should return:
//1 if equal
//0 if not
#define list_find(list, equal) list_find_full(list, (equal_type)equal)
uint8_t *list_find_full(struct linked_list *list, int (*equal)(uint8_t *data));

//See list_find()
#define list_find1(list, equal, param) list_find1_full(list, (equal1_type)equal, (uint8_t *)param)
uint8_t *list_find1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param);

//See list_find()
#define list_find2(list, equal, param1, param2) list_find2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2)
uint8_t *list_find2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2);

//See list_find()
#define list_find4(list, equal, param1, param2, param3, param4) list_find4_full(list, (equal4_type)equal, (uint8_t *)param1, (uint8_t *)param2, (uint8_t *)param3, (uint8_t *)param4)
uint8_t *list_find4_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2, uint8_t *param3, uint8_t *param4),
		uint8_t *param1, uint8_t *param2, uint8_t *param3, uint8_t *param4);

//Creates a new list and returns the pointers for which <equal> returns true
//<equal> should return:
//1 if equal
//0 if not
#define list_find_all(list, equal) list_find_all_full(list, (equal_type)equal)
struct linked_list *list_find_all_full(struct linked_list *list, int (*equal)(uint8_t *data));

//See list_find_all()
#define list_find_all1(list, equal, param) list_find_all1_full(list, (equal1_type)equal, (uint8_t *)param)
struct linked_list *list_find_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param);

//See list_find_all()
#define list_find_all2(list, equal, param1, param2) list_find_all2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2)
struct linked_list *list_find_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1,
		uint8_t *param2);

//Finds & returns the last element that satisfies <equal>
//<equal> should return:
//1 if equal
//0 if not
#define list_find_last(list, equal) list_find_last_full(list, (equal_type)equal)
uint8_t *list_find_last_full(struct linked_list *list, int (*equal)(uint8_t *data));

//See list_find_last()
#define list_find_last1(list, equal, param) list_find_last1_full(list, (equal1_type)equal, (uint8_t *)param)
uint8_t *list_find_last1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param);

//See list_find_last()
#define list_find_last2(list, equal, param1, param2) list_find_last2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2)
uint8_t *list_find_last2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2);

//Iterates through list and calls <apply> on each element
//<apply> should do something on the element, removing an element in <apply> is permissible
#define list_for_each(list, apply) list_for_each_full(list, (apply_type)apply)
void list_for_each_full(struct linked_list *list, void (*apply)(uint8_t *data));

//See list_for_each()
#define list_for_each1(list, apply, param) list_for_each1_full(list, (apply1_type)apply, (uint8_t *)param)
void list_for_each1_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param), uint8_t *param);

//See list_for_each()
#define list_for_each2(list, apply, param1, param2) list_for_each2_full(list, (apply2_type)apply, (uint8_t *)param1, (uint8_t *)param2)
void list_for_each2_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2);

//Return a new list containing copies of each element that <equal> returns true for
//<equal> should return:
//1 if equal
//0 if not
//<clone> should return a pointer to a copied version of an element, returning the same pointer is permissible but must be handled
#define list_filter(list, equal, clone) list_filter_full(list, (equal_type)equal, (clone_type)clone)
struct linked_list *list_filter_full(struct linked_list *list, int (*equal)(uint8_t *data), uint8_t *(*clone)(uint8_t *data));

//See list_filter()
#define list_filter1(list, equal, param, clone) list_filter1_full(list, (equal1_type)equal, (uint8_t *)param, (clone_type)clone)
struct linked_list *list_filter1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param, uint8_t *(*clone)(uint8_t *data));

//See list_filter()
#define list_filter2(list, equal, param1, param2, clone) list_filter2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2, (clone_type)clone)
struct linked_list *list_filter2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2,
		uint8_t *(*clone)(uint8_t *data));

//Iterate and free the elements of <list>, afterwards free the list
//<release> should free the data structure in the element as well as any subcomponents
#define list_free(list, release) list_free_full(list, (release_type)release)
void list_free_full(struct linked_list *list, void (*release)(uint8_t *data));

//Iterate and free the elements of <list> that equal returns true for
//<equal> should return:
//1 if equal
//0 if not
//<release> should free the data structure in the element as well as any subcomponents
#define list_free_all(list, equal, release) list_free_all_full(list, (equal_type)equal, (release_type)release)
void list_free_all_full(struct linked_list *list, int (*equal)(uint8_t *data), void (*release)(uint8_t *data));

//See list_free_all()
#define list_free_all1(list, equal, param, release) list_free_all1_full(list, (equal1_type)equal, (uint8_t *)param, (release_type)release)
void list_free_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param, void (*release)(uint8_t *data));

//See list_free_all()
#define list_free_all2(list, equal, param1, param2, release) list_free_all2_full(list, (equal2_type)equal, (uint8_t *)param1, (uint8_t *)param2, (release_type)release)
void list_free_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2,
		void (*release)(uint8_t *data));

//^^^^^^^^^^^^^^^^^ End of linked_list data structure library

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
#define MAX_ADDRESSES 1024
#define MAX_ROUTES 1024

struct addr_record { //for a particular address
	int32_t if_index;
	uint32_t family;
	struct sockaddr_storage ip; //ip
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	struct sockaddr_storage bdc; //broadcast
	struct sockaddr_storage dst; //end-to-end dst
};
struct addr_record *addr_clone(struct addr_record *addr);
int addr_is_v4(struct addr_record *addr);
int addr_ipv4_test(struct addr_record *addr, uint32_t *ip);
int addr_bdcv4_test(struct addr_record *addr, uint32_t *ip);
int addr_is_v6(struct addr_record *addr);
int addr_ipv6_test(struct addr_record *addr, uint32_t *ip); //TODO
int addr_bdcv6_test(struct addr_record *addr, uint32_t *ip); //TODO

void addr4_set_ip(struct sockaddr_storage *addr, uint32_t ip);
uint32_t addr4_get_ip(struct sockaddr_storage *addr);
void addr4_set_port(struct sockaddr_storage *addr, uint16_t port);
uint16_t addr4_get_port(struct sockaddr_storage *addr);
void addr6_set_ip(struct sockaddr_storage *addr, uint32_t ip); //TODO
uint8_t *addr6_get_ip(struct sockaddr_storage *addr); //TODO

struct if_record { //for an interface
	//inherent
	int32_t index;
	uint8_t name[IFNAMSIZ]; //SIOCGIFNAME
	uint64_t mac; //SIOCGIFHWADDR
	uint16_t type; //1=eth, 2=Wifi

	//changeable
	uint8_t status; //1=infrastructure, 2=adhoc modes //TODO rename to mode
	uint32_t mtu; //SIOCGIFMTU
	uint32_t flags; //TODO use? //SIOCGIFFLAGS

	struct linked_list *addr_list;
};
struct if_record *ifr_clone(struct if_record *ifr);
int ifr_running_test(struct if_record *ifr);
int ifr_index_test(struct if_record *ifr, int32_t *index);
int ifr_name_test(struct if_record *ifr, uint8_t *name);
void ifr_total_test(struct if_record *ifr, uint32_t *total);
int ifr_ipv4_test(struct if_record *ifr, uint32_t *ip);
int ifr_ipv6_test(struct if_record *ifr, uint32_t *ip); //TODO
void ifr_free(struct if_record *ifr);

struct route_record {
	int32_t if_index;
	uint32_t family;
	struct sockaddr_storage dst; //end-to-end dst
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	uint32_t metric;
	uint32_t timeout;
	struct timeval *stamp;
};
int route_is_addr4(struct route_record *route);
int route_is_addr6(struct route_record *route);
struct route_record *route_clone(struct route_record *route);

struct cache_record {
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	struct sockaddr_storage gw;
	int32_t if_index;

	uint32_t metric; //TODO remove?
	uint32_t timeout; //TODO remove?
	struct timeval *stamp;
};

struct envi_record {
	struct linked_list *if_list; //list of if_record, for a list of interfaces
	struct if_record *if_loopback;
	struct if_record *if_main;
	//struct linked_list *addr_list; //list of addr_record, for interfaces

	struct linked_list *route_list; //list of route_record, for a routing table
//struct linked_list *route_cache; //TODO add in routing cache?
//struct linked_list *foward_list; //TODO add in forwarding table?
};

#endif /* FINSTYPES_H_ */
