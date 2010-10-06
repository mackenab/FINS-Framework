/**@file test_arp.h
 *@brief this files contains all prototypes for the functions to test an ARP module
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */

#include "finstypes.h"
#include <inttypes.h>

void gen_neighbor_list(char* fileName);

void mimic_net_request(uint32_t IP_sender_addrs, uint64_t MAC_sender_addrs, struct ARP_message *request_ARP);

void mimic_net_reply(struct finsFrame *request, struct finsFrame *reply_fins_ptr);

struct node* read_neighbor_list(char* fileName);

void init_recordsARP(char *fileName);

void fins_to_fins(struct finsFrame *request_fins_ptr, struct finsFrame *reply_fins_ptr);

void send_receive_update(char *fileName);

uint32_t read_IP_addrs();


