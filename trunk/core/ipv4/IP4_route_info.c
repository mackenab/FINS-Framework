#include "ipv4.h"

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/socket.h>
#endif

extern uint32_t my_host_ip_addr;
extern uint32_t my_host_mask;
extern uint32_t loopback_ip_addr;
//uint32_t loopback_mask;
extern uint32_t any_ip_addr;

void IP4_print_routing_table(struct ip4_routing_table * table_pointer) {
	struct ip4_routing_table *current_pointer;
	current_pointer = table_pointer;
	printf("Routing table:\n");
	printf("Destination\tGateway\t\tMask\tMetric\tInterface\n");
	while (current_pointer != NULL) {
		printf("%u.%u.%u.%u \t", (unsigned int) current_pointer->dst >> 24, (unsigned int) (current_pointer->dst >> 16) & 0xFF,
				(unsigned int) (current_pointer->dst >> 8) & 0xFF, (unsigned int) current_pointer->dst & 0xFF);
		printf("%u.%u.%u.%u \t", (unsigned int) current_pointer->gw >> 24, (unsigned int) (current_pointer->gw >> 16) & 0xFF,
				(unsigned int) (current_pointer->gw >> 8) & 0xFF, (unsigned int) current_pointer->gw & 0xFF);
		printf("%u \t", (unsigned int) current_pointer->mask);
		printf("%u \t", current_pointer->metric);
		printf("%u", current_pointer->interface);
		printf("\n");
		current_pointer = current_pointer->next_entry;
	}
}

struct ip4_routing_table * IP4_sort_routing_table(struct ip4_routing_table * table_pointer) {
	if (table_pointer == NULL) {
		return NULL;
	}
	struct ip4_routing_table *first = table_pointer;
	struct ip4_routing_table *previous;
	struct ip4_routing_table *current;
	int swapped = 1;
	while (swapped) {
		swapped = 0;
		previous = NULL;
		current = table_pointer;
		while ((current != NULL) && (current->next_entry != NULL)) {
			//uncomment these after kernel stuff stable
			//PRINT_DEBUG("masks (curr, next): %d %d",(int)current->mask, (int)current->next_entry->mask);
			if (current->mask < current->next_entry->mask) {
				//PRINT_DEBUG("mask < mask");
				if (previous == NULL) {
					//PRINT_DEBUG("prev  ==  null");
					first = current->next_entry;
					current->next_entry = current->next_entry->next_entry;
					first->next_entry = current;
				} else {
					//PRINT_DEBUG("prev  !=  null");
					previous->next_entry = current->next_entry;
					current->next_entry = current->next_entry->next_entry;
					previous->next_entry->next_entry = current;
				}
				swapped = 1;
			}
			previous = current;
			current = current->next_entry;
		}
	} PRINT_DEBUG("IP4_sort_routing_table end");
	return (first);

}

struct ip4_routing_table * parse_nlmsg(struct nlmsghdr* msg) {
	char dst_temp[IP4_ALEN];
	char gw_temp[IP4_ALEN];
	unsigned int priority;
	unsigned int interface;
	struct ip4_routing_table *table_pointer = NULL;

	switch (msg->nlmsg_type) {
	case NLMSG_ERROR: {
		struct nlmsgerr* errorMsg = (struct nlmsgerr*) NLMSG_DATA(msg);
		PRINT_DEBUG("recvd NLMSG_ERROR error seq:%d code:%d...", msg->nlmsg_seq, errorMsg->error);
		break;
	}
	case RTM_NEWROUTE: {
		struct rtmsg* rtm = (struct rtmsg*) NLMSG_DATA(msg);
		struct rtattr* rta = RTM_RTA(rtm);
		int rtaLen = msg->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
		if (rtm->rtm_type == RTN_UNICAST) // don't consider local, broadcast and unreachable routes
		{
			table_pointer = (struct ip4_routing_table*) secure_malloc(sizeof(struct ip4_routing_table));
			memset(table_pointer, 0, sizeof(struct ip4_routing_table)); // zero the routing table entry data
			for (; RTA_OK(rta, rtaLen); rta = RTA_NEXT(rta, rtaLen)) {
				switch (rta->rta_type) {
				case RTA_DST: //destination
					table_pointer->mask = rtm->rtm_dst_len;
					memcpy(dst_temp, RTA_DATA(rta), IP4_ALEN);
					//PRINT_DEBUG("received RTA_DST");
					PRINT_DEBUG("dst_str = %u.%u.%u.%u", dst_temp[0] & 0xFF, dst_temp[1] & 0xFF, dst_temp[2] & 0xFF, dst_temp[3] & 0xFF);
					table_pointer->dst = IP4_ADR_P2H(dst_temp[0]&0xFF, dst_temp[1]&0xFF, dst_temp[2]&0xFF, dst_temp[3]&0xFF);
					break;
				case RTA_GATEWAY: //next hop
					table_pointer->mask = rtm->rtm_dst_len;
					memcpy(gw_temp, RTA_DATA(rta), IP4_ALEN);
					//PRINT_DEBUG("received RTA_GATEWAY");
					PRINT_DEBUG("gw_str = %u.%u.%u.%u", gw_temp[0] & 0xFF, gw_temp[1] & 0xFF, gw_temp[2] & 0xFF, gw_temp[3] & 0xFF);
					table_pointer->gw = IP4_ADR_P2H(gw_temp[0]&0xFF, gw_temp[1]&0xFF, gw_temp[2]&0xFF, gw_temp[3]&0xFF);
					break;
				case RTA_OIF: //interface
					memcpy(&table_pointer->interface, RTA_DATA(rta), sizeof(interface)); //TODO won't work with current hack
					PRINT_DEBUG("interface:%u", table_pointer->interface);
					break;
				case RTA_PRIORITY: //metric
					memcpy(&table_pointer->metric, RTA_DATA(rta), sizeof(priority));
					PRINT_DEBUG("metric:%u", table_pointer->metric);
					break;
				} //switch(rta->)
			} // for()
		} // if RTN_UNICAST
		return (table_pointer);
	}
	} //switch (msg->nlmsg_type)
	return (NULL);
}

struct ip4_routing_table * IP4_get_routing_table_old() {
	int nlmsg_len;
	struct nlmsghdr* msg;
	char receive_buffer[IP4_NETLINK_BUFF_SIZE];
	char * receive_ptr;
	unsigned int sock;
	struct ip4_route_request route_req;
	struct ip4_routing_table * routing_table;
	struct ip4_routing_table * current_table_entry;

	unsigned int pid = (uint32_t) getpid();
	unsigned int seq = (uint32_t) getppid();
	if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
		PRINT_DEBUG("couldn't open NETLINK_ROUTE socket");
		return NULL;
	}
	/* prepare netlink message header*/
	route_req.msg.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	route_req.msg.nlmsg_type = RTM_GETROUTE;
	route_req.msg.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	route_req.msg.nlmsg_seq = seq;
	route_req.msg.nlmsg_pid = pid;

	route_req.rt.rtm_family = AF_INET;
	route_req.rt.rtm_dst_len = IP4_ALEN * 8; // must be supplied in bits
	route_req.rt.rtm_src_len = 0;
	route_req.rt.rtm_table = RT_TABLE_MAIN;
	route_req.rt.rtm_protocol = RTPROT_UNSPEC;
	route_req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	route_req.rt.rtm_type = RTN_UNSPEC;
	route_req.rt.rtm_flags = 0;

	// write the message to our netlink socket
	int result = send(sock, &route_req, sizeof(route_req), 0);
	if (result < 0) {
		PRINT_ERROR("Routing table request send error.");
		return NULL;
	}

	memset(receive_buffer, 0, IP4_NETLINK_BUFF_SIZE);
	receive_ptr = receive_buffer;
	nlmsg_len = 0;
	while (1) {
		int msg_len = recv(sock, receive_ptr, IP4_NETLINK_BUFF_SIZE, 0);
		if (msg_len < 0) {
			PRINT_ERROR("recv() error.");
			return NULL; //ERROR
		}
		msg = (struct nlmsghdr *) receive_ptr;
		if (msg->nlmsg_type == NLMSG_DONE) {
			break;
		}
		for (; 0 != NLMSG_OK(msg, msg_len); msg = NLMSG_NEXT(msg, msg_len)) {
			if (msg->nlmsg_seq == seq) {
				if (routing_table == NULL) {
					routing_table = current_table_entry = parse_nlmsg(msg);
				} else {
					current_table_entry->next_entry = parse_nlmsg(msg);
					if (current_table_entry->next_entry != NULL) {
						current_table_entry = current_table_entry->next_entry;
					}
				}
			}
			receive_ptr = receive_ptr + msg_len;
			nlmsg_len = nlmsg_len + msg_len;
		}
	}
	return routing_table;
}

struct ip4_routing_table * IP4_get_routing_table() {
	struct ip4_routing_table *routing_table;

	struct ip4_routing_table *row0 = (struct ip4_routing_table*) secure_malloc(sizeof(struct ip4_routing_table));
	struct ip4_routing_table *row1 = (struct ip4_routing_table*) secure_malloc(sizeof(struct ip4_routing_table));
	struct ip4_routing_table *row2 = (struct ip4_routing_table*) secure_malloc(sizeof(struct ip4_routing_table));

	if (1) { //laptop eth0
		row0->dst = my_host_ip_addr & my_host_mask;
		row0->gw = any_ip_addr;
		row0->mask = 24;
		row0->metric = 10;
		row0->interface = my_host_ip_addr; //TODO change back to number? so looks up in interface list
		row0->next_entry = row1;

		row1->dst = any_ip_addr;
		row1->gw = (my_host_ip_addr & my_host_mask) | 1;
		row1->mask = 24;
		row1->metric = 10;
		row1->interface = my_host_ip_addr; //TODO change back to number? so looks up in interface list
		row1->next_entry = row2;

		row2->dst = loopback_ip_addr;
		row2->gw = IP4_ADR_P2H(10,0,2,2);
		row2->mask = 0;
		row2->metric = 0;
		row2->interface = my_host_ip_addr;
		row2->next_entry = NULL;
	}

	if (0) { //standard linux table
		row0->dst = IP4_ADR_P2H(10,0,2,0);
		row0->gw = IP4_ADR_P2H(0,0,0,0);
		row0->mask = 24;
		row0->metric = 1;
		row0->interface = 3; //number assiociated with interface & thus IP?
		row0->next_entry = row1;

		row1->dst = IP4_ADR_P2H(169,254,0,0);
		row1->gw = IP4_ADR_P2H(0,0,0,0);
		row1->mask = 16;
		row1->metric = 1000;
		row1->interface = 3;
		row1->next_entry = row2;

		row2->dst = IP4_ADR_P2H(0,0,0,0);
		row2->gw = IP4_ADR_P2H(10,0,2,2);
		row2->mask = 0;
		row2->metric = 0;
		row2->interface = 3;
		row2->next_entry = NULL;
	}

	routing_table = row0;
	return routing_table;
}
