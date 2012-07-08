
#include "IP4.h"

void IP4_print_routing_table(struct ip4_routing_table * table_pointer)
{
	struct ip4_routing_table *current_pointer;
	current_pointer = table_pointer;
	printf("Routing table:\n");
	printf("Destination\tGateway\t\tMask\tMetric\tInterface\n");
	while (current_pointer != NULL)
	{
		printf("%u.%u.%u.%u \t", (unsigned int) current_pointer->dst >> 24,
				(unsigned int) (current_pointer->dst >> 16) & 0xFF,
				(unsigned int) (current_pointer->dst >> 8) & 0xFF,
				(unsigned int) current_pointer->dst & 0xFF);
		printf("%u.%u.%u.%u \t", (unsigned int) current_pointer->gw >> 24,
				(unsigned int) (current_pointer->gw >> 16) & 0xFF,
				(unsigned int) (current_pointer->gw >> 8) & 0xFF,
				(unsigned int) current_pointer->gw & 0xFF);
		printf("%u \t", (unsigned int) current_pointer->mask);
		printf("%u \t", current_pointer->metric);
		printf("%u", current_pointer->interface);
		printf("\n");
		current_pointer = current_pointer->next_entry;
	}
}

struct ip4_routing_table * IP4_sort_routing_table(
		struct ip4_routing_table * table_pointer)
{
	if (table_pointer == NULL)
	{
		return NULL;
	}
	struct ip4_routing_table *first = table_pointer;
	struct ip4_routing_table *previous;
	struct ip4_routing_table *current;
	int swapped = 1;
	while (swapped)
	{
		swapped = 0;
		previous = NULL;
		current = table_pointer;
		while ((current!=NULL)&&(current->next_entry != NULL))
		{
			if (current->mask < current->next_entry->mask)
			{
				if (previous == NULL)
				{
					first = current->next_entry;
					current->next_entry = current->next_entry->next_entry;
					first->next_entry = current;
				} else
				{
					previous->next_entry = current->next_entry;
					current->next_entry = current->next_entry->next_entry;
					previous->next_entry->next_entry = current;
				}
				swapped = 1;
			}
			previous = current;
			current = current->next_entry;
		}
	}
	return (first);

}

struct ip4_routing_table * parse_nlmsg(struct nlmsghdr* msg)
{
	char dst_temp[IP4_ALEN];
	char gw_temp[IP4_ALEN];
	unsigned int priority;
	unsigned int interface;
	struct ip4_routing_table *table_pointer = NULL;

	switch (msg->nlmsg_type)
	{
	case NLMSG_ERROR:
	{
		struct nlmsgerr* errorMsg = (struct nlmsgerr*) NLMSG_DATA(msg);
		PRINT_DEBUG("\nrecvd NLMSG_ERROR error seq:%d code:%d...", msg->nlmsg_seq, errorMsg->error);
		break;
	}
	case RTM_NEWROUTE:
	{
		struct rtmsg* rtm = (struct rtmsg*) NLMSG_DATA(msg);
		struct rtattr* rta = RTM_RTA(rtm);
		int rtaLen = msg->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
		if (rtm->rtm_type == RTN_UNICAST) // don't consider local, broadcast and unreachable routes
		{
			table_pointer = (struct ip4_routing_table*) malloc(
					sizeof(struct ip4_routing_table));
			memset(table_pointer, 0, sizeof(struct ip4_routing_table)); // zero the routing table entry data
			for (; RTA_OK(rta, rtaLen); rta = RTA_NEXT(rta, rtaLen))
			{
				switch (rta->rta_type)
				{
				case RTA_DST: //destination
					table_pointer->mask = rtm->rtm_dst_len;
					memcpy(dst_temp, RTA_DATA(rta), IP4_ALEN);
					PRINT_DEBUG("received RTA_DST");
					PRINT_DEBUG("dst_str = %u.%u.%u.%u", dst_temp[0]&0xFF, dst_temp[1]&0xFF, dst_temp[2]&0xFF, dst_temp[3]&0xFF);
					table_pointer->dst
							= IP4_ADR_P2N(dst_temp[0]&0xFF, dst_temp[1]&0xFF, dst_temp[2]&0xFF, dst_temp[3]&0xFF);
					break;
				case RTA_GATEWAY: //next hop
					table_pointer->mask = rtm->rtm_dst_len;
					memcpy(gw_temp, RTA_DATA(rta), IP4_ALEN);
					PRINT_DEBUG("received RTA_GATEWAY");
					PRINT_DEBUG("gw_str = %u.%u.%u.%u",gw_temp[0]&0xFF, gw_temp[1]&0xFF, gw_temp[2]&0xFF, gw_temp[3]&0xFF);
					table_pointer->gw
							= IP4_ADR_P2N(gw_temp[0]&0xFF, gw_temp[1]&0xFF, gw_temp[2]&0xFF, gw_temp[3]&0xFF);
					break;
				case RTA_OIF: //interface
					memcpy(&table_pointer->interface, RTA_DATA(rta),
							sizeof(interface));
					PRINT_DEBUG("interface:%u",table_pointer->interface);
					break;
				case RTA_PRIORITY: //metric
					memcpy(&table_pointer->metric, RTA_DATA(rta),
							sizeof(priority));
					PRINT_DEBUG("metric:%u",table_pointer->metric);
					break;
				} //switch(rta->)
			}// for()
		} // if RTN_UNICAST
		return (table_pointer);
	}
	} //switch (msg->nlmsg_type)
	return (NULL);
}

struct ip4_routing_table * IP4_get_routing_table()
{
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

	if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
	{
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
	route_req.rt.rtm_dst_len = IP4_ALEN * 8;// must be supplied in bits
	route_req.rt.rtm_src_len = 0;
	route_req.rt.rtm_table = RT_TABLE_MAIN;
	route_req.rt.rtm_protocol = RTPROT_UNSPEC;
	route_req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	route_req.rt.rtm_type = RTN_UNSPEC;
	route_req.rt.rtm_flags = 0;

	// write the message to our netlink socket
	int result = send(sock, &route_req, sizeof(route_req), 0);
	if (result < 0)
	{
		PRINT_ERROR("Routing table request send error.");
		return NULL;
	}

	memset(receive_buffer, 0, IP4_NETLINK_BUFF_SIZE);
	receive_ptr = receive_buffer;
	nlmsg_len = 0;
	while (1)
	{
		int msg_len = recv(sock, receive_ptr, IP4_NETLINK_BUFF_SIZE, 0);
		if (msg_len < 0)
		{
			PRINT_ERROR("recv() error.");
			return NULL; //ERROR
		}
		msg = (struct nlmsghdr *) receive_ptr;
		if (msg->nlmsg_type == NLMSG_DONE)
		{
			break;
		}
		for (; 0 != NLMSG_OK(msg, msg_len); msg = NLMSG_NEXT(msg, msg_len))
		{
			if (msg->nlmsg_seq == seq)
			{
				if (routing_table == NULL)
				{
					routing_table = current_table_entry = parse_nlmsg(msg);
				} else
				{
					current_table_entry->next_entry = parse_nlmsg(msg);
					if (current_table_entry->next_entry != NULL)
					{
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
