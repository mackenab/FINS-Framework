/*
 * @file daemon.c
 *
 * @date Mar 6, 2011
 *      @author Abdallah Abdallah
 *      @brief  The DeMux which redirects every request to its appropriate
 *      protocol alternative socket interface. This initial basic
 *      version includes UDP handlers and TCP handlers). It also has the functions
 *      which manage and maintain our socket database
 */

#include "daemon.h"

#include <switch.h>
static struct fins_proto_module daemon_proto = { .module_id = DAEMON_ID, .name = "daemon", .running_flag = 1, };

pthread_t wedge_to_daemon_thread;
pthread_t switch_to_daemon_thread;

sem_t daemon_sockets_sem;
struct daemon_socket daemon_sockets[MAX_SOCKETS];

struct daemon_call daemon_calls[MAX_CALLS];
struct daemon_call_list *expired_call_list;

int daemon_thread_count;

uint8_t daemon_interrupt_flag;

int init_fins_nl(void) {
	int sockfd;
	int ret;

	sem_init(&nl_sem, 0, 1);

	// Get a netlink socket descriptor
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FINS);
	if (sockfd == -1) {
		return -1;
	}

	// Populate local_sockaddress
	memset(&local_sockaddress, 0, sizeof(local_sockaddress));
	local_sockaddress.nl_family = AF_NETLINK;
	local_sockaddress.nl_pad = 0;
	local_sockaddress.nl_pid = getpid(); //pthread_self() << 16 | getpid(),	// use second option for multi-threaded process
	local_sockaddress.nl_groups = 0; // unicast

	// Bind the local netlink socket
	ret = bind(sockfd, (struct sockaddr*) &local_sockaddress, sizeof(local_sockaddress));
	if (ret == -1) {
		return -1;
	}

	// Populate kernel_sockaddress
	memset(&kernel_sockaddress, 0, sizeof(kernel_sockaddress));
	kernel_sockaddress.nl_family = AF_NETLINK;
	kernel_sockaddress.nl_pad = 0;
	kernel_sockaddress.nl_pid = 0; // to kernel
	kernel_sockaddress.nl_groups = 0; // unicast

	return sockfd;
}

/*
 * Sends len bytes from buf on the sockfd.  Returns 0 if successful.  Returns -1 if an error occurred, errno set appropriately.
 */
int send_wedge(int sockfd, uint8_t *buf, size_t len, int flags) {
	PRINT_DEBUG("Entered: sockfd=%d, buf=%p, len=%d, flags=0x%x", sockfd, buf, len, flags);

	int ret; // Holds system call return values for error checking

	// Begin send message section
	// Build a message to send to the kernel
	int nlmsg_len = NLMSG_LENGTH(len);
	struct nlmsghdr *nlh = (struct nlmsghdr *) secure_malloc(nlmsg_len);
	memset(nlh, 0, nlmsg_len);

	nlh->nlmsg_len = nlmsg_len;
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0; // arbitrary value
	nlh->nlmsg_seq = 0; // sequence number
	nlh->nlmsg_pid = getpid(); // pthread_self() << 16 | getpid();	// use the second one for multiple threads
	nlh->nlmsg_flags = flags;

	// Insert payload (memcpy)
	memcpy(NLMSG_DATA(nlh), buf, len);

	// finish message packing
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &kernel_sockaddress;
	msg.msg_namelen = sizeof(kernel_sockaddress);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the message
	PRINT_DEBUG("Sending message to kernel");

	secure_sem_wait(&nl_sem);
	ret = sendmsg(sockfd, &msg, 0);
	sem_post(&nl_sem);

	free(nlh);

	if (ret == -1) {
		return -1;
	} else {
		return 0;
	}
}

struct daemon_call *call_create(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index) {
	PRINT_DEBUG("Entered: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			call_id, call_index, call_pid, call_type, sock_id, sock_index);

	struct daemon_call *call = (struct daemon_call *) secure_malloc(sizeof(struct daemon_call));
	call->next = NULL;
	call->alloc = 1;

	call->call_id = call_id;
	call->call_index = call_index;

	call->call_pid = call_pid;
	call->call_type = call_type;

	call->sock_id = sock_id;
	call->sock_index = sock_index;

	call->serial_num = 0;
	call->data = 0;
	call->flags = 0;
	call->ret = 0;

	call->sock_id_new = 0;
	call->sock_index_new = 0;

	PRINT_DEBUG("Exited: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d, call=%p",
			call_id, call_index, call_pid, call_type, sock_id, sock_index, call);
	return call;
}

struct daemon_call *call_clone(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	struct daemon_call *call_clone = (struct daemon_call *) secure_malloc(sizeof(struct daemon_call));
	call_clone->next = NULL;
	call_clone->alloc = 1;

	call_clone->call_id = call->call_id;
	call_clone->call_index = call->call_index;

	call_clone->call_pid = call->call_pid;
	call_clone->call_type = call->call_type;

	call_clone->sock_id = call->sock_id;
	call_clone->sock_index = call->sock_index;

	call_clone->serial_num = call->serial_num;
	call_clone->data = call->data;
	call_clone->flags = call->flags;
	call_clone->ret = call->ret;

	call_clone->sock_id_new = call->sock_id_new;
	call_clone->sock_index_new = call->sock_index_new;

	PRINT_DEBUG("Exited: call=%p, clone=%p", call, call_clone);
	return call_clone;
}

void call_free(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	free(call);
}

int daemon_calls_insert(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index) {
	PRINT_DEBUG("Entered: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			call_id, call_index, call_pid, call_type, sock_id, sock_index);

	if (daemon_calls[call_index].call_id != -1) { //TODO may actually remove, add check such that FCF pointing
		PRINT_ERROR("Error, call_index in use: daemon_calls[%d].call_id=%u", call_index, daemon_calls[call_index].call_id);
		PRINT_ERROR("Overwriting with: daemon_calls[%d].call_id=%u", call_index, call_id);

		if (daemon_sockets[daemon_calls[call_index].sock_index].sock_id == daemon_calls[call_index].sock_id && (daemon_calls[call_index].call_type == poll_call
				|| daemon_calls[call_index].call_type == recvmsg_call)) {
			call_list_remove(daemon_sockets[daemon_calls[call_index].sock_index].call_list, &daemon_calls[call_index]);
		}

		//this should only occur on a ^C which breaks the wedge sem_wait(), thus exiting the call before hearing back from the daemon and then re-using the index
		//since the wedge side call already returned and the program is exiting, replying to the wedge for the old call is unnecessary as it would be dropped
		//also the associated daemon_in function from a returning FCF for the old call does not need to be executed as the socket will soon be removed
		//TODO exception might be overwriting as the daemon_in function occurring
	}

	daemon_calls[call_index].next = NULL;

	daemon_calls[call_index].call_id = call_id;
	daemon_calls[call_index].call_index = call_index;

	daemon_calls[call_index].call_pid = call_pid;
	daemon_calls[call_index].call_type = call_type;

	daemon_calls[call_index].sock_id = sock_id;
	daemon_calls[call_index].sock_index = sock_index;

	daemon_calls[call_index].serial_num = 0;
	daemon_calls[call_index].data = 0;
	daemon_calls[call_index].flags = 0;
	daemon_calls[call_index].ret = 0;

	daemon_calls[call_index].sock_id_new = 0;
	daemon_calls[call_index].sock_index_new = 0;

	if (daemon_calls[call_index].to_running) {
		daemon_calls[call_index].to_flag = 0;
		stop_timer(daemon_calls[call_index].to_fd);
	}

	return 1;
}

int daemon_calls_find(uint32_t serial_num) {
	int i;

	PRINT_DEBUG("Entered: serial_num=%u", serial_num);

	for (i = 0; i < MAX_CALLS; i++) {
		if (daemon_calls[i].call_id != -1 && daemon_calls[i].serial_num == serial_num) {
			PRINT_DEBUG("Exited: serial_num=%u, call_index=%u", serial_num, i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: serial_num=%u, call_index=%d", serial_num, -1);
	return -1;
}

void daemon_calls_remove(int call_index) {
	PRINT_DEBUG("Entered: call_index=%d", call_index);

	daemon_calls[call_index].call_id = -1;

	stop_timer(daemon_calls[call_index].to_fd);
	daemon_calls[call_index].to_flag = 0;
}

void daemon_calls_shutdown(int call_index) {
	PRINT_DEBUG("Entered: call_index=%d", call_index);

	daemon_calls[call_index].to_running = 0;

	//stop threads
	start_timer(daemon_calls[call_index].to_fd, TO_MIN);

	//sem_post(&conn->write_wait_sem);
	//sem_post(&conn->write_sem);
	//clear all threads using this conn_stub

	PRINT_DEBUG("");
	//post to read/write/connect/etc threads
	pthread_join(daemon_calls[call_index].to_thread, NULL);
}

struct daemon_call_list *call_list_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct daemon_call_list *call_list = (struct daemon_call_list *) secure_malloc(sizeof(struct daemon_call_list));
	call_list->front = NULL;
	call_list->end = NULL;

	call_list->max = max;
	call_list->len = 0;

	//call_list_check(call_list);

	PRINT_DEBUG("Exited: max=%u, call_list=%p", max, call_list);
	return call_list;
}

void call_list_append(struct daemon_call_list *call_list, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, serial_num=%u", call_list, call, call->serial_num);

	call->next = NULL;
	if (call_list_is_empty(call_list)) {
		//queue empty
		call_list->front = call;
	} else {
		//node after end
		call_list->end->next = call;
	}
	call_list->end = call;
	call_list->len++;

	//call_list_check(call_list);

	PRINT_DEBUG("Exited: call_list=%p, len=%u", call_list, call_list->len);
}

struct daemon_call *call_list_find_pid(struct daemon_call_list *call_list, int call_pid, uint32_t call_type, uint64_t sock_id) { //TODO remove sock_id? since call_list divided by sock
	PRINT_DEBUG("Entered: call_list=%p, call_pid=%d, call_type=%u, sock_id=%llu", call_list, call_pid, call_type, sock_id);

	struct daemon_call *comp = call_list->front;
	while (comp) {
		if (comp->call_pid == call_pid && comp->call_type == call_type && comp->sock_id == sock_id) {
			PRINT_DEBUG("Exited: call_list=%p, call_pid=%d, call_type=%u, sock_id=%llu, call=%p", call_list, call_pid, call_type, sock_id, comp);
			return comp;
		}
		comp = comp->next;
	}

	PRINT_DEBUG("Exited: call_list=%p, call_pid=%d, call_type=%u, sock_id=%llu, call=%p", call_list, call_pid, call_type, sock_id, NULL);
	return NULL;
}

struct daemon_call *call_list_find_serial_num(struct daemon_call_list *call_list, uint32_t serial_num) {
	PRINT_DEBUG("Entered: call_list=%p, serial_num=%u", call_list, serial_num);

	struct daemon_call *comp = call_list->front;
	while (comp) {
		if (comp->serial_num == serial_num) {
			PRINT_DEBUG("Exited: call_list=%p, serial_num=%u, call=%p", call_list, serial_num, comp);
			return comp;
		}
		comp = comp->next;
	}

	PRINT_DEBUG("Exited: call_list=%p, serial_num=%u, call=%p", call_list, serial_num, NULL);
	return NULL;
}

struct daemon_call *call_list_remove_front(struct daemon_call_list *call_list) {
	PRINT_DEBUG("Entered: call_list=%p", call_list);

	struct daemon_call *call = call_list->front;
	if (call) {
		call_list->front = call->next;
		call_list->len--;
	} else { //TODO remove when everything's ironed out?
		PRINT_ERROR("reseting len: len=%u", call_list->len);
		call_list->len = 0;
	}

	//call_list_check(call_list);

	PRINT_DEBUG("Exited: call_list=%p, len=%u, call=%p", call_list, call_list->len, call);
	return call;
}

void call_list_remove(struct daemon_call_list *call_list, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p", call_list, call);

	if (call_list_is_empty(call_list)) {
		//call_list_check(call_list);

		PRINT_DEBUG("Exited: call_list=%p, len=%u", call_list, call_list->len);
		return;
	}

	if (call_list->front == call) {
		call_list->front = call_list->front->next;
		call_list->len--;

		//call_list_check(call_list);

		PRINT_DEBUG("Exited: call_list=%p, len=%u", call_list, call_list->len);
		return;
	}

	struct daemon_call *temp = call_list->front;
	while (temp->next != NULL) {
		if (temp->next == call) {
			if (call_list->end == call) {
				call_list->end = temp;
				temp->next = NULL;
			} else {
				temp->next = call->next;
			}

			call_list->len--;

			//call_list_check(call_list);

			PRINT_DEBUG("Exited: call_list=%p, len=%u", call_list, call_list->len);
			return;
		}
		temp = temp->next;
	}
}

int call_list_check(struct daemon_call_list *call_list) { //TODO remove all references
	PRINT_DEBUG("Entered: call_list=%p, len=%u", call_list, call_list->len);

	int count = 0;

	struct daemon_call *temp = call_list->front;
	while (temp && count <= call_list->max) {
		count++;
		temp = temp->next;
	}

	if (count == call_list->len) {
	} else {
		PRINT_ERROR("todo error: call_list=%p, max=%u, len=%u, count=%u, check=%u", call_list, call_list->max, call_list->len, count, count == call_list->len);
		temp = call_list->front;
		while (temp && count <= call_list->max) {
			PRINT_DEBUG("count=%d, call=%p", count, temp);
			count++;
			temp = temp->next;
		}
	}

	PRINT_DEBUG("Exited: call_list=%p, count=%u, check=%u", call_list, count, count == call_list->len);
	return count == call_list->len;
}

int call_list_is_empty(struct daemon_call_list *call_list) {
	return call_list->len == 0;
}

int call_list_has_space(struct daemon_call_list *call_list) {
	return call_list->len < call_list->max;
}

void call_list_free(struct daemon_call_list *call_list) {
	PRINT_DEBUG("Entered: call_list=%p, len=%u", call_list, call_list->len);

	struct daemon_call *call;
	while (!call_list_is_empty(call_list)) {
		call = call_list_remove_front(call_list);
		if (call->alloc) {
			call_free(call);
		} else {
			if (call->call_id != -1) {
				daemon_calls_remove(call->call_index);
			} else {
				PRINT_ERROR("todo error");
			}
		}
	}

	free(call_list);
}

/**
 * @brief insert new daemon socket in the first empty location
 * in the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int daemon_sockets_insert(uint64_t sock_id, int sock_index, int type, int protocol) {
	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d, type=%d, protocol=%d", sock_id, sock_index, type, protocol);
	if (daemon_sockets[sock_index].sock_id == -1) {
		daemon_sockets[sock_index].sock_id = sock_id;
		daemon_sockets[sock_index].state = SS_UNCONNECTED;

		/**
		 * bind the socket by default to the default IP which is assigned
		 * to the Interface which was already started by the Capturing and Injecting process
		 * The IP default value it supposed to be acquired from the configuration file
		 * The allowable ports range is supposed also to be aquired the same way
		 */

		daemon_sockets[sock_index].type = type; //Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM it has nothing to do with layer 4 protocols like TCP, UDP , etc
		daemon_sockets[sock_index].protocol = protocol;

		daemon_sockets[sock_index].host_ip = 0; //TODO change to -1? or have flags for bind/connect?
		daemon_sockets[sock_index].host_port = 0; //The host port is initially assigned randomly and stay the same unless binding explicitly later
		daemon_sockets[sock_index].rem_ip = 0;
		daemon_sockets[sock_index].rem_port = 0;

		daemon_sockets[sock_index].bound = 0;
		daemon_sockets[sock_index].listening = 0;
		daemon_sockets[sock_index].backlog = DEFAULT_BACKLOG;

		daemon_sockets[sock_index].sock_id_new = -1;
		daemon_sockets[sock_index].sock_index_new = -1;

		daemon_sockets[sock_index].call_list = call_list_create(DAEMON_CALL_LIST_MAX); //really only for poll_call & recvmsg_call, split for efficiency?
		memset(&daemon_sockets[sock_index].stamp, 0, sizeof(struct timeval));

		daemon_sockets[sock_index].data_queue = init_queue(NULL, MAX_Queue_size);
		daemon_sockets[sock_index].data_buf = 0;

		daemon_sockets[sock_index].error_queue = init_queue(NULL, MAX_Queue_size); //only used when RECVERR enabled for ICMP/UDP
		daemon_sockets[sock_index].error_buf = 0;

		daemon_sockets[sock_index].error_call = 0;
		daemon_sockets[sock_index].error_msg = 0;

		daemon_sockets[sock_index].sockopts.FIP_TTL = 64;
		daemon_sockets[sock_index].sockopts.FIP_TOS = 64;
		daemon_sockets[sock_index].sockopts.FSO_REUSEADDR = 0;

		//daemon_sockets[sock_index].sockopts.FSO_RCVTIMEO = IPTOS_LOWDELAY;
		//daemon_sockets[sock_index].sockopts.FSO_SNDTIMEO = IPTOS_LOWDELAY;

		return 1;
	} else {
		PRINT_DEBUG("index in use: index=%d", sock_index);
		return 0;
	}
}

/**
 * @brief find a daemon socket among the daemon sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int daemon_sockets_find(uint64_t sock_id) {
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	int i = 0;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id == sock_id) {
			PRINT_DEBUG("Exited: sock_id=%llu, sock_index=%d", sock_id, i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: sock_id=%llu, sock_index=%d", sock_id, -1);
	return (-1);
}

int daemon_sockets_match(uint16_t dst_port, uint32_t dst_ip, int protocol) {
	PRINT_DEBUG("Entered: %u/%u: %d, ", dst_ip, dst_port, protocol);

	int i;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id != -1) {
			if (protocol == IPPROTO_ICMP) {
				if ((daemon_sockets[i].protocol == protocol) && (daemon_sockets[i].host_ip == dst_ip)) {
					PRINT_DEBUG("ICMP");
					return (i);
				}
			} else {
				if (daemon_sockets[i].host_ip == INADDR_ANY) {
					if (daemon_sockets[i].host_port == dst_port) {
						PRINT_DEBUG("hostport == dstport");
						return (i);
					}
				} else if ((daemon_sockets[i].host_port == dst_port) && (daemon_sockets[i].host_ip == dst_ip)/** && (daemonSockets[i].protocol == protocol)*/) {
					PRINT_DEBUG("host_IP == dstip");
					return (i);
				} else {
					PRINT_DEBUG("default");
				}
			}

			if (0) {
				if (daemon_sockets[i].host_ip == INADDR_ANY && (protocol != IPPROTO_ICMP)) {
					if ((daemon_sockets[i].host_port == dst_port))
						return (i);
				} else if ((daemon_sockets[i].host_port == dst_port) && (daemon_sockets[i].host_ip == dst_ip) && ((protocol != IPPROTO_ICMP))
				/** && (daemonSockets[i].protocol == protocol)*/) {
					return (i);
				}

				/** Matching for ICMP incoming datagrams
				 * In this case the IP passes is actually the source IP of that incoming message (Or called the host)
				 */
				else if ((daemon_sockets[i].protocol == protocol) && (protocol == IPPROTO_ICMP) && (daemon_sockets[i].rem_ip == dst_ip)) {
					return (i);

				} else {
				}
			}
		}
	} // end of for loop

	return (-1);

}

int daemon_sockets_match_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol) {
	PRINT_DEBUG("Entered: host=%u/%u, rem=%u/%u, prot=%d", host_ip, host_port, rem_ip, rem_port, protocol);

	int i;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id != -1 && daemon_sockets[i].host_ip == host_ip && daemon_sockets[i].host_port == host_port && daemon_sockets[i].rem_ip
				== rem_ip && daemon_sockets[i].rem_port == rem_port && daemon_sockets[i].protocol == protocol) {
			PRINT_DEBUG("Exited: host=%u/%u, rem=%u/%u, sock_index=%d", host_ip, host_port, rem_ip, rem_port, i);
			return (i);
		}
	}

	//TODO add check for INADDR_ANY & INPORT_ANY
	PRINT_DEBUG("Exited: host=%u/%u, rem=%u/%u, sock_index=%d", host_ip, host_port, rem_ip, rem_port, -1);
	return (-1);
}

/**
 * @brief check if this host port is free or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found previously-allocated)
 */
int daemon_sockets_check_ports(uint16_t host_port, uint32_t host_ip) {
	PRINT_DEBUG("Entered: host_ip=%u, host_port=%u", host_ip, host_port);

	int i = 0;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].host_ip == INADDR_ANY) {
			if (daemon_sockets[i].host_port == host_port) {
				return (0);
			}
		} else {
			if ((daemon_sockets[i].host_port == host_port) && (daemon_sockets[i].host_ip == host_ip)) {
				return (0);
			}
		}
	}
	return (1);
}

/**
 * @brief remove a daemon socket from
 * the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int daemon_sockets_remove(int sock_index) {
	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d", daemon_sockets[sock_index].sock_id, sock_index);
	daemon_sockets[sock_index].sock_id = -1;
	daemon_sockets[sock_index].state = SS_FREE;

	//TODO stop all threads related to

	//TODO send NACK for each call in call_list

	struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

	struct daemon_call *call;
	while (!call_list_is_empty(call_list)) {
		call = call_list_remove_front(call_list);
		if (call) {
			if (call->alloc) {
				nack_send(call->call_id, call->call_index, call->call_type, 0);

				call_free(call);
			} else {
				if (call->call_id != -1) {
					nack_send(call->call_id, call->call_index, call->call_type, 0);

					daemon_calls_remove(call->call_index);
				} else {
					PRINT_ERROR("todo error: call_id=%u, call_index=%d, call_type=%u", call->call_id, call->call_index, call->call_type);
				}
			}
		} else {
			PRINT_ERROR("todo error");
			break;
		}
	}
	call_list_free(call_list);

	term_queue(daemon_sockets[sock_index].error_queue);
	term_queue(daemon_sockets[sock_index].data_queue);

	return 1;
}

/**
 * @brief check if this destination port and address has been contacted as
 * destinations earlier or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found pre-allocated)
 */

int check_daemon_dstports(uint16_t dstport, uint32_t dstip) {

	int i = 0;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if ((daemon_sockets[i].rem_port == dstport) && (daemon_sockets[i].rem_ip == dstip))
			return (-1);

	}
	return (1);

}

/**
 * @brief generate a random integer between min and max
 * @param minimum value of the range, maximum value of the range
 * @return the random integer value
 *
 */

int randoming(int min, int max) {

	srand((unsigned) time(NULL));
	return (min + (int) (max - min + 1) * (rand() / (RAND_MAX + 1.0)));

}

int nack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret;

	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, nack=%d", call_id, call_index, call_type, msg, NACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = NACK;
	hdr->msg = msg;

	ret = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret == 1; //TODO change to ret_val ?
}

int ack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret;

	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, ack=%d", call_id, call_index, call_type, msg, ACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = ACK;
	hdr->msg = msg;

	ret = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret == 1; //TODO change to ret_val ?
}

int daemon_to_switch(struct finsFrame *ff) {
	return module_to_switch(&daemon_proto, ff);
}

int daemon_fcf_to_switch(uint8_t dest_id, metadata *params, uint32_t serial_num, uint16_t opcode, uint32_t param_id) {
	PRINT_DEBUG("Entered: module_id=%d, meta=%p, serial_num=%u, opcode=%u, param_id=%u", dest_id, params, serial_num, opcode, param_id);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = CONTROL;
	ff->destinationID.id = dest_id;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->ctrlFrame.senderID = DAEMON_ID;
	ff->ctrlFrame.serial_num = serial_num;
	ff->ctrlFrame.opcode = opcode;
	ff->ctrlFrame.param_id = param_id;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("ff=%p, meta=%p", ff, params);
	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		free(ff);
		return 0;
	}
}

int daemon_fdf_to_switch(uint8_t dest_id, uint8_t *data, uint32_t data_len, metadata *params) {
	PRINT_DEBUG("Entered: module_id=%u, data=%p, data_len=%u, meta=%p", dest_id, data, data_len, params);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = dest_id;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	PRINT_DEBUG("sending: ff=%p, meta=%p", ff, params);
	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		PRINT_ERROR("freeing: ff=%p", ff);
		free(ff);
		return 0;
	}
}

void socket_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	int domain;
	int type;
	int protocol;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	domain = *(int *) pt;
	pt += sizeof(int);

	type = *(int *) pt;
	pt += sizeof(int);

	protocol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("domain=%d, type=%u, protocol=%d", domain, type, protocol);
	if (domain != AF_INET) {
		PRINT_ERROR("Wrong domain, only AF_INET us supported");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) { //is proto==icmp needed?
		socket_out_icmp(hdr, domain, type, protocol);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		socket_out_tcp(hdr, domain, type, protocol);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		socket_out_udp(hdr, domain, type, protocol);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void bind_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	socklen_t addr_len;
	struct sockaddr_in *addr;
	int reuseaddr;
	uint8_t *pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len <= 0) {
		PRINT_ERROR("READING ERROR! CRASH, addrlen=%d", addr_len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	} else {
		PRINT_DEBUG("addr_len=%d", addr_len);
	}

	addr = (struct sockaddr_in *) secure_malloc(addr_len);
	memcpy(addr, pt, addr_len);
	pt += addr_len;

	reuseaddr = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("addr=%u/%d, family=%d, reuseaddr=%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, reuseaddr);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		return;
	}

	daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR |= reuseaddr; //TODO: when sockopts fully impelmented just set to '='

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d",
			daemon_calls[hdr->call_index].sock_id, daemon_calls[hdr->call_index].sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) { //is proto==icmp needed?
		bind_out_icmp(hdr, addr);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		bind_out_tcp(hdr, addr);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		bind_out_udp(hdr, addr);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
	}
}

void listen_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	int backlog;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	backlog = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("backlog=%d", backlog);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		listen_out_icmp(hdr, backlog);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		listen_out_tcp(hdr, backlog);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		listen_out_udp(hdr, backlog);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void connect_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	socklen_t addrlen;
	struct sockaddr_in *addr;
	int flags;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_ERROR("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	addr = (struct sockaddr_in *) secure_malloc(addrlen);
	memcpy(addr, pt, addrlen);
	pt += addrlen;

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		return;
	}

	PRINT_DEBUG("addr=%u/%d, family=%d, flags=0x%x", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, flags);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		connect_out_icmp(hdr, addr, flags);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		connect_out_tcp(hdr, addr, flags);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		connect_out_udp(hdr, addr, flags);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
	}
}

void accept_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint64_t sock_id_new;
	int sock_index_new;
	int flags;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	sock_id_new = *(uint64_t *) pt;
	pt += sizeof(uint64_t);

	sock_index_new = *(int *) pt;
	pt += sizeof(int);

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("");PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		accept_out_icmp(hdr, sock_id_new, sock_index_new, flags);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		accept_out_tcp(hdr, sock_id_new, sock_index_new, flags); //TODO finish
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		accept_out_udp(hdr, sock_id_new, sock_index_new, flags);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void getname_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	int peer;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	peer = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("");PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getname_out_icmp(hdr, peer);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		getname_out_tcp(hdr, peer);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		getname_out_udp(hdr, peer);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void ioctl_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t buf_len) {
	uint32_t cmd;
	uint8_t * pt;
	uint8_t *temp;
	int len;
	int msg_len = 0;
	uint8_t *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	struct sockaddr_in addr;
	struct ifreq ifr;
	int total;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, buf_len);

	pt = buf;

	cmd = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	switch (cmd) {
	case SIOCGIFCONF:
		PRINT_DEBUG("SIOCGIFCONF=%d", cmd);
		//TODO implement: http://lxr.linux.no/linux+v2.6.39.4/net/core/dev.c#L3919, http://lxr.linux.no/linux+v2.6.39.4/net/ipv4/devinet.c#L926
		len = *(int *) pt;
		pt += sizeof(int);

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFCONF), len=%d", cmd, len);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + 2 * sizeof(struct ifreq);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		temp = pt; //store ptr to where total should be stored
		pt += sizeof(int);

		//TODO implement a looped version of this that's taken from where interface/device info will be stored
		total = 0;
		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "lo");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(loopback_ip_addr);
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "eth0");
			//strcpy(ifr.ifr_name, "wlan0");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(my_host_ip_addr);
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		*(int *) temp = total;
		PRINT_DEBUG("total=%d (%d)", total, total/32);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGIFADDR:
		PRINT_DEBUG("SIOCGIFADDR=%d", cmd);

		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGIFDSTADDR:
		PRINT_DEBUG("SIOCGIFDSTADDR=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFDSTADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGIFBRDADDR:
		PRINT_DEBUG("SIOCGIFBRDADDR=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFBRDADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl((my_host_ip_addr & my_host_mask) | (~my_host_mask));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl((my_host_ip_addr & my_host_mask) | (~my_host_mask));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl((my_host_ip_addr & my_host_mask) | (~my_host_mask));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl((my_host_ip_addr & my_host_mask) | (~my_host_mask));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(any_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGIFNETMASK:
		PRINT_DEBUG("SIOCGIFNETMASK=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFNETMASK), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_mask);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_mask);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_mask);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_mask);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_mask);
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case FIONREAD:
		PRINT_DEBUG("FIONREAD=%d", cmd);
		msg_len = 0; //handle per socket/protocol

		PRINT_ERROR("todo")
		;
		break;
	case TIOCOUTQ:
		PRINT_DEBUG("TIOCOUTQ=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
		//case TIOCINQ: //equiv to FIONREAD??
	case SIOCGIFNAME:
		PRINT_DEBUG("SIOCGIFNAME=%d", cmd);
		len = *(int *) pt; //IFNAMSIZ
		pt += sizeof(int);

		total = *(int *) pt; //ifr_ifindex
		pt += sizeof(int);

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFNAME), index=%d", cmd, total);

		temp = (uint8_t *) secure_malloc(len);

		//TODO get correct values from IP?
		if (total == 0) {
			strcpy((char *) temp, "eth0");
			//strcpy((char *) temp, "wlan0");
		} else if (total == 1) {
			strcpy((char *) temp, "lo");
		} else if (total == 2) {
			strcpy((char *) temp, "wlan0");
		} else if (total == 3) {
			strcpy((char *) temp, "lo");
		} else {
			PRINT_DEBUG("index=%d", total);
		}

		PRINT_DEBUG("index=%d, temp='%s'", total, temp);

		msg_len = sizeof(struct nl_daemon_to_wedge) + len;
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, temp, len);
		pt += len;

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGIFFLAGS:
		PRINT_DEBUG("SIOCGIFFLAGS=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFFLAGS), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP? ifr_flags
		if (strcmp((char *) temp, "eth0") == 0) {
			total = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			total = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			total = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			total = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
		} else if (strcmp((char *) temp, "lo") == 0) {
			total = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', ifr_flags=0x%x", temp, total);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = total;
		pt += sizeof(int);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCSIFFLAGS:
		PRINT_DEBUG("SIOCSIFFLAGS=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCGIFMTU:
		PRINT_DEBUG("SIOCGIFMTU=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFMTU), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP? ifr_mtu
		if (strcmp((char *) temp, "eth0") == 0) {
			total = 1500;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			total = 1500;
		} else if (strcmp((char *) temp, "eth2") == 0) {
			total = 1500;
		} else if (strcmp((char *) temp, "wlan0") == 0) {
			total = 1500;
		} else if (strcmp((char *) temp, "lo") == 0) {
			total = 16436;
		} else {
			PRINT_DEBUG("temp='%s'", temp);
		}

		PRINT_DEBUG("temp='%s', ifr_mtu=%d", temp, total);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = total;
		pt += sizeof(int);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCADDRT:
		PRINT_DEBUG("SIOCADDRT=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCDELRT:
		PRINT_DEBUG("SIOCDELRT=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCSIFADDR:
		PRINT_DEBUG("SIOCSIFADDR=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
		//case SIOCAIPXITFCRT:
		//case SIOCAIPXPRISLT:
		//case SIOCIPXCFGDATA:
		//case SIOCIPXNCPCONN:
	case SIOCGSTAMP:
		PRINT_DEBUG("SIOCGSTAMP=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCSIFDSTADDR:
		PRINT_DEBUG("SIOCSIFDSTADDR=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCSIFBRDADDR:
		PRINT_DEBUG("SIOCSIFBRDADDR=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	case SIOCSIFNETMASK:
		PRINT_DEBUG("SIOCSIFNETMASK=%d", cmd);
		PRINT_ERROR("todo")
		;
		break;
	default:
		PRINT_ERROR("default: cmd=%d", cmd)
		;
		break;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exiting, fail send_wedge: sock_id=%llu", hdr->sock_id);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
		free(msg);
	} else {
		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&daemon_sockets_sem);
		if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		int type = daemon_sockets[hdr->sock_index].type;
		int protocol = daemon_sockets[hdr->sock_index].protocol;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
			ioctl_out_icmp(hdr, cmd, buf, buf_len);
		} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
			ioctl_out_tcp(hdr, cmd, buf, buf_len);
		} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
			ioctl_out_udp(hdr, cmd, buf, buf_len);
		} else {
			PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	}
}

void sendmsg_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint32_t sk_flags;
	int timestamp;
	int addr_len;
	struct sockaddr_in *addr = NULL;
	uint32_t msg_flags;
	uint32_t msg_controllen;
	void *msg_control = NULL;
	uint32_t data_len;
	uint8_t *data = NULL;
	uint8_t *pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	sk_flags = *(unsigned long *) pt;
	pt += sizeof(unsigned long);
	timestamp = sk_flags & ((1 << SOCK_TIMESTAMP) | (1 << SOCK_RCVTSTAMP));

	addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len > 0) {
		if (addr_len >= sizeof(struct sockaddr_in)) {
			addr = (struct sockaddr_in *) secure_malloc(addr_len);
			memcpy(addr, pt, addr_len);
			pt += addr_len;

			PRINT_DEBUG("addr_len=%d, addr=%s/%d", addr_len, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		} else {
			//TODO error?
			PRINT_ERROR("todo error: addr_len=%d", addr_len);
		}
	} else {
		PRINT_DEBUG("addr_len=%d", addr_len);
	}

	msg_flags = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	if (msg_controllen) {
		msg_control = secure_malloc(msg_controllen);
		memcpy(msg_control, pt, msg_controllen);
		pt += msg_controllen;
	}

	data_len = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	if (data_len) {
		data = (uint8_t *) secure_malloc(data_len);
		memcpy(data, pt, data_len);
		pt += data_len;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (msg_controllen)
			free(msg_control);
		if (data_len)
			free(data);
		return;
	}

	PRINT_DEBUG("");PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (msg_controllen)
			free(msg_control);
		if (data_len)
			free(data);

		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP |= timestamp;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	//#########################
#ifdef DEBUG
	uint8_t *temp = (uint8_t *) secure_malloc(data_len + 1);
	memcpy(temp, data, data_len);
	temp[data_len] = '\0';
	PRINT_DEBUG("data='%s'", temp);
	free(temp);
	//#########################
	uint8_t *temp2 = (uint8_t *) secure_malloc(msg_controllen + 1);
	memcpy(temp2, msg_control, msg_controllen);
	temp2[msg_controllen] = '\0';
	PRINT_DEBUG("msg_control='%s'", temp2);
	free(temp2);
#endif
	//#########################

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		sendmsg_out_icmp(hdr, data, data_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		sendmsg_out_tcp(hdr, data, data_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		sendmsg_out_udp(hdr, data, data_len, msg_flags, addr, addr_len);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (data_len)
			free(data);
	}

	if (msg_controllen)
		free(msg_control);
}

void recvmsg_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint32_t sk_flags;
	int timestamp;
	int data_len;
	uint32_t msg_controllen;
	int flags;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	sk_flags = *(unsigned long *) pt;
	pt += sizeof(unsigned long);
	timestamp = sk_flags & ((1 << SOCK_TIMESTAMP) | (1 << SOCK_RCVTSTAMP)); //TODO remove rcvtstamp? or figure out/expand

	data_len = *(int *) pt; //check on not in original socket_interceptor: recvmsg
	pt += sizeof(int);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	/*
	 msg_flags = *(uint32_t *) pt; //TODO remove, set when returning
	 pt += sizeof(uint32_t);

	 if (msg_controllen) {	//TODO send msg_controllen?
	 msg_control = (uint8_t *) secure_malloc(msg_controllen);
	 memcpy(msg_control, pt, msg_controllen);
	 pt += msg_controllen;
	 }
	 */

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		//if (msg_controllen) {
		//	free(msg_control);
		//}

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("flags=0x%x", flags);

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);
		//if (msg_controllen) {
		//	free(msg_control);
		//}

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP |= timestamp;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		recvmsg_out_icmp(hdr, data_len, msg_controllen, flags);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		recvmsg_out_tcp(hdr, data_len, msg_controllen, flags);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		recvmsg_out_udp(hdr, data_len, msg_controllen, flags);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}

	//if (msg_controllen) {
	//	free(msg_control);
	//}
}

void getsockopt_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	int level;
	int optname;
	int optlen;
	uint8_t *optval;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = *(int *) pt;
	pt += sizeof(int);

	if (optlen > 0) { //TODO remove?
		optval = (uint8_t *) secure_malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
		return;
	}

	PRINT_DEBUG("");PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getsockopt_out_icmp(hdr, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		getsockopt_out_tcp(hdr, level, optname, optlen, optval);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		getsockopt_out_udp(hdr, level, optname, optlen, optval);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
	}
}

void setsockopt_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	int level;
	int optname;
	int optlen;
	uint8_t *optval;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = (int) (*(uint32_t *) pt);
	pt += sizeof(uint32_t);

	if (optlen > 0) {
		optval = (uint8_t *) secure_malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
		return;
	}

	PRINT_DEBUG("");PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
		return;
	}

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		setsockopt_out_icmp(hdr, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		setsockopt_out_tcp(hdr, level, optname, optlen, optval);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		setsockopt_out_udp(hdr, level, optname, optlen, optval);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		if (optlen > 0)
			free(optval);
	}
}

void release_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		release_out_icmp(hdr);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		release_out_tcp(hdr);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		release_out_udp(hdr);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void poll_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint8_t * pt;
	int events;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	pt = buf;

	events = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLERR);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL); //TODO check value?
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		poll_out_icmp(hdr, events);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		poll_out_tcp(hdr, events);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		poll_out_udp(hdr, events);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLERR);
	}
}

void mmap_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {
	uint8_t * pt;
	pt = buf;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		//mmap_tcp_icmp(hdr);
		PRINT_DEBUG("implement mmap_icmp");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		//mmap_tcp_out(hdr);
		PRINT_DEBUG("implement mmap_tcp");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		//mmap_out_udp(hdr);
		PRINT_DEBUG("implement mmap_udp");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void socketpair_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

}

void shutdown_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	int how;
	uint8_t * pt;

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	pt = buf;

	how = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = daemon_sockets[hdr->sock_index].type;
	int protocol = daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		shutdown_out_icmp(hdr, how);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		shutdown_out_tcp(hdr, how);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		shutdown_out_udp(hdr, how);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void close_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	daemon_sockets_remove(hdr->sock_index);

	PRINT_DEBUG("");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
}

void sendpage_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, ssize_t len) {

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

}

void connect_timeout(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	if (daemon_sockets[call->sock_index].sock_id != call->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, call->sock_id=%llu",
				call->sock_index, daemon_sockets[call->sock_index].sock_id, call->sock_id);

		nack_send(call->call_id, call->call_index, call->call_type, 0);
		daemon_calls_remove(call->call_index);
		return;
	}

	int type = daemon_sockets[call->sock_index].type;
	int protocol = daemon_sockets[call->sock_index].protocol;

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		PRINT_ERROR("todo error");
		//shouldn't occur
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		connect_timeout_tcp(call);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		PRINT_ERROR("todo error");
		//shouldn't occur
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	}
}

void accept_timeout(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	if (daemon_sockets[call->sock_index].sock_id != call->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, call->sock_id=%llu",
				call->sock_index, daemon_sockets[call->sock_index].sock_id, call->sock_id);

		nack_send(call->call_id, call->call_index, call->call_type, 0);
		daemon_calls_remove(call->call_index);
		return;
	}

	int type = daemon_sockets[call->sock_index].type;
	int protocol = daemon_sockets[call->sock_index].protocol;

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		PRINT_ERROR("todo error");
		//shouldn't occur
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		accept_timeout_tcp(call);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		PRINT_ERROR("todo error");
		//shouldn't occur
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	}
}

void recvmsg_timeout(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	if (daemon_sockets[call->sock_index].sock_id != call->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, call->sock_id=%llu",
				call->sock_index, daemon_sockets[call->sock_index].sock_id, call->sock_id);

		nack_send(call->call_id, call->call_index, call->call_type, 0);
		daemon_calls_remove(call->call_index);
		return;
	}

	int type = daemon_sockets[call->sock_index].type;
	int protocol = daemon_sockets[call->sock_index].protocol;

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		recvmsg_timeout_icmp(call);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		recvmsg_timeout_tcp(call);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		recvmsg_timeout_udp(call);
	} else {
		PRINT_ERROR("non supported socket type=%d, protocol=%d", type, protocol);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	}
}

int daemon_setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int daemon_setBlocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0; //TODO verify is right?
	return ioctl(fd, FIOBIO, &flags);
#endif
}

void handle_call_new(struct nl_wedge_to_daemon *hdr, uint8_t *msg_pt, ssize_t msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR ("call_index out of range: call_index=%d", hdr->call_index);
		return;
	}

	//############################### Debug
#ifdef DEBUG
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	uint8_t *pt;
	temp = (uint8_t *) secure_malloc(3 * msg_len + 1);
	pt = temp;
	int i;
	for (i = 0; i < msg_len; i++) {
		if (i == 0) {
			sprintf((char *) pt, "%02x", msg_pt[i]);
			pt += 2;
		} else if (i % 4 == 0) {
			sprintf((char *) pt, ":%02x", msg_pt[i]);
			pt += 3;
		} else {
			sprintf((char *) pt, " %02x", msg_pt[i]);
			pt += 3;
		}
	}
	temp[3 * msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);
#endif
	//###############################

	if (hdr->call_type == socket_call) {
		socket_out(hdr, msg_pt, msg_len);
	} else {
		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&daemon_sockets_sem);

		//---------------------- find
		if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_ERROR(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0); //TODO ret not valid descriptor
			return;
		}
		//----------------------

		daemon_sockets[hdr->sock_index].threads++;
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		struct daemon_socket *sock = &daemon_sockets[hdr->sock_index];

		secure_sem_wait(&sock->sem);
		if (sock->running) {
			switch (hdr->call_type) {
			case bind_call:
				//bind_call_handler(hdr, sock, msg_pt, msg_len);

				//In bind_call:
				if (sock->ops) {
					//sock->ops->bind(hdr, sock, addr);
				}
				break;
			}
		} else {
			PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			secure_sem_wait(&daemon_sockets_sem);
			daemon_sockets[hdr->sock_index].threads--;
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		}
		sem_post(&daemon_sockets[hdr->sock_index].sem);
	}
}

void daemon_out_ff(struct nl_wedge_to_daemon *hdr, uint8_t *msg_pt, ssize_t msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);

	//############################### Debug
#ifdef DEBUG
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	if (0) {
		uint8_t *pt;
		temp = (uint8_t *) secure_malloc(3 * msg_len + 1);
		pt = temp;
		int i;
		for (i = 0; i < msg_len; i++) {
			if (i == 0) {
				sprintf((char *) pt, "%02x", msg_pt[i]);
				pt += 2;
			} else if (i % 4 == 0) {
				sprintf((char *) pt, ":%02x", msg_pt[i]);
				pt += 3;
			} else {
				sprintf((char *) pt, " %02x", msg_pt[i]);
				pt += 3;
			}
		}
		temp[3 * msg_len] = '\0';
		PRINT_DEBUG("msg='%s'", temp);
		free(temp);
	}
#endif
	//###############################

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR ("call_index out of range: call_index=%d", hdr->call_index);
		return;
	}

	switch (hdr->call_type) {
	case socket_call:
		socket_out(hdr, msg_pt, msg_len);
		break;
	case bind_call:
		bind_out(hdr, msg_pt, msg_len);
		break;
	case listen_call:
		listen_out(hdr, msg_pt, msg_len);
		break;
	case connect_call:
		connect_out(hdr, msg_pt, msg_len);
		break;
	case accept_call:
		accept_out(hdr, msg_pt, msg_len);
		break;
	case getname_call:
		getname_out(hdr, msg_pt, msg_len);
		break;
	case ioctl_call:
		ioctl_out(hdr, msg_pt, msg_len);
		break;
	case sendmsg_call:
		sendmsg_out(hdr, msg_pt, msg_len);
		break;
	case recvmsg_call:
		recvmsg_out(hdr, msg_pt, msg_len);
		break;
	case getsockopt_call:
		getsockopt_out(hdr, msg_pt, msg_len);
		break;
	case setsockopt_call:
		setsockopt_out(hdr, msg_pt, msg_len);
		break;
	case release_call:
		release_out(hdr, msg_pt, msg_len);
		break;
	case poll_call:
		poll_out(hdr, msg_pt, msg_len);
		break;
	case mmap_call:
		mmap_out(hdr, msg_pt, msg_len); //TODO dummy
		break;
	case socketpair_call:
		socketpair_out(hdr, msg_pt, msg_len); //TODO dummy
		break;
	case shutdown_call:
		shutdown_out(hdr, msg_pt, msg_len); //TODO dummy
		break;
	case close_call:
		/**
		 * TODO fix the problem into remove daemonsockets
		 * the Queue Terminate function has a bug as explained into it
		 */
		close_out(hdr, msg_pt, msg_len);
		break;
	case sendpage_call:
		sendpage_out(hdr, msg_pt, msg_len);
		break;
	default:
		PRINT_ERROR("Dropping, received unknown call_type=%d", hdr->call_type)
		;
		break;
	}
}

void test_func_daemon(struct nl_wedge_to_daemon *hdr, uint8_t *msg_pt, ssize_t msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d, call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);

	//############################### Debug
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	uint8_t *pt;
	temp = (uint8_t *) secure_malloc(3 * msg_len + 1);
	pt = temp;
	int i;
	for (i = 0; i < msg_len; i++) {
		if (i == 0) {
			sprintf((char *) pt, "%02x", msg_pt[i]);
			pt += 2;
		} else if (i % 4 == 0) {
			sprintf((char *) pt, ":%02x", msg_pt[i]);
			pt += 3;
		} else {
			sprintf((char *) pt, " %02x", msg_pt[i]);
			pt += 3;
		}
	}
	temp[3 * msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);
	//###############################

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR ("call_index out of range: call_index=%d", hdr->call_index);
		return;
	}

	int events;
	pt = msg_pt;

	events = *(int *) pt;
	pt += sizeof(int);

	if (pt - msg_pt != msg_len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - msg_pt, msg_len);
		//nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
}

void *wedge_to_daemon(void *local) {
	PRINT_CRITICAL("Entered");

	int ret;

	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	int nfds = 1;
	struct pollfd fds[nfds];
	fds[0].fd = nl_sockfd;
	//fds[0].events = POLLIN | POLLERR; //| POLLPRI;
	fds[0].events = POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND;//| POLLERR;
	//fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	PRINT_DEBUG("fd: sock=%d, events=%x", nl_sockfd, fds[0].events);
	int time = 1000;

	uint8_t *recv_buf;
	recv_buf = (uint8_t *) secure_malloc(RECV_BUFFER_SIZE + 16); //16 = NLMSGHDR size

	struct sockaddr sockaddr_sender; // Needed for recvfrom
	socklen_t sockaddr_senderlen = sizeof(sockaddr_sender); // Needed for recvfrom
	memset(&sockaddr_sender, 0, sockaddr_senderlen);

	struct nlmsghdr *nlh;
	void *nl_buf; // Pointer to your actual data payload
	ssize_t nl_len, part_len; // Size of your actual data payload
	uint8_t *part_pt;

	uint8_t *msg_buf = NULL;
	ssize_t msg_len = -1;
	uint8_t *msg_pt = NULL;

	struct nl_wedge_to_daemon *hdr;
	int okFlag, doneFlag = 0;
	ssize_t test_msg_len;

	int pos;

	PRINT_DEBUG("Waiting for message from kernel");

	int counter = 0;
	while (daemon_proto.running_flag) {

		PRINT_DEBUG("NL counter = %d", counter++);

		//TODO find alternative? convert to event driven
		if (0) { //works but over taxes the nl socket, causing sendmsg to take 10+ ms.
			daemon_setNonblocking(nl_sockfd);
			do {
				ret = recvfrom(nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
			} while (daemon_proto.running_flag && ret <= 0);

			if (!daemon_proto.running_flag) {
				break;
			}

			if (ret == -1) {
				perror("recvfrom() caused an error");
				exit(-1);
			}

			daemon_setBlocking(nl_sockfd);
		}
		if (0) { //works but blocks, so can't shutdown properly, have to double ^C or kill
			ret = recvfrom(nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);

			if (!daemon_proto.running_flag) {
				break;
			}

			if (ret == -1) {
				perror("recvfrom() caused an error");
				exit(-1);
			}
		}
		if (1) { //works, appears to be minor overhead, select/poll have fd cap if increase num of nl sockets
			do {
				ret = poll(fds, nfds, time);
			} while (daemon_proto.running_flag && ret <= 0);

			if (!daemon_proto.running_flag) {
				break;
			}

			if (fds[0].revents & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
				ret = recvfrom(nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
			} else {
				PRINT_ERROR("nl poll error");
				perror("nl poll");
				break;
			}
		}

		//PRINT_DEBUG("%d", sockaddr_sender);

		nlh = (struct nlmsghdr *) recv_buf;

		if ((okFlag = NLMSG_OK(nlh, ret))) {
			switch (nlh->nlmsg_type) {
			case NLMSG_NOOP:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP");
				break;
			case NLMSG_ERROR:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_ERROR")
				;
			case NLMSG_OVERRUN:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_OVERRUN")
				;
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE");
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default");
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len=%d", nl_len);

				part_pt = nl_buf;
				test_msg_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);

				//PRINT_DEBUG("test_msg_len=%d, msg_len=%d", test_msg_len, msg_len);

				if (msg_len == -1) {
					msg_len = test_msg_len;
				} else if (test_msg_len != msg_len) {
					okFlag = 0;
					PRINT_ERROR("test_msg_len != msg_len");
					//could just malloc msg_buff again
					break;//might comment out or make so start new
				}

				part_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);
				if (part_len > RECV_BUFFER_SIZE) {
					PRINT_ERROR("part_len (%d) > RECV_BUFFER_SIZE (%d)", part_len, RECV_BUFFER_SIZE);
				}

				//PRINT_DEBUG("part_len=%d", part_len);

				pos = *(int *) part_pt;
				part_pt += sizeof(int);
				if (pos > msg_len || pos != msg_pt - msg_buf) {
					if (pos > msg_len) {
						PRINT_ERROR("pos > msg_len");
					} else {
						PRINT_ERROR("pos != msg_pt - msg_buf");
					}
				}

				//PRINT_DEBUG("pos=%d", pos);

				PRINT_DEBUG("msg_len=%d, part_len=%d, pos=%d, seq=%d", msg_len, part_len, pos, nlh->nlmsg_seq);

				if (nlh->nlmsg_seq == 0) {
					if (msg_buf != NULL) {
						PRINT_ERROR("error: msg_buf != NULL at new sequence, freeing");
						free(msg_buf);
					}
					msg_buf = (uint8_t *) secure_malloc(msg_len);
					msg_pt = msg_buf;
				}

				if (msg_pt != NULL) {
					msg_pt = msg_buf + pos; //atm redundant, is for if out of sync msgs
					memcpy(msg_pt, part_pt, part_len);
					msg_pt += part_len;
				} else {
					PRINT_ERROR("error: msg_pt is NULL");
				}

				if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
					//doneFlag = 1; //not multi-part msg //removed multi
				}
				break;
			}
		}

		if (okFlag != 1) {
			doneFlag = 0;
			PRINT_ERROR("okFlag != 1");
			//send kernel a resend request
			//with pos of part being passed can store msg_buf, then recopy new part when received
		}

		if (doneFlag) {
			if (msg_len < sizeof(struct nl_wedge_to_daemon)) {
				//TODOD error
				PRINT_ERROR("todo error");
			}

			hdr = (struct nl_wedge_to_daemon *) msg_buf;
			msg_pt = msg_buf + sizeof(struct nl_wedge_to_daemon);
			msg_len -= sizeof(struct nl_wedge_to_daemon);

			daemon_out_ff(hdr, msg_pt, msg_len);

			free(msg_buf);
			doneFlag = 0;
			msg_buf = NULL;
			msg_pt = NULL;
			msg_len = -1;
		}
	}

	free(recv_buf);
	close(nl_sockfd);

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
}

void *switch_to_daemon(void *local) {
	PRINT_CRITICAL("Entered");

	while (daemon_proto.running_flag) {
		daemon_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
}

void daemon_handle_to(struct daemon_call *call) { //TODO finish transitioning to this TO system
	PRINT_DEBUG("Entered: call=%p, call_index=%d", call, call->call_index);

	//TO for call
	//split call by call_type/sock_type, poll_timeout_tcp

	switch (call->call_type) {
	case connect_call:
		connect_timeout(call);
		break;
	case accept_call:
		accept_timeout(call);
		break;
	case recvmsg_call:
		recvmsg_timeout(call);
		break;
		//Close or poll? sendmsg TO in TCP
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call->call_type)
		;
		//exit(1);
		break;
	}
}

void daemon_interrupt(void) {
	PRINT_DEBUG("Entered");

	int i = 0;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);

	for (i = 0; i < MAX_CALLS; i++) {
		if (daemon_calls[i].sock_id != -1 && daemon_calls[i].to_flag) {
			daemon_calls[i].to_flag = 0;

			daemon_handle_to(&daemon_calls[i]);
		}
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);
}

void daemon_get_ff(void) {
	struct finsFrame *ff;

	do {
		secure_sem_wait(daemon_proto.event_sem);
		secure_sem_wait(daemon_proto.input_sem);
		ff = read_queue(daemon_proto.input_queue);
		sem_post(daemon_proto.input_sem);
	} while (daemon_proto.running_flag && ff == NULL && !daemon_interrupt_flag); //TODO change logic here, combine with switch_to_daemon?

	if (!daemon_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == CONTROL) {
			daemon_fcf(ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (ff->dataFrame.directionFlag == UP) {
				daemon_in_fdf(ff);
				PRINT_DEBUG("");
			} else { //directionFlag==DOWN
				PRINT_ERROR("todo error");
				//drop
			}
		} else {
			PRINT_ERROR("todo error");
		}
	} else if (daemon_interrupt_flag) {
		daemon_interrupt_flag = 0;

		daemon_interrupt();
	} else {
		PRINT_ERROR("todo error");
	}
}

void daemon_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo")
		;
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo")
		;
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo")
		;
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		daemon_read_param_reply(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		PRINT_ERROR("todo")
		;
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		daemon_set_param_reply(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		daemon_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		daemon_exec_reply(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		daemon_error(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo")
		;
		freeFinsFrame(ff);
		break;
	}
}

void daemon_read_param_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int call_index = daemon_calls_find(ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,

	if (call_index == -1) {
		PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		freeFinsFrame(ff);
		return;
	}

	uint32_t call_id = daemon_calls[call_index].call_id;
	uint32_t call_type = daemon_calls[call_index].call_type;

	uint64_t sock_id = daemon_calls[call_index].sock_id;
	int sock_index = daemon_calls[call_index].sock_index;

	uint32_t data = daemon_calls[call_index].data;

	daemon_calls_remove(call_index);

	if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}
	if (call_type == poll_call || call_type == recvmsg_call) {
		call_list_remove(daemon_sockets[sock_index].call_list, &daemon_calls[call_index]);
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	switch (call_type) {
	case getsockopt_call:
		getsockopt_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index, data); //CTRL_READ_PARAM_REPLY
		break;
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call_type)
		;
		//exit(1);
		break;
	}
}

void daemon_exec_reply_new(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//metadata *params = ff->metaData;
	switch (ff->ctrlFrame.param_id) {

	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id)
		;
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void daemon_set_param_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int call_index = daemon_calls_find(ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,

	if (call_index == -1) {
		PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		freeFinsFrame(ff);
		return;
	}

	uint32_t call_id = daemon_calls[call_index].call_id;
	uint32_t call_type = daemon_calls[call_index].call_type;

	uint64_t sock_id = daemon_calls[call_index].sock_id;
	int sock_index = daemon_calls[call_index].sock_index;

	uint32_t data = daemon_calls[call_index].data;

	daemon_calls_remove(call_index);

	if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}
	if (call_type == poll_call || call_type == recvmsg_call) {
		call_list_remove(daemon_sockets[sock_index].call_list, &daemon_calls[call_index]);
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	switch (call_type) {
	case setsockopt_call:
		setsockopt_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index, data); //CTRL_SET_PARAM_REPLY
		break;
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call_type)
		;
		//exit(1);
		break;
	}
}

void daemon_exec(struct finsFrame *ff) {
	uint32_t protocol;
	uint32_t ret_msg;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *params = ff->metaData;
	switch (ff->ctrlFrame.param_id) {
	case EXEC_TCP_POLL_POST: //TODO move to ALERT?
		PRINT_DEBUG("param_id=EXEC_TCP_POLL_POST (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(params, "protocol", &protocol);
		secure_metadata_readFromElement(params, "ret_msg", &ret_msg);

		switch (protocol) {
		case IPPROTO_ICMP:
			//daemon_icmp_in_error(ff, src_ip, dst_ip);
			PRINT_ERROR("todo")
			;
			break;
		case IPPROTO_TCP:
			daemon_tcp_in_poll(ff, ret_msg);
			break;
		case IPPROTO_UDP:
			//daemon_udp_in_error(ff, src_ip, dst_ip);
			PRINT_ERROR("todo")
			;
			break;
		default:
			//PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
			//freeFinsFrame(ff);
			break;
		}
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id)
		;
		//TODO implement?

		ff->destinationID.id = ff->ctrlFrame.senderID;

		ff->ctrlFrame.senderID = DAEMON_ID;
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		ff->ctrlFrame.ret_val = 0;

		daemon_to_switch(ff);
		break;
	}
}

void daemon_exec_reply(struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	struct daemon_call *call = call_list_find_serial_num(expired_call_list, ff->ctrlFrame.serial_num);
	if (call) {
		call_list_remove(expired_call_list, call);

		if (daemon_sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
			PRINT_ERROR("Exited, socket closed: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			freeFinsFrame(ff);
			return;
		}
		//TODO something?
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		switch (call->call_type) {
		case connect_call:
			connect_expired_tcp(ff, call, 0); //TODO include data? or don't post until after?
			break;
		case accept_call:
			accept_expired_tcp(ff, call, 0);
			break;
		default:
			PRINT_ERROR("Not supported dropping: call_type=%d", call->call_type)
			;
			//exit(1);
			break;
		}
	} else {
		int call_index = daemon_calls_find(ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,
		if (call_index == -1) {
			PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			freeFinsFrame(ff);
			return;
		} else {
			uint32_t call_id = daemon_calls[call_index].call_id;

			int call_pid = daemon_calls[call_index].call_pid;
			uint32_t call_type = daemon_calls[call_index].call_type;

			uint64_t sock_id = daemon_calls[call_index].sock_id;
			int sock_index = daemon_calls[call_index].sock_index;

			uint32_t flags = daemon_calls[call_index].flags;
			uint32_t data = daemon_calls[call_index].data;

			uint64_t sock_id_new = daemon_calls[call_index].sock_id_new;
			int sock_index_new = daemon_calls[call_index].sock_index_new;

			daemon_calls_remove(call_index);

			if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
				PRINT_ERROR("Exited, socket closed: ff=%p", ff);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(call_id, call_index, call_type, 0);
				freeFinsFrame(ff);
				return;
			}
			if (call_type == poll_call || call_type == recvmsg_call) {
				call_list_remove(daemon_sockets[sock_index].call_list, &daemon_calls[call_index]);
			}

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			switch (call_type) {
			case connect_call:
				connect_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index, flags); //TODO include data? or don't post until after?
				break;
			case accept_call:
				accept_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index, sock_id_new, sock_index_new, flags);
				break;
			case sendmsg_call:
				sendmsg_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index, flags); //FDF, so get EXEC? //atm CTRL_EXEC_REPLY
				break;
			case release_call:
				release_in_tcp(ff, call_id, call_index, call_type, sock_id, sock_index);
				break;
			case poll_call:
				poll_in_tcp_fcf(ff, call_id, call_index, call_pid, call_type, sock_id, sock_index, data, flags); //CTRL_EXEC_REPLY
				break;
			default:
				PRINT_ERROR("Not supported dropping: call_type=%d", call_type)
				;
				//exit(1);
				break;
			}
		}
	}
}

void daemon_error(struct finsFrame *ff) { //TODO expand for different error types, atm only for TTL expired/dest unreach
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	uint32_t protocol;
	uint32_t src_ip;
	uint32_t dst_ip;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_protocol", &protocol);
	secure_metadata_readFromElement(params, "send_src_ip", &src_ip);
	secure_metadata_readFromElement(params, "send_dst_ip", &dst_ip);

	//ff->ctrlFrame.data_len = sent->data_len;
	//ff->ctrlFrame.data = sent->data;

	switch (protocol) {
	case IPPROTO_ICMP:
		daemon_icmp_in_error(ff, src_ip, dst_ip);
		break;
	case IPPROTO_TCP:
		daemon_tcp_in_error(ff, src_ip, dst_ip);
		break;
	case IPPROTO_UDP:
		daemon_udp_in_error(ff, src_ip, dst_ip);
		break;
	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol)
		;
		freeFinsFrame(ff);
		break;
	}
}

void daemon_in_fdf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, len=%d", ff, ff->metaData, ff->dataFrame.pduLength);

	uint32_t protocol = 0;
	uint32_t dst_ip = 0;
	uint32_t src_ip = 0;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "recv_protocol", &protocol);
	secure_metadata_readFromElement(params, "recv_src_ip", &src_ip);
	secure_metadata_readFromElement(params, "recv_dst_ip", &dst_ip);

	//##############################################
#ifdef DEBUG
	struct in_addr *temp = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
	if (src_ip) {
		temp->s_addr = htonl(src_ip);
	} else {
		temp->s_addr = 0;
	}
	struct in_addr *temp2 = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
	if (dst_ip) {
		temp2->s_addr = htonl(dst_ip);
	} else {
		temp2->s_addr = 0;
	}
	PRINT_DEBUG("ff=%p, prot=%u", ff, protocol);
	PRINT_DEBUG("src=%s (%u)", inet_ntoa(*temp), src_ip);
	PRINT_DEBUG("dst=%s (%u)", inet_ntoa(*temp2), dst_ip);

	free(temp);
	free(temp2);

	char *buf = (char *) secure_malloc(ff->dataFrame.pduLength + 1);
	memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	buf[ff->dataFrame.pduLength] = '\0';
	PRINT_DEBUG("pdulen=%u, pdu='%s'", ff->dataFrame.pduLength, buf);
	free(buf);
#endif
	//##############################################

	switch (protocol) {
	case IPPROTO_ICMP:
		daemon_icmp_in_fdf(ff, src_ip, dst_ip);
		break;
	case IPPROTO_TCP:
		daemon_tcp_in_fdf(ff, src_ip, dst_ip);
		break;
	case IPPROTO_UDP:
		daemon_udp_in_fdf(ff, src_ip, dst_ip);
		break;
	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol)
		;
		freeFinsFrame(ff);
		break;
	}
}

void daemon_init(void) {
	PRINT_CRITICAL("Entered");
	daemon_proto.running_flag = 1;

	module_create_ops(&daemon_proto);
	module_register(&daemon_proto);

	//init_daemonSockets();
	daemon_thread_count = 0;

	int i;
	sem_init(&daemon_sockets_sem, 0, 1);
	for (i = 0; i < MAX_SOCKETS; i++) {
		daemon_sockets[i].sock_id = -1;
		daemon_sockets[i].state = SS_FREE;
	}

	for (i = 0; i < MAX_CALLS; i++) {
		daemon_calls[i].call_id = -1;

		daemon_calls[i].to_running = 1;
		daemon_calls[i].to_flag = 0;
		daemon_calls[i].to_fd = timerfd_create(CLOCK_REALTIME, 0);
		if (daemon_calls[i].to_fd == -1) {
			PRINT_ERROR("ERROR: unable to create to_fd.");
			exit(-1);
		}

		//start timer thread
		struct intsem_to_thread_data *to_data = (struct intsem_to_thread_data *) secure_malloc(sizeof(struct intsem_to_thread_data));
		to_data->id = ++daemon_thread_count;
		to_data->fd = daemon_calls[i].to_fd;
		to_data->running = &daemon_calls[i].to_running;
		to_data->flag = &daemon_calls[i].to_flag;
		to_data->interrupt = &daemon_interrupt_flag;
		to_data->sem = daemon_proto.event_sem;
		secure_pthread_create(&daemon_calls[i].to_thread, NULL, intsem_to_thread, (void *) to_data);
	}

	expired_call_list = call_list_create(MAX_CALLS);

	//init the netlink socket connection to daemon
	nl_sockfd = init_fins_nl();
	if (nl_sockfd == -1) {
		perror("init_fins_nl() caused an error");
		exit(-1);
	}

	//prime the kernel to establish daemon's PID
	int daemoncode = daemon_start_call;
	int ret;
	ret = send_wedge(nl_sockfd, (uint8_t *) &daemoncode, sizeof(int), 0);
	if (ret != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_CRITICAL("Connected to wedge at fd=%d", nl_sockfd);
}

void daemon_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	secure_pthread_create(&wedge_to_daemon_thread, fins_pthread_attr, wedge_to_daemon, fins_pthread_attr);
	secure_pthread_create(&switch_to_daemon_thread, fins_pthread_attr, switch_to_daemon, fins_pthread_attr);
}

void daemon_shutdown(void) {
	PRINT_CRITICAL("Entered");
	daemon_proto.running_flag = 0;
	sem_post(daemon_proto.event_sem);

	//prime the kernel to establish daemon's PID
	int daemoncode = daemon_stop_call;
	int ret = send_wedge(nl_sockfd, (uint8_t *) &daemoncode, sizeof(int), 0);
	if (ret) {
		PRINT_DEBUG("send_wedge failure");
		//perror("sendfins() caused an error");
	}
	PRINT_CRITICAL("Disconnecting to wedge at fd=%d", nl_sockfd);

	PRINT_CRITICAL("Joining switch_to_daemon_thread");
	pthread_join(switch_to_daemon_thread, NULL);
	PRINT_CRITICAL("Joining wedge_to_daemon_thread");
	pthread_join(wedge_to_daemon_thread, NULL); //TODO change thread so can be stopped, atm is blocking
}

void daemon_release(void) {
	PRINT_CRITICAL("Entered");

	//unregister
	module_unregister(daemon_proto.module_id);

	//TODO free all module related mem

	PRINT_CRITICAL("expired_call_list->len=%u", expired_call_list->len);
	call_list_free(expired_call_list);

	int i = 0;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id != -1) {
			daemon_sockets_remove(i); //TODO replace inner with this?
			/*
			 PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d", daemon_sockets[sock_index].sock_id, sock_index);
			 daemon_sockets[i].sock_id = -1;
			 daemon_sockets[i].state = SS_FREE;

			 //TODO stop all threads related to

			 //TODO send NACK for each call in call_list

			 while (!call_list_is_empty(daemon_sockets[i].call_list)) {
			 call = call_list_remove_front(daemon_sockets[i].call_list);

			 nack_send(call->call_id, call->call_index, call->call_type, 0);

			 daemon_calls_remove(call->call_index);
			 }
			 call_list_free(daemon_sockets[i].call_list);

			 term_queue(daemon_sockets[i].dataQueue);
			 */
		}
	}

	for (i = 0; i < MAX_CALLS; i++) {
		daemon_calls_shutdown(i);
	}

	sem_destroy(&nl_sem);
	sem_destroy(&daemon_sockets_sem);

	module_destroy_ops(&daemon_proto);
}
