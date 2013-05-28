/*  
 * fins_stack_wedge.c -
 */

/* License and signing info */
//#define M_LICENSE	"GPL"	// Most common, but we're releasing under BSD 3-clause, the
#define M_LICENSE	"GPL and additional rights"
#define M_DESCRIPTION	"Unregisters AF_INET and registers the FINS protocol in its place"
#define M_AUTHOR	"Jonathan Reed <jonathanreed07@gmail.com>"

#include "fins_stack_wedge.h"	/* Defs for this module */

#define RECV_BUFFER_SIZE	4096//1024//NLMSG_DEFAULT_SIZE//NLMSG_GOODSIZE//16384//8192	// Same as userspace, Pick an appropriate value here //NLMSG_GOODSIZE
#define AF_FINS 2
#define PF_FINS AF_FINS
#define NETLINK_FINS 20

//commenting stops debug printout
#define DEBUG
#define IMPORTANT
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printk("FINS: DEBUG: %s, %d: "format"\n", __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) printk("FINS: IMPORTANT: %s, %d: "format"\n", __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printk("FINS: ERROR: %s, %d: "format"\n", __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif

// Create one semaphore here for every socketcall that is going to block
struct fins_wedge_socket wedge_sockets[MAX_SOCKETS];
struct semaphore wedge_sockets_sem;

struct fins_wedge_call wedge_calls[MAX_CALLS];
struct semaphore wedge_calls_sem; //TODO merge with sockets_sem?
__u32 call_count; //TODO fix eventual roll over problem

// Data declarations
/* Data for netlink sockets */
struct sock *fins_nl_sk = NULL;
__s32 fins_daemon_pid; // holds the pid of the FINS daemon so we know who to send back to
struct semaphore link_sem;

void wedge_calls_init(void) {
	__s32 i;
	PRINT_DEBUG("Entered");

	call_count = 0;

	sema_init(&wedge_calls_sem, 1);
	for (i = 0; i < MAX_CALLS; i++) {
		wedge_calls[i].call_id = -1;
	}

	PRINT_DEBUG("Exited.");
}

__s32 wedge_calls_insert(__u32 call_id, __u64 sock_id, __s32 sock_index, __u32 call_type) { //TODO might not need sock
	__s32 i;

	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d, call_id=%u, call_type=%u", sock_id, sock_index, call_id, call_type);

	for (i = 0; i < MAX_CALLS; i++) {
		if (wedge_calls[i].call_id == -1) {
			wedge_calls[i].running = 1;

			wedge_calls[i].call_id = call_id;
			wedge_calls[i].call_type = call_type;

			wedge_calls[i].sock_id = sock_id;
			wedge_calls[i].sock_index = sock_index;

			//sema_init(&wedge_calls[i].sem, 1);
			wedge_calls[i].reply = 0;
			sema_init(&wedge_calls[i].wait_sem, 0);

			wedge_calls[i].ret = 0;

			PRINT_DEBUG("Exited: rc=%d", i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: rc=%d", -1);
	return -1;
}

__s32 wedge_calls_find(__u64 sock_id, __s32 sock_index, __u32 call_type) {
	__u32 i;

	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d, call_type=%u", sock_id, sock_index, call_type);

	for (i = 0; i < MAX_CALLS; i++) {
		if (wedge_calls[i].call_id != -1 && wedge_calls[i].sock_id == sock_id && wedge_calls[i].sock_index == sock_index && wedge_calls[i].call_type
				== call_type) { //TODO remove sock_index? maybe unnecessary
			PRINT_DEBUG("Exited: rc=%d", i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: rc=%d", -1);
	return -1;
}

__s32 wedge_calls_remove(__u32 call_id) { //TODO remove? not used since id/index typicall tied, & removal doesn't need locking
	__s32 i;

	PRINT_DEBUG("Entered: call_id=%u", call_id);

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	for (i = 0; i < MAX_CALLS; i++) {
		if (wedge_calls[i].call_id == call_id) {
			wedge_calls[i].call_id = -1;

			up(&wedge_calls_sem);

			//TODO finish
			return (1);
		}
	}
	up(&wedge_calls_sem);
	return (-1);
}

void wedge_calls_remove_all(void) {
	__u32 i;

	PRINT_DEBUG("Entered");

	for (i = 0; i < MAX_CALLS; i++) {
		if (wedge_calls[i].call_id != -1) {
			up(&wedge_calls[i].wait_sem);

			msleep(1); //TODO may need to change
		}
	}
}

void wedge_sockets_init(void) {
	__s32 i;

	PRINT_DEBUG("Entered");

	sema_init(&wedge_sockets_sem, 1);
	for (i = 0; i < MAX_SOCKETS; i++) {
		wedge_sockets[i].sock_id = -1;
	}

	//PRINT_DEBUG("Exited.");
}

__s32 wedge_sockets_insert(__u64 sock_id, struct sock *sk) { //TODO might not need sock
	__s32 i;
	__s32 j;

	PRINT_DEBUG("Entered: sock_id%llu, sk=%p", sock_id, sk);

	for (i = 0; i < MAX_SOCKETS; i++) {
		if ((wedge_sockets[i].sock_id == -1)) {
			wedge_sockets[i].running = 1;

			wedge_sockets[i].sock_id = sock_id;
			wedge_sockets[i].sk = sk;

			for (j = 0; j < MAX_CALL_TYPES; j++) {
				wedge_sockets[i].threads[j] = 0;
			}

			wedge_sockets[i].release_flag = 0;
			wedge_sockets[i].sk_new = NULL;

			PRINT_DEBUG("Exited: rc=%d", i);
			return i;
			//return i;
		}
	}

	PRINT_DEBUG("Exited: rc=%d", -1);
	return -1;
	//return -1;
}

__s32 wedge_sockets_find(__u64 sock_id) {
	__s32 i;

	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (wedge_sockets[i].sock_id == sock_id) {
			PRINT_DEBUG("Exited: rc=%d", i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: rc=%d", -1);
	return -1;
}

__s32 wedge_sockets_remove(__u64 sock_id, __s32 sock_index, __u32 call_type) {
	__u32 i;
	__s32 call_index;

	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d, call_type=%u", sock_id, sock_index, call_type);

	for (i = 0; i < MAX_CALL_TYPES; i++) {
		while (1) {
			if (wedge_sockets[sock_index].threads[i] < 1 || (i == call_type && wedge_sockets[sock_index].threads[i] < 2)) {
				break;
			}
			up(&wedge_sockets_sem);

			if (down_interruptible(&wedge_calls_sem)) {
				PRINT_ERROR("calls_sem acquire fail");
				//TODO error
			}
			call_index = wedge_calls_find(sock_id, sock_index, i);
			up(&wedge_calls_sem);
			if (call_index == -1) {
				break;
			}
			up(&wedge_calls[call_index].wait_sem);

			msleep(1); //TODO may need to change

			if (down_interruptible(&wedge_sockets_sem)) {
				PRINT_ERROR("sockets_sem acquire fail");
				//TODO error
			}
		}
	}

	wedge_sockets[sock_index].sock_id = -1;

	return 0;
}

void wedge_socket_remove_all(void) {
	__u32 i;
	__u32 j;
	__s32 call_index;

	PRINT_DEBUG("Entered");

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (wedge_sockets[i].sock_id != -1) {
			for (j = 0; j < MAX_CALL_TYPES; j++) {
				while (1) {
					if (wedge_sockets[i].threads[j] < 1) {
						break;
					}
					up(&wedge_sockets_sem);

					if (down_interruptible(&wedge_calls_sem)) {
						PRINT_ERROR("calls_sem acquire fail");
						//TODO error
					}
					call_index = wedge_calls_find(wedge_sockets[i].sock_id, i, j);
					up(&wedge_calls_sem);
					if (call_index == -1) {
						break;
					}
					up(&wedge_calls[call_index].wait_sem);

					msleep(1); //TODO may need to change

					if (down_interruptible(&wedge_sockets_sem)) {
						PRINT_ERROR("sockets_sem acquire fail");
						//TODO error
					}
				}
			}

			wedge_sockets[i].sock_id = -1;
		}
	}
}

__s32 threads_incr(__s32 sock_index, __u32 call) {
	//__s32 ret = 1;
	//return ret;
	return 1;
}

__s32 threads_decr(__s32 sock_index, __u32 call) {
	//__s32 ret = 0;
	//return ret;
	return 0;
}

__s32 wedge_sockets_wait(__u64 sock_id, __s32 sock_index, __u32 calltype) {
	//__s32 error = 0;

	PRINT_DEBUG("Entered for sock=%llu, sock_index=%d, call=%u", sock_id, sock_index, calltype);

	PRINT_DEBUG("Exited: rc=%d", 0);
	return 0;
}

__s32 checkConfirmation(__s32 call_index) {
	PRINT_DEBUG("Entered: call_index=%d", call_index);

	//extract msg from reply in wedge_calls[sock_index]
	if (wedge_calls[call_index].ret == ACK) {
		PRINT_DEBUG("recv ACK");
		if (wedge_calls[call_index].len == 0) {
			//return 0;
			return wedge_calls[call_index].msg;
		} else {
			PRINT_ERROR("wedge_calls[sock_index].reply_buf error, wedge_calls[%d].len=%d, wedge_calls[%d].buf=%p",
					call_index, wedge_calls[call_index].len, call_index, wedge_calls[call_index].buf);
			return -1;
		}
	} else if (wedge_calls[call_index].ret == NACK) {
		PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
		return -wedge_calls[call_index].msg;
	} else {
		PRINT_ERROR("error, acknowledgement: %u", wedge_calls[call_index].ret);
		return -1;
	}
}

/* FINS Netlink functions  */
/*
 * Sends len bytes from buffer buf to process pid, and sets the flags.
 * If buf is longer than RECV_BUFFER_SIZE, it's broken into sequential messages.
 * Returns 0 if successful or -1 if an error occurred.
 */

//assumes msg_buf is just the msg, does not have a prepended msg_len
//break msg_buf into parts of size RECV_BUFFER_SIZE with a prepended header (header part of RECV...)
//prepend msg header: total msg length, part length, part starting position
__s32 nl_send_msg(__s32 pid, __u32 seq, __s32 type, void *buf, __s32 len, __s32 flags) {
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	__s32 ret_val;

	//#################### Debug
#ifdef DEBUG
	__u8 *print_buf;
	__u8 *print_pt;
	__u8 *pt;
	__s32 i;
#endif
	//####################

	PRINT_DEBUG("Entered: pid=%d, seq=%d, type=%d, len=%d", pid, seq, type, len);

	//####################
#ifdef DEBUG
	if (0) {
		print_buf = (__u8 *) kmalloc(3 * len + 1, GFP_KERNEL);
		if (print_buf == NULL) {
			PRINT_ERROR("print_buf allocation fail");
		} else {
			print_pt = print_buf;
			pt = buf;
			for (i = 0; i < len; i++) {
				if (i == 0) {
					sprintf(print_pt, "%02x", *(pt + i));
					print_pt += 2;
				} else if (i % 4 == 0) {
					sprintf(print_pt, ":%02x", *(pt + i));
					print_pt += 3;
				} else {
					sprintf(print_pt, " %02x", *(pt + i));
					print_pt += 3;
				}
			}
			*print_pt = '\0';
			PRINT_DEBUG("buf='%s'", print_buf);
			kfree(print_buf);
		}
	}
#endif
	//####################

	// Allocate a new netlink message
	skb = nlmsg_new(len, 0); // nlmsg_new(size_t payload, gfp_t flags)
	if (skb == NULL) {
		PRINT_ERROR("netlink Failed to allocate new skb");
		return -1;
	}

	// Load nlmsg header
	// nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, __s32 type, __s32 payload, __s32 flags)
	nlh = nlmsg_put(skb, KERNEL_PID, seq, type, len, flags);
	NETLINK_CB(skb).dst_group = 0; // not in a multicast group

	// Copy data into buffer
	memcpy(NLMSG_DATA(nlh), buf, len);

	// Send the message
	//ret_val = nlmsg_unicast(fins_nl_sk, skb, pid);
	ret_val = netlink_unicast(fins_nl_sk, skb, pid, 0); //blocking

	if (ret_val < 0) {
		PRINT_ERROR("netlink error sending to user");

		return -1;
	}

	PRINT_DEBUG("Exited: pid=%d, seq=%d, type=%d, len=%d, ret_val=%d", pid, seq, type, len, ret_val);
	return 0;
}

__s32 nl_send(__s32 pid, void *msg_buf, __u32 msg_len, __s32 flags) {
	__s32 ret;
	void *part_buf;
	__u8 *msg_pt;
	__s32 pos;
	__u32 seq;
	struct nl_wedge_to_daemon_hdr *part_hdr;
	__u8 *msg_start;
	__s32 header_size;
	__s32 part_len;

	//#################### Debug
#ifdef DEBUG
	__u8 *print_buf;
	__u8 *print_pt;
	__u8 *pt;
	__s32 i;
#endif
	//####################

	PRINT_DEBUG("Entered: pid=%d, msg_buf=%p, msg_len=%u, flags=0x%x", pid, msg_buf, msg_len, flags);

	if (down_interruptible(&link_sem)) {
		PRINT_ERROR("link_sem acquire fail");
	}

	//#################### Debug
#ifdef DEBUG
	if (0) {
		print_buf = (__u8 *) kmalloc(3 * msg_len + 1, GFP_KERNEL);
		if (print_buf == NULL) {
			PRINT_ERROR("print_buf allocation fail");
		} else {
			print_pt = print_buf;
			pt = msg_buf;
			for (i = 0; i < msg_len; i++) {
				if (i == 0) {
					sprintf(print_pt, "%02x", *(pt + i));
					print_pt += 2;
				} else if (i % 4 == 0) {
					sprintf(print_pt, ":%02x", *(pt + i));
					print_pt += 3;
				} else {
					sprintf(print_pt, " %02x", *(pt + i));
					print_pt += 3;
				}
			}
			*print_pt = '\0';
			PRINT_DEBUG("msg_buf='%s'", print_buf);
			kfree(print_buf);
		}
	}
#endif
	//####################

	part_buf = (__u8 *) kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
	if (part_buf == NULL) {
		PRINT_ERROR("part_buf allocation fail");
		up(&link_sem);
		return -1;
	}

	msg_pt = msg_buf;
	pos = 0;
	seq = 0;

	part_hdr = (struct nl_wedge_to_daemon_hdr *) part_buf;
	msg_start = part_buf + sizeof(struct nl_wedge_to_daemon_hdr);

	header_size = sizeof(struct nl_wedge_to_daemon_hdr);
	part_len = RECV_BUFFER_SIZE - header_size;

	part_hdr->msg_len = msg_len;
	part_hdr->part_len = part_len;

	while (msg_len - pos > part_len) {
		PRINT_DEBUG("pos=%d, seq=%d", pos, seq);

		part_hdr->pos = pos;

		memcpy(msg_start, msg_pt, part_len);

		ret = nl_send_msg(pid, seq, 0x0, part_buf, RECV_BUFFER_SIZE, flags/*| NLM_F_MULTI*/);
		if (ret < 0) {
			PRINT_ERROR("netlink error sending seq %d to user", seq);
			up(&link_sem);
			PRINT_DEBUG("Exited: pid=%d, msg_buf=%p, msg_len=%u, flags=0x%x, ret=%d", pid, msg_buf, msg_len, flags, -1);
			return -1;
		}
		//msleep(1);

		msg_pt += part_len;
		pos += part_len;
		seq++;
	}

	PRINT_DEBUG("pos=%d, seq=%d", pos, seq);

	part_len = msg_len - pos;
	part_hdr->part_len = part_len;
	part_hdr->pos = pos;

	memcpy(msg_start, msg_pt, part_len);

	ret = nl_send_msg(pid, seq, NLMSG_DONE, part_buf, header_size + part_len, flags);
	if (ret < 0) {
		PRINT_ERROR("netlink error sending seq %d to user", seq);
		up(&link_sem);
		PRINT_DEBUG("Exited: pid=%d, msg_buf=%p, msg_len=%u, flags=0x%x, ret=%d", pid, msg_buf, msg_len, flags, -1);
		return -1;
	}

	kfree(part_buf);
	up(&link_sem);

	PRINT_DEBUG("Exited: pid=%d, msg_buf=%p, msg_len=%u, flags=0x%x, ret=%d", pid, msg_buf, msg_len, flags, 0);
	return 0;
}

/*
 * This function is automatically called when the kernel receives a datagram on the corresponding netlink socket.
 */
void nl_data_ready(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	__u8 *buf; // Pointer to data in payload
	__s32 len; // Payload length
	__s32 pid; // pid of sending process
	struct nl_daemon_to_wedge *hdr;

	__u32 reply_call; // a number corresponding to the type of socketcall this packet is in response to

	PRINT_DEBUG("Entered: skb=%p", skb);

	if (skb == NULL) {
		PRINT_DEBUG("Exiting: skb NULL \n");
		return;
	}
	nlh = (struct nlmsghdr *) skb->data;
	pid = nlh->nlmsg_pid; // get pid from the header

	// Get a pointer to the start of the data in the buffer and the buffer (payload) length
	buf = (__u8 *) (NLMSG_DATA(nlh));
	len = NLMSG_PAYLOAD(nlh, 0);

	PRINT_DEBUG("nl_pid=%d, nl_len=%d", pid, len);

	// **** Remember the LKM must be up first, then the daemon,
	// but the daemon must make contact before any applications try to use socket()

	if (pid == -1) { // if the socket daemon hasn't made contact before
		// Print what we received
		PRINT_DEBUG("No msg pID, received='%p'", buf);
	} else {
		if (len >= sizeof(struct nl_daemon_to_wedge)) {
			hdr = (struct nl_daemon_to_wedge *) buf;
			len -= sizeof(struct nl_daemon_to_wedge);

			/*
			 * extract common values and pass rest to shared buffer
			 * reply_call & sock_id, are to verify buf goes to the right sock & call
			 * This is preemptive as with multithreading we may have to add a shared queue
			 */

			PRINT_DEBUG("Reply: call_type=%u, call_id=%u, call_index=%d, sock_id=%llu, sock_index=%d, ret=%u, msg=%u, len=%d",
					hdr->call_type, hdr->call_id, hdr->call_index, hdr->sock_id, hdr->sock_index, hdr->ret, hdr->msg, len
			);

			if (hdr->call_type == 0) { //set to different calls
				if (hdr->sock_index == -1 || hdr->sock_index > MAX_SOCKETS) {
					PRINT_ERROR("invalid sock_index: sock_index=%d", hdr->sock_index);
					goto end;
				}
				if (down_interruptible(&wedge_sockets_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				if (wedge_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
					up(&wedge_sockets_sem);
					PRINT_ERROR("socket removed: sock_index=%d, sock_id=%llu", hdr->sock_index, hdr->sock_id);
					goto end;
				}

				PRINT_DEBUG("sock_index=%d, type=%u, threads=%d", hdr->sock_index, hdr->call_type, wedge_sockets[hdr->sock_index].threads[hdr->call_type]);
				if (wedge_sockets[hdr->sock_index].threads[hdr->call_type] < 1) { //TODO may be unnecessary, since have call_index/call_id
					up(&wedge_sockets_sem);
					PRINT_ERROR("Exiting: no waiting threads found: sock_index=%d, type=%u", hdr->sock_index, hdr->call_type);
					goto end;
				}
				up(&wedge_sockets_sem);

				if (wedge_sockets[hdr->sock_index].release_flag && (hdr->call_type != RELEASE_CALL)) { //TODO: may be unnecessary & can be removed (flag, etc)
					PRINT_DEBUG("socket released, dropping for sock_index=%d, sock_id=%llu, type=%d", hdr->sock_index, hdr->sock_id, hdr->call_type);
					//goto end; //TODO uncomment or remove
				}
			} else if (hdr->call_type == POLL_EVENT_CALL) {
				if (hdr->sock_index == -1 || hdr->sock_index > MAX_SOCKETS) {
					PRINT_ERROR("invalid sock_index: sock_index=%d", hdr->sock_index);
					goto end;
				}
				if (down_interruptible(&wedge_sockets_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				if (wedge_sockets[hdr->sock_index].sock_id == hdr->sock_id) {
					if (hdr->ret == ACK) {
						PRINT_DEBUG("triggering socket: sock_id=%llu, sock_index=%d, mask=0x%x", hdr->sock_id, hdr->sock_index, hdr->msg);

						//TODO change so that it wakes up only a single task with the pID given in wedge_sockets[hdr->sock_index].msg
						if (waitqueue_active(sk_sleep(wedge_sockets[hdr->sock_index].sk))) {
							//wake_up_interruptible(sk_sleep(wedge_sockets[hdr->sock_index].sk));
							PRINT_DEBUG("waking");
							wake_up_poll(sk_sleep(wedge_sockets[hdr->sock_index].sk), hdr->msg); //wake with this mode?
						}
					} else if (hdr->ret == NACK) {
						PRINT_ERROR("todo error");
					} else {
						PRINT_ERROR("todo error");
					}
				} else {
					PRINT_ERROR("socket mismatched: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
							hdr->sock_index, wedge_calls[hdr->sock_index].sock_id, hdr->sock_id);
				}
				up(&wedge_sockets_sem);
			} else if (hdr->call_type < MAX_CALL_TYPES) {
				//This wedge version relies on the fact that each call gets a unique call ID and that value is only sent to the wedge once
				//Under this assumption a lock-less implementation can be used
				if (hdr->call_index == -1 || hdr->call_index > MAX_CALLS) {
					PRINT_ERROR("invalid call_index: call_index=%d", hdr->call_index);
					goto end;
				}
				if (down_interruptible(&wedge_calls_sem)) {
					PRINT_ERROR("calls_sem acquire fail");
					//TODO error
				}
				if (wedge_calls[hdr->call_index].call_id == hdr->call_id) {
					if (wedge_calls[hdr->call_index].call_type != hdr->call_type) { //TODO remove type check ~ unnecessary? shouldn't ever happen
						PRINT_ERROR("call mismatched: call_index=%d, call_type=%u, hdr->type=%u",
								hdr->call_index, wedge_calls[hdr->call_index].call_type, hdr->call_type);
					}
					wedge_calls[hdr->call_index].ret = hdr->ret;
					wedge_calls[hdr->call_index].msg = hdr->msg;
					wedge_calls[hdr->call_index].buf = buf + sizeof(struct nl_daemon_to_wedge);
					wedge_calls[hdr->call_index].len = len;
					wedge_calls[hdr->call_index].reply = 1;
					PRINT_DEBUG("shared created: sock_id=%llu, call_id=%d, ret=%u, msg=%u, len=%d",
							wedge_calls[hdr->call_index].sock_id, wedge_calls[hdr->call_index].call_id, wedge_calls[hdr->call_index].ret, wedge_calls[hdr->call_index].msg, wedge_calls[hdr->call_index].len);
					up(&wedge_calls[hdr->call_index].wait_sem); //DON"T reference wedge_calls[hdr->call_index] after this

				} else {
					PRINT_ERROR("call mismatched: call_index=%d, id=%u, hdr->id=%u", hdr->call_index, wedge_calls[hdr->call_index].call_id, hdr->call_id);
				}
				up(&wedge_calls_sem);
			} else {
				//TODO error
				PRINT_ERROR("todo error");
			}
		} else if (len == sizeof(__u32 )) {
			reply_call = *(__u32 *) buf;
			if (reply_call == DAEMON_START_CALL) {
				if (fins_daemon_pid != -1) {
					PRINT_IMPORTANT("########## Daemon pID changed, old pid=%d", fins_daemon_pid);
				}
				//fins_stack_passthrough_enabled = 1;
				fins_daemon_pid = pid;
				PRINT_IMPORTANT("########## Daemon connected, pid=%d", fins_daemon_pid);

				if (down_interruptible(&wedge_sockets_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				wedge_socket_remove_all();
				up(&wedge_sockets_sem);

				if (down_interruptible(&wedge_calls_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				wedge_calls_remove_all();
				up(&wedge_calls_sem);
			} else if (reply_call == DAEMON_STOP_CALL) {
				PRINT_IMPORTANT("########## Daemon disconnected");
				//fins_stack_passthrough_enabled = 0;
				fins_daemon_pid = -1; //TODO expand this functionality

				if (down_interruptible(&wedge_sockets_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				wedge_socket_remove_all();
				up(&wedge_sockets_sem);

				if (down_interruptible(&wedge_calls_sem)) {
					PRINT_ERROR("sockets_sem acquire fail");
					//TODO error
				}
				wedge_calls_remove_all();
				up(&wedge_calls_sem);
			} else {
				//TODO drop?
				PRINT_ERROR("todo error. Dropping...");
			}
		} else {
			//TODO error
			PRINT_ERROR("todo error");
			PRINT_DEBUG("Exiting: len too small: len=%d, hdr=%d", len, sizeof(struct nl_daemon_to_wedge));
		}
	}

	end: //
	PRINT_DEBUG("Exited: skb=%p", skb);
}

/* This function is called from within fins_release and is modeled after ipx_destroy_socket() */
/*static void fins_destroy_socket(struct sock *sk) {
 PRINT_DEBUG("called.");
 skb_queue_purge(&sk->sk_receive_queue);
 sk_refcnt_debug_dec(sk);
 }*/

__s32 fins_sk_create(struct net *net, struct socket *sock) {
	struct sock *sk;

	sk = sk_alloc(net, PF_FINS, GFP_KERNEL, &fins_proto);
	if (sk == NULL) {
		return -ENOMEM;
	}

	sk_refcnt_debug_inc(sk);
	sock_init_data(sock, sk);

	sk->sk_no_check = 1;
	sock->ops = &fins_proto_ops;

	return 0;
}

void fins_sk_destroy(struct socket *sock) {
	struct sock *sk;
	sk = sock->sk;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;

	sk_refcnt_debug_release(sk);
	skb_queue_purge(&sk->sk_receive_queue);
	sk_refcnt_debug_dec(sk);

	sock_put(sk);
}

/*
 * If the FINS stack passthrough is enabled, this function is called when socket() is called from userspace.
 * See wedge_create_socket for details.
 */
static int fins_create(struct net *net, struct socket *sock, int protocol, int kern) {
	int rc = -ESOCKTNOSUPPORT;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = SOCKET_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
				PRINT_ERROR("daemon not connected");
				PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
				return -1;
			}

			// Required stuff for kernel side
			rc = fins_sk_create(net, sock);
			if (rc) {
				PRINT_ERROR("allocation failed");
				PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
				return rc;
			}

			sk = sock->sk;
			if (sk == NULL) {
				PRINT_ERROR("sk null");
				PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
				return -1;
			}
			lock_sock(sk);

			sock_id = get_unique_sock_id(sk);
			PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

			if (down_interruptible(&wedge_sockets_sem)) {
				PRINT_ERROR("sockets_sem acquire fail");
				//TODO error
			}
			sock_index = wedge_sockets_insert(sock_id, sk);
			PRINT_DEBUG("insert: sock_id=%llu, sock_index=%d", sock_id, sock_index);
			if (sock_index == -1) {
				up(&wedge_sockets_sem);
				fins_sk_destroy(sock);
				PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -ENOMEM);
				return -ENOMEM;
			}

			wedge_sockets[sock_index].threads[call_type]++;
			up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

			if (down_interruptible(&wedge_calls_sem)) {
				PRINT_ERROR("calls_sem acquire fail");
				//TODO error
			}
			call_id = call_count++;
			call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
			up(&wedge_calls_sem);
			PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
			if (call_index == -1) {
				rc = -ENOMEM;
				goto removeSocket;
			}

			// Build the message
			buf_len = sizeof(struct nl_wedge_to_daemon) + 3 * sizeof(__s32);
			buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
			if (buf == NULL) {
				PRINT_ERROR("buffer allocation error");
				wedge_calls[call_index].call_id = -1;
				rc = -ENOMEM;
				goto removeSocket;
			}

			hdr = (struct nl_wedge_to_daemon *) buf;
			hdr->sock_id = sock_id;
			hdr->sock_index = sock_index;
			hdr->call_type = call_type;
			hdr->call_pid = call_pid;
			hdr->call_id = call_id;
			hdr->call_index = call_index;
			pt = buf + sizeof(struct nl_wedge_to_daemon);

			*(__s32 *) pt = AF_FINS; //~2, since this overrides AF_INET (39)
			pt += sizeof(__s32);

			*(__s32 *) pt = sock->type;
			pt += sizeof(__s32);

			*(__s32 *) pt = protocol;
			pt += sizeof(__s32);

			if (pt - buf != buf_len) {
				PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
				kfree(buf);
				wedge_calls[call_index].call_id = -1;
				rc = -1;
				goto removeSocket;
			}

			PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

			// Send message to fins_daemon
			ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
			kfree(buf);
			if (ret) {
				PRINT_ERROR("nl_send failed");
				wedge_calls[call_index].call_id = -1;
				rc = -1;
				goto removeSocket;
			}
			//release_sock(sk); //no one else can use, since socket creates

			PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
			if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
				PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
			}PRINT_DEBUG("relocked my semaphore");

			//lock_sock(sk); //no one else can use, since socket creates
			//wedge_calls[call_index].sem
			PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%d, ret=%u, msg=%u, len=%d",
					wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;
	//wedge_calls[call_index].sem

	if (rc) {
		removeSocket: //
		if (down_interruptible(&wedge_sockets_sem)) {
			PRINT_ERROR("sockets_sem acquire fail");
			//TODO error
		}
		ret = wedge_sockets_remove(sock_id, sock_index, call_type);
		up(&wedge_sockets_sem);

		fins_sk_destroy(sock);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
		return rc;
	}

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = BIND_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, addr_len=%d", sock_id, addr_len);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32) + addr_len + sizeof(__u32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = addr_len;
	pt += sizeof(__s32);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	*(__u32 *) pt = sk->sk_reuse;
	pt += sizeof(__u32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_listen(struct socket *sock, int backlog) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = LISTEN_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, backlog=%d", sock_id, backlog);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = backlog;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = CONNECT_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, addr_len=%d, flags=0x%x", sock_id, addr_len, flags);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + 2 * sizeof(__s32) + addr_len;
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = addr_len;
	pt += sizeof(__s32);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	*(__s32 *) pt = flags;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_accept(struct socket *sock, struct socket *sock_new, int flags) { //TODO fix, two blocking accept calls
	int rc;
	struct sock *sk, *sk_new;
	__u64 sock_id, sock_id_new;
	__s32 sock_index, index_new;
	__u32 call_type = ACCEPT_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, flags=0x%x", sock_id, flags);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk_new = wedge_sockets[sock_index].sk_new;
	if (sk_new == NULL) {
		rc = fins_sk_create(sock_net(sock->sk), sock_new);
		if (rc) {
			PRINT_ERROR("allocation failed");
			up(&wedge_sockets_sem);
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
			return rc;
		}
		sk_new = sock_new->sk;
		lock_sock(sk_new);

		sock_new->sk = NULL; //if return rc!=0 sock_new released, gens release_call

		sock_id_new = get_unique_sock_id(sk_new);
		PRINT_DEBUG("Created new: sock_id=%llu", sock_id_new);

		index_new = wedge_sockets_insert(sock_id_new, sk_new);
		PRINT_DEBUG("insert new: sock_id=%llu, sock_index=%d", sock_id_new, index_new);
		if (index_new == -1) {
			up(&wedge_sockets_sem);
			fins_sk_destroy(sock_new);
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
			return rc;
		}

		wedge_sockets[sock_index].sk_new = sk_new;
	} else {
		lock_sock(sk_new);

		sock_id_new = get_unique_sock_id(sk_new);
		PRINT_DEBUG("Retrieved new: sock_id=%llu", sock_id_new);

		index_new = wedge_sockets_find(sock_id_new);
		PRINT_DEBUG("new: sock_index=%d", sock_index);
		if (sock_index == -1) {
			/*
			 index_new = insert_wedge_socket(uniqueSockID_new, sk_new);
			 PRINT_DEBUG("insert new: sock_id=%llu sock_index=%d", uniqueSockID_new, index_new);
			 if (index_new == -1) {
			 up(&sockets_sem);
			 fins_sk_destroy(sock_new);
			 release_sock(sk);
			 PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
			 return rc;
			 }
			 */
			up(&wedge_sockets_sem);
			release_sock(sk_new);
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
			return -1;
		}
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u64) + 2 * sizeof(__s32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__u64 *) pt = sock_id_new;
	pt += sizeof(__u64);

	*(__s32 *) pt = index_new;
	pt += sizeof(__s32);

	*(__s32 *) pt = flags;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk_new);
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	lock_sock(sk_new);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
		if (rc == 0) {
			sock_new->sk = sk_new;
			if (down_interruptible(&wedge_sockets_sem)) {
				PRINT_ERROR("sockets_sem acquire fail");
				//TODO error
			}
			wedge_sockets[sock_index].sk_new = NULL;

			//TODO create new sk_new

			up(&wedge_sockets_sem);
		}
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk_new);
	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_getname(struct socket *sock, struct sockaddr *addr, int *len, int peer) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	int sock_index;
	__u32 call_type = GETNAME_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;
	struct sockaddr_in *addr_in;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, len=%d, peer=0x%x", sock_id, *len, peer);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = peer;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		if (wedge_calls[call_index].ret == ACK) {
			PRINT_DEBUG("recv ACK");

			if (wedge_calls[call_index].buf && wedge_calls[call_index].len >= sizeof(__s32)) {
				pt = wedge_calls[call_index].buf;

				*len = *(__s32 *) pt;
				pt += sizeof(__s32);

				PRINT_DEBUG("len=%d", *len);
				memset(addr, 0, sizeof(struct sockaddr));
				memcpy(addr, pt, *len);
				pt += *len;

				//########
				addr_in = (struct sockaddr_in *) addr;
				//addr_in->sin_port = ntohs(4000); //causes end port to be 4000
				PRINT_DEBUG("address: %u/%u", ntohl((addr_in->sin_addr).s_addr), ntohs(addr_in->sin_port));
				//########

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				} else {
					rc = 0;
				}
			} else {
				PRINT_ERROR("wedge_calls[call_index].buf error, wedge_calls[call_index].len=%d, wedge_calls[call_index].buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
		} else if (wedge_calls[call_index].ret == NACK) {
			PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
			rc = -wedge_calls[call_index].msg;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedge_calls[call_index].ret);
			rc = -1;
		}
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = SENDMSG_CALL;
	__u32 call_id;
	__s32 call_index;

	__s32 i = 0;
	__u32 data_len = 0;
	char *temp;

	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, len=%d", sock_id, len);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	for (i = 0; i < (msg->msg_iovlen); i++) {
		data_len += msg->msg_iov[i].iov_len;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32) + (msg->msg_namelen > 0 ? msg->msg_namelen : 0) + 4 * sizeof(__u32)
	+ msg->msg_controllen + data_len;
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__u32 *) pt = sk->sk_flags;
	pt += sizeof(__u32);

	*(__s32 *) pt = msg->msg_namelen;
	pt += sizeof(__s32);

	if (msg->msg_namelen > 0) {
		memcpy(pt, msg->msg_name, msg->msg_namelen);
		pt += msg->msg_namelen;
	}

	*(__u32 *) pt = msg->msg_flags; //stores sendmsg call flags
	pt += sizeof(__u32);

	*(__u32 *) pt = msg->msg_controllen;
	pt += sizeof(__u32);

	memcpy(pt, msg->msg_control, msg->msg_controllen);
	pt += msg->msg_controllen;
	//Notice that the compiler takes  (msg->msg_iov[i]) as a struct not a pointer to struct

	*(__u32 *) pt = data_len;
	pt += sizeof(__u32);

	temp = pt;

	i = 0;
	for (i = 0; i < msg->msg_iovlen; i++) {
		if (msg->msg_iov[i].iov_base == NULL) {
			if (msg->msg_iov[i].iov_len > 0) {
				//len != 0
				PRINT_ERROR("Buffer error: msg->msg_iov[%i].iov_base=NULL, msg->msg_iov[i].iov_len=%d", i, msg->msg_iov[i].iov_len);
				kfree(buf);
				wedge_calls[call_index].call_id = -1;
				rc = -1;
				goto end;
			} else {
				//len == 0, do nothing/skip?
			}
		} else {
			memcpy(pt, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
			pt += msg->msg_iov[i].iov_len;
		}
		//PRINT_DEBUG("current element %d , element length = %d", i ,(msg->msg_iov[i]).iov_len );
	}

	PRINT_DEBUG("msg_namelen=%u, data_buf_len=%d, msg_controllen=%u, msg_flags=0x%x, buf_len=%u", msg->msg_namelen, (__s32)len, msg->msg_controllen, msg->msg_flags, buf_len);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("data_len=%d", data_len);PRINT_DEBUG("data='%s'", temp);

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		//rc = checkConfirmation(call_index);
		//if (rc == 0) {
		//	rc = data_len;
		//}

		if (wedge_calls[call_index].ret == ACK) {
			PRINT_DEBUG("recv ACK");
			if (wedge_calls[call_index].len == 0) {
				rc = wedge_calls[call_index].msg;
			} else {
				PRINT_ERROR("wedge_calls[sock_index].reply_buf error, wedge_calls[%d].len=%d wedge_calls[%d].buf=%p",
						call_index, wedge_calls[call_index].len, call_index, wedge_calls[call_index].buf);
				rc = -1;
			}
		} else if (wedge_calls[call_index].ret == NACK) {
			PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
			rc = -wedge_calls[call_index].msg;
		} else {
			PRINT_ERROR("error, acknowledgement: %u", wedge_calls[call_index].ret);
			rc = -1;
		}
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = RECVMSG_CALL;
	__u32 call_id;
	__s32 call_index;
	struct sockaddr_in *addr_in;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;
	__s32 i;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + 2 * sizeof(__s32) + 2*sizeof(__u32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__u32 *) pt = sk->sk_flags;
	pt += sizeof(__u32);

	*(__s32 *) pt = (__s32) len;
	pt += sizeof(__s32);

	*(__u32 *) pt = msg->msg_controllen; //TODO send msg_controllen?
	pt += sizeof(__u32);

	*(__s32 *) pt = flags;
	pt += sizeof(__s32);

	//sk->sk_rcvtimeo;

	PRINT_DEBUG("msg_namelen=%u, data_buf_len=%d, msg_controllen=%u, flags=0x%x, buf_len=%u", msg->msg_namelen, (__s32)len, msg->msg_controllen, flags, buf_len);

	/*
	 *(__u32 *) pt = msg->msg_flags; //always 0, set on return
	 pt += sizeof(__u32);

	 memcpy(pt, msg->msg_control, msg->msg_controllen); //0? would think set on return
	 pt += msg->msg_controllen;
	 */
	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		if (wedge_calls[call_index].ret == ACK) {
			PRINT_DEBUG("recv ACK");
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len >= 0) {
				pt = wedge_calls[call_index].buf;

				msg->msg_flags = wedge_calls[call_index].msg;

				//TODO: find out if this is right! udpHandling writes sockaddr_in here
				msg->msg_namelen = *(__u32 *) pt; //reuse var since not needed anymore
				pt += sizeof(__u32);

				PRINT_DEBUG("msg_namelen=%u, msg_name=%p", msg->msg_namelen, msg->msg_name);
				if (msg->msg_namelen == 0) {
					msg->msg_namelen = sizeof(struct sockaddr_in);
				}

				if (msg->msg_namelen != 0) {
					if (msg->msg_name == NULL) {
						msg->msg_name = (__u8 *) kmalloc(msg->msg_namelen, GFP_KERNEL);
						if (msg->msg_name == NULL) {
							PRINT_ERROR("buffer allocation error");
							wedge_calls[call_index].call_id = -1;
							rc = -ENOMEM;
							goto end;
						}
					}

					memcpy(msg->msg_name, pt, msg->msg_namelen);
					pt += msg->msg_namelen;
				}

				//########
				addr_in = (struct sockaddr_in *) msg->msg_name;
				//addr_in->sin_port = ntohs(4000); //causes end port to be 4000
				PRINT_DEBUG("address: %u/%u", ntohl((addr_in->sin_addr).s_addr), ntohs(addr_in->sin_port));
				//########

				buf_len = *(__u32 *) pt; //reuse var since not needed anymore
				pt += sizeof(__u32);

				if (buf_len >= 0) {
					//########
#ifdef DEBUG
					__u8 *temp = (__u8 *) kmalloc(buf_len + 1, GFP_KERNEL);
					memcpy(temp, pt, buf_len);
					temp[buf_len] = '\0';
					PRINT_DEBUG("msg='%s'", temp);
					kfree(temp);
#endif
					//########

					ret = buf_len; //reuse as counter
					i = 0;
					while (ret > 0 && i < msg->msg_iovlen) {
						if (ret > msg->msg_iov[i].iov_len) {
							if (copy_to_user(msg->msg_iov[i].iov_base, pt, msg->msg_iov[i].iov_len)) {
								PRINT_ERROR("copy to user error");
								wedge_calls[call_index].call_id = -1;
								rc = -1;
								goto end;
							}
							pt += msg->msg_iov[i].iov_len;
							ret -= msg->msg_iov[i].iov_len;
							i++;
						} else {
							if (copy_to_user(msg->msg_iov[i].iov_base, pt, ret)) {
								PRINT_ERROR("copy to user error");
								wedge_calls[call_index].call_id = -1;
								rc = -1;
								goto end;
							}
							pt += ret;
							ret = 0;
							break;
						}
					}
					if (ret) {
						//throw buffer overflow error?
						PRINT_ERROR("user buffer overflow error, overflow=%d", ret);
					}

					rc = buf_len;
				} else {
					PRINT_ERROR("iov_base alloc failure");
					rc = -1;
				}

				msg->msg_controllen = *(__u32 *) pt; //reuse var since not needed anymore
				pt += sizeof(__u32);

				if (msg->msg_controllen > CONTROL_LEN_MAX) {
					PRINT_ERROR("Random corruption error: msg_controllen=%u", msg->msg_controllen);
					msg->msg_controllen = 0;
				}

				PRINT_DEBUG("msg_controllen=%u, msg_control=%p", msg->msg_controllen, msg->msg_control);
				if (msg->msg_control == NULL) {
					msg->msg_control = kmalloc(msg->msg_controllen, GFP_KERNEL);
					if (msg->msg_control == NULL) {
						PRINT_ERROR("buffer allocation error");
						wedge_calls[call_index].call_id = -1;
						rc = -ENOMEM;
						goto end;
					}
				}

				memcpy(msg->msg_control, pt, msg->msg_controllen);
				pt += msg->msg_controllen;

				msg->msg_control = ((__u8 *) msg->msg_control) + msg->msg_controllen; //required for kernel

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
		} else if (wedge_calls[call_index].ret == NACK) {
			PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
			if (wedge_calls[call_index].msg) {
				rc = -wedge_calls[call_index].msg;
			} else {
				rc = -1;
			}
		} else {
			PRINT_ERROR("error, acknowledgement: ret=%u, msg=%u", wedge_calls[call_index].ret, wedge_calls[call_index].msg);
			rc = -1;
		}
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	int rc = 0;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = IOCTL_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct ifconf ifc;
	struct ifreq ifr;
	struct ifreq *ifr_pt;

	void __user
	*arg_pt = (void __user *)arg;

	__s32 len;
	char __user
	*pos;

	//char *name;
	struct sockaddr_in *addr;

	//http://lxr.linux.no/linux+v2.6.39.4/net/core/dev.c#L4905 - ioctl

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	sk = sock->sk;
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, cmd=%u", sock_id, cmd);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	switch (cmd) {
		case SIOCGIFCONF:
		PRINT_DEBUG("cmd=%d ==SIOCGIFCONF", cmd);

		if (copy_from_user(&ifc, arg_pt, sizeof(struct ifconf))) {
			PRINT_ERROR("ERROR: cmd=%d ==SIOCGIFDSTADDR", cmd);
			//TODO error
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
			return -1;
		}

		pos = ifc.ifc_buf;
		if (ifc.ifc_buf == NULL) {
			len = 0;
		} else {
			len = ifc.ifc_len;
		}
		ifr_pt = ifc.ifc_req; //TODO figure out what this is used for

		PRINT_DEBUG("len=%d, pos=%d, ifr=%d", len, (__s32)pos, (__s32)ifr_pt);

		// Build the message
		buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u32) + sizeof(__s32);
		buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
		if (buf == NULL) {
			PRINT_ERROR("buffer allocation error");
			wedge_calls[call_index].call_id = -1;
			rc = -ENOMEM;
			goto end;
		}

		hdr = (struct nl_wedge_to_daemon *) buf;
		hdr->sock_id = sock_id;
		hdr->sock_index = sock_index;
		hdr->call_type = call_type;
		hdr->call_pid = call_pid;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		pt = buf + sizeof(struct nl_wedge_to_daemon);

		*(__u32 *) pt = cmd;
		pt += sizeof(__u32);

		*(__s32 *) pt = len;
		pt += sizeof(__s32);

		if (pt - buf != buf_len) {
			PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
		break;
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFFLAGS:
		case SIOCGIFMTU:
		if (copy_from_user(&ifr, arg_pt, sizeof(struct ifreq))) {
			PRINT_ERROR("ERROR: cmd=%d", cmd);
			//TODO error
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
			return -1;
		}

		PRINT_DEBUG("cmd=%d, name='%s'", cmd, ifr.ifr_name);

		// Build the message
		buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u32) + sizeof(__s32) + IFNAMSIZ;
		buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
		if (buf == NULL) {
			PRINT_ERROR("buffer allocation error");
			wedge_calls[call_index].call_id = -1;
			rc = -ENOMEM;
			goto end;
		}

		hdr = (struct nl_wedge_to_daemon *) buf;
		hdr->sock_id = sock_id;
		hdr->sock_index = sock_index;
		hdr->call_type = call_type;
		hdr->call_pid = call_pid;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		pt = buf + sizeof(struct nl_wedge_to_daemon);

		*(__u32 *) pt = cmd;
		pt += sizeof(__u32);

		*(__s32 *) pt = IFNAMSIZ;
		pt += sizeof(__s32);

		memcpy(pt, ifr.ifr_name, IFNAMSIZ);
		pt += IFNAMSIZ;

		if (pt - buf != buf_len) {
			PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
		break;
		case FIONREAD:
		PRINT_DEBUG("cmd=FIONREAD");

		// Build the message
		buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u32);
		buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
		if (buf == NULL) {
			PRINT_ERROR("buffer allocation error");
			wedge_calls[call_index].call_id = -1;
			rc = -ENOMEM;
			goto end;
		}

		hdr = (struct nl_wedge_to_daemon *) buf;
		hdr->sock_id = sock_id;
		hdr->sock_index = sock_index;
		hdr->call_type = call_type;
		hdr->call_pid = call_pid;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		pt = buf + sizeof(struct nl_wedge_to_daemon);

		*(__u32 *) pt = cmd;
		pt += sizeof(__u32);

		if (pt - buf != buf_len) {
			PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
		break;
		case SIOCGIFNAME:
		//ifreq.ifr_ifindex = x;
		//if (ioctl(sock, SIOCGIFNAME, &ifreq) < 0)
		//	perr_quit("ioctl");
		//printf("index %d is '%s'\n", x, ifreq.ifr_name);

		if (copy_from_user(&ifr, arg_pt, sizeof(struct ifreq))) {
			PRINT_ERROR("ERROR: cmd=%d ==SIOCGIFNAME", cmd);
			//TODO error
			release_sock(sk);
			PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
			return -1;
		}

		PRINT_DEBUG("cmd=%d, index='%d'", cmd, ifr.ifr_ifindex);

		// Build the message
		buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u32) + 2 * sizeof(__s32);
		buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
		if (buf == NULL) {
			PRINT_ERROR("buffer allocation error");
			wedge_calls[call_index].call_id = -1;
			rc = -ENOMEM;
			goto end;
		}

		hdr = (struct nl_wedge_to_daemon *) buf;
		hdr->sock_id = sock_id;
		hdr->sock_index = sock_index;
		hdr->call_type = call_type;
		hdr->call_pid = call_pid;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		pt = buf + sizeof(struct nl_wedge_to_daemon);

		*(__u32 *) pt = cmd;
		pt += sizeof(__u32);

		*(__s32 *) pt = IFNAMSIZ;
		pt += sizeof(__s32);

		*(__s32 *) pt = ifr.ifr_ifindex;
		pt += sizeof(__s32);

		if (pt - buf != buf_len) {
			PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
		break;
		case SIOCSIFFLAGS:
		case TIOCOUTQ:
		//case TIOCINQ: //equiv to FIONREAD??
		case SIOCADDRT:
		case SIOCDELRT:
		case SIOCSIFADDR:
		//case SIOCAIPXITFCRT:
		//case SIOCAIPXPRISLT:
		//case SIOCIPXCFGDATA:
		//case SIOCIPXNCPCONN:
		case SIOCGSTAMP:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
		//TODO implement
		PRINT_DEBUG("cmd=%d not implemented", cmd);

		// Build the message
		buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__u32);
		buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
		if (buf == NULL) {
			PRINT_ERROR("buffer allocation error");
			wedge_calls[call_index].call_id = -1;
			rc = -ENOMEM;
			goto end;
		}

		hdr = (struct nl_wedge_to_daemon *) buf;
		hdr->sock_id = sock_id;
		hdr->sock_index = sock_index;
		hdr->call_type = call_type;
		hdr->call_pid = call_pid;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		pt = buf + sizeof(struct nl_wedge_to_daemon);

		*(__u32 *) pt = cmd;
		pt += sizeof(__u32);

		if (pt - buf != buf_len) {
			PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
		break;
		default:
		PRINT_DEBUG("cmd=%d default", cmd);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);

	if (!wedge_calls[call_index].reply) {
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	if (wedge_calls[call_index].ret == ACK) {
		PRINT_DEBUG("ioctl ACK");
		switch (cmd) {
			case SIOCGIFCONF:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len >= sizeof(__s32)) {
				//values stored in ifr.ifr_addr
				pt = wedge_calls[call_index].buf;

				len = *(__s32 *) pt;
				pt += sizeof(__s32);

				PRINT_DEBUG("SIOCGIFCONF len=%d, ifc_len=%d", len, ifc.ifc_len);
				ifc.ifc_len = len;
				PRINT_DEBUG("SIOCGIFCONF len=%d, ifc_len=%d", len, ifc.ifc_len);

				if (copy_to_user(ifc.ifc_buf, pt, len)) { //TODO remove?? think this is wrong
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}
				pt += len;

				//len = ifc.ifc_len;
				//pos = ifc.ifc_buf;
				//ifr_pt = ifc.ifc_req;

				if (copy_to_user(arg_pt, &ifc, sizeof(struct ifconf))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFADDR:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(struct sockaddr_in)) {
				pt = wedge_calls[call_index].buf;

				memcpy(&ifr.ifr_addr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_addr;
				//memcpy(addr, pt, sizeof(struct sockaddr));
				PRINT_DEBUG("name='%s', addr=%u (%u/%u)", ifr.ifr_name, (__s32)addr, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFDSTADDR:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(struct sockaddr_in)) {
				pt = wedge_calls[call_index].buf;

				memcpy(&ifr.ifr_dstaddr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_dstaddr;
				PRINT_DEBUG("name='%s', addr=%u (%u/%u)", ifr.ifr_name, (__s32)addr, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFBRDADDR:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(struct sockaddr_in)) {
				pt = wedge_calls[call_index].buf;

				memcpy(&ifr.ifr_broadaddr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
				PRINT_DEBUG("name='%s', addr=%u (%u/%u)", ifr.ifr_name, (__s32)addr, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFNETMASK:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(struct sockaddr_in)) {
				pt = wedge_calls[call_index].buf;

				memcpy(&ifr.ifr_addr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_addr;
				PRINT_DEBUG("name='%s', addr=%u (%u/%u)", ifr.ifr_name, (__s32)addr, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port));
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFNAME:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(struct sockaddr_in)) {
				pt = wedge_calls[call_index].buf;

				len = IFNAMSIZ;

				memcpy(ifr.ifr_name, pt, len); //IFNAMSIZ
				pt += len;

				//#################
				PRINT_DEBUG("len=%d, name='%s'", len, ifr.ifr_name);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case FIONREAD:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(__s32)) {
				pt = wedge_calls[call_index].buf;

				len = *(__s32 *) pt;
				pt += sizeof(__s32);

				//#################
				PRINT_DEBUG("len=%d", len);
				//#################

				if (copy_to_user(arg_pt, &len, sizeof(__s32))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFFLAGS:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(__s32)) {
				pt = wedge_calls[call_index].buf;

				len = *(__s32 *) pt; //ifr_flags
				pt += sizeof(__s32);

				ifr.ifr_flags = (__s16) len;

				//#################
				PRINT_DEBUG("ifr_flags=0x%x", ifr.ifr_flags);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGIFMTU:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len == sizeof(__s32)) {
				pt = wedge_calls[call_index].buf;

				ifr.ifr_mtu = *(__s32 *) pt;
				pt += sizeof(__s32);

				//#################
				PRINT_DEBUG("ifr_mtu=%d", ifr.ifr_mtu);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			case SIOCGSTAMP:
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len >= sizeof(__s32)) {
				//values stored in ifr.ifr_addr
				pt = wedge_calls[call_index].buf;

				len = *(__s32 *) pt;
				pt += sizeof(__s32);

				if (copy_to_user(arg_pt, pt, len)) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}
				pt += len;

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("READING ERROR! diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			//case TIOCINQ: //equiv to FIONREAD??
			//-----------------------------------
			case TIOCOUTQ:
			case SIOCADDRT:
			case SIOCDELRT:
			case SIOCSIFADDR:
			//case SIOCAIPXITFCRT:
			//case SIOCAIPXPRISLT:
			//case SIOCIPXCFGDATA:
			//case SIOCIPXNCPCONN:
			case SIOCSIFDSTADDR:
			case SIOCSIFBRDADDR:
			case SIOCSIFNETMASK:
			//TODO implement cases above
			if (wedge_calls[call_index].buf && (wedge_calls[call_index].len == 0)) {
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
			break;
			default:
			PRINT_DEBUG("cmd=%d default", cmd);
			rc = -1;
			break;
		}
	} else if (wedge_calls[call_index].ret == NACK) {
		PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
		//rc = -1;
		rc = -wedge_calls[call_index].msg;
	} else {
		PRINT_ERROR("error, acknowledgement: %d", wedge_calls[call_index].ret);
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;
	//##

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

/*
 * This function is called automatically to cleanup when a program that
 * created a socket terminates.
 * Or manually via close()?????
 * Modeled after ipx_release().
 */
static int fins_release(struct socket *sock) {
	int rc = 0;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = RELEASE_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0; //TODO should be -1, done to prevent stalls
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		//fins_sk_destroy(sock); //NULL reference
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		fins_sk_destroy(sock);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}

	if (wedge_sockets[sock_index].release_flag) {
		//check such that successive release calls return immediately, affectively release only performed once
		up(&wedge_sockets_sem);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}

	wedge_sockets[sock_index].release_flag = 1;
	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	ret = wedge_sockets_remove(sock_id, sock_index, call_type);
	up(&wedge_sockets_sem);

	fins_sk_destroy(sock);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
	return 0; //TODO should be rc, 0 to prevent stalling
}

static unsigned int fins_poll(struct file *file, struct socket *sock, poll_table *table) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = POLL_CALL;
	__u32 call_id;
	__s32 call_index;
	__s32 events;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, 0);
		return 0;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = 0;
		goto end;
	}

	PRINT_DEBUG("file=%p, sock=%p, table=%p", file, sock, table);
	if (table) {
		events = table->key; //key added in Kv2.6.38? still there in Kv3.1.10
		//events = table->_key; //for Kv3.4.0
	} else {
		events = 0;
	}PRINT_DEBUG("events=0x%x", events);

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = 0;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = events;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = 0;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = 0;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		if (wedge_calls[call_index].ret == ACK) {
			PRINT_DEBUG("recv ACK");

			if (wedge_calls[call_index].buf && (wedge_calls[call_index].len == 0)) {
				//pt = wedge_calls[call_index].buf;

				//rc = *(__u32 *) pt;
				//pt += sizeof(__u32);

				rc = wedge_calls[call_index].msg;

				/*
				 if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
				 PRINT_DEBUG("READING ERROR! CRASH, diff=%d, len=%d", pt - wedge_calls[call_index].buf, wedge_calls[call_index].len);
				 rc = 0;
				 }
				 */

				PRINT_DEBUG("rc=0x%x", rc);
				//rc = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
				//rc = POLLOUT;
				//rc = -1;
				//PRINT_DEBUG("rc=0x%x", rc);
				if (table && !(events & rc)) {
					poll_wait(file, sk_sleep(sk), table); //TODO move to earlier?
				}
			} else {
				PRINT_ERROR("wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = 0;
			}
		} else if (wedge_calls[call_index].ret == NACK) {
			PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
			//rc = -wedge_calls[call_index].msg; //TODO put in sk error value
			rc = 0;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedge_calls[call_index].ret);
			rc = 0;
		}
	} else {
		rc = 0;
		//rc = POLLNVAL; //TODO figure out?
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

//TODO figure out when this is called
static int fins_shutdown(struct socket *sock, int how) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = SHUTDOWN_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu, how=%d", sock_id, how);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + sizeof(__s32);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = how;
	pt += sizeof(__s32);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_socketpair(struct socket *sock1, struct socket *sock2) {
	struct sock *sk1, *sk2;
	__u64 uniqueSockID1, uniqueSockID2;
	int ret;
	char *buf; // used for test
	__u32 buffer_length; // used for test

	PRINT_IMPORTANT("Called");
	return -1;

	sk1 = sock1->sk;
	uniqueSockID1 = get_unique_sock_id(sk1);

	sk2 = sock2->sk;
	uniqueSockID2 = get_unique_sock_id(sk2);

	PRINT_DEBUG("Entered for %llu, %llu.", uniqueSockID1, uniqueSockID2);

	// Notify FINS daemon
	if (fins_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: rc=%d", -1);
		return -1;
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "fins_socketpair() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		PRINT_IMPORTANT("Exited: rc=%d", -1);
		return -1;
	}

	PRINT_IMPORTANT("Exited: rc=%d", 0);
	return 0;
}

static int fins_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = MMAP_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static ssize_t fins_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = SENDPAGE_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len
	);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	//static int fins_getsockopt(struct socket *sock, int level, int optname, char *optval, int *optlen) {
	int rc = 0;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = GETSOCKOPT_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	__s32 len;

	//SO_REUSEADDR
	//SO_ERROR
	//SO_PRIORITY
	//SO_SNDBUF
	//SO_RCVBUF

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	ret = copy_from_user(&len, optlen, sizeof(__s32));
	if (ret) {
		PRINT_ERROR("copy_from_user fail ret=%d", ret);
		goto end;
	}PRINT_DEBUG("len=%d", len);

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + 3 * sizeof(__s32) + (len > 0 ? len : 0);
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = level;
	pt += sizeof(__s32);

	*(__s32 *) pt = optname;
	pt += sizeof(__s32);

	*(__s32 *) pt = len;
	pt += sizeof(__s32);

	if (len > 0) { //TODO prob don't need
		ret = copy_from_user(pt, optval, len);
		pt += len;
		if (ret) {
			PRINT_ERROR("copy_from_user fail ret=%d", ret);
			kfree(buf);
			wedge_calls[call_index].call_id = -1;
			rc = -1;
			goto end;
		}
	}

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len);
	if (wedge_calls[call_index].reply) {
		if (wedge_calls[call_index].ret == ACK) {
			PRINT_DEBUG("recv ACK");
			if (wedge_calls[call_index].buf && wedge_calls[call_index].len >= sizeof(__s32)) {
				pt = wedge_calls[call_index].buf;
				rc = 0;

				//re-using len var
				len = *(__s32 *) pt;
				pt += sizeof(__s32);
				ret = copy_to_user(optlen, &len, sizeof(__s32));
				if (ret) {
					PRINT_ERROR("copy_from_user fail ret=%d", ret);
					rc = -1;
				}

				if (len > 0) {
					ret = copy_to_user(optval, pt, len);
					pt += len;
					if (ret) {
						PRINT_ERROR("copy_from_user fail ret=%d", ret);
						rc = -1;
					}
				}

				if (pt - wedge_calls[call_index].buf != wedge_calls[call_index].len) {
					PRINT_ERROR("write error: diff=%d, len=%d", pt-wedge_calls[call_index].buf, wedge_calls[call_index].len);
					rc = -1;
				}
			} else {
				PRINT_ERROR( "wedgeSockets[sock_index].reply_buf error, wedgeSockets[sock_index].reply_len=%d, wedgeSockets[sock_index].reply_buf=%p",
						wedge_calls[call_index].len, wedge_calls[call_index].buf);
				rc = -1;
			}
		} else if (wedge_calls[call_index].ret == NACK) {
			PRINT_DEBUG("recv NACK msg=%u", wedge_calls[call_index].msg);
			rc = -wedge_calls[call_index].msg;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedge_calls[call_index].ret);
			rc = -1;
		}
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

static int fins_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	//static int fins_setsockopt(struct socket *sock, int level, int optname, char *optval, unsigned int optlen) {
	int rc;
	struct sock *sk;
	__u64 sock_id;
	__s32 sock_index;
	__u32 call_type = SETSOCKOPT_CALL;
	__u32 call_id;
	__s32 call_index;
	__u32 buf_len;
	__u8 *buf;
	struct nl_wedge_to_daemon *hdr;
	__u8 *pt;
	__s32 ret;

	struct task_struct *curr = get_current();
	__s32 call_pid = (__s32) curr->pid;
	PRINT_IMPORTANT("Entered: call_pid=%d", call_pid);

	if (fins_daemon_pid == -1) { // FINS daemon not connected, nowhere to send msg
		PRINT_ERROR("daemon not connected");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	sk = sock->sk;
	if (sk == NULL) {
		PRINT_ERROR("sk null");
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}
	lock_sock(sk);

	sock_id = get_unique_sock_id(sk);
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);

	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	sock_index = wedge_sockets_find(sock_id);
	PRINT_DEBUG("sock_index=%d", sock_index);
	if (sock_index == -1) {
		up(&wedge_sockets_sem);
		release_sock(sk);
		PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, -1);
		return -1;
	}

	wedge_sockets[sock_index].threads[call_type]++;
	up(&wedge_sockets_sem); //TODO move to later? lock_sock should guarantee

	if (down_interruptible(&wedge_calls_sem)) {
		PRINT_ERROR("calls_sem acquire fail");
		//TODO error
	}
	call_id = call_count++;
	call_index = wedge_calls_insert(call_id, sock_id, sock_index, call_type);
	up(&wedge_calls_sem);
	PRINT_DEBUG("call_id=%u, call_index=%d", call_id, call_index);
	if (call_index == -1) {
		rc = -ENOMEM;
		goto end;
	}

	// Build the message
	buf_len = sizeof(struct nl_wedge_to_daemon) + 3 * sizeof(__s32) + optlen;
	buf = (__u8 *) kmalloc(buf_len, GFP_KERNEL);
	if (buf == NULL) {
		PRINT_ERROR("buffer allocation error");
		wedge_calls[call_index].call_id = -1;
		rc = -ENOMEM;
		goto end;
	}

	hdr = (struct nl_wedge_to_daemon *) buf;
	hdr->sock_id = sock_id;
	hdr->sock_index = sock_index;
	hdr->call_type = call_type;
	hdr->call_pid = call_pid;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	pt = buf + sizeof(struct nl_wedge_to_daemon);

	*(__s32 *) pt = level;
	pt += sizeof(__s32);

	*(__s32 *) pt = optname;
	pt += sizeof(__s32);

	*(__u32 *) pt = optlen;
	pt += sizeof(__u32);

	ret = copy_from_user(pt, optval, optlen);
	pt += optlen;
	if (ret) {
		PRINT_ERROR("copy_from_user fail ret=%d", ret);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	if (pt - buf != buf_len) {
		PRINT_ERROR("write error: diff=%d, len=%u", pt-buf, buf_len);
		kfree(buf);
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}

	PRINT_DEBUG("call_type=%d, sock_id=%llu, buf_len=%u", call_type, sock_id, buf_len);

	// Send message to fins_daemon
	ret = nl_send(fins_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		wedge_calls[call_index].call_id = -1;
		rc = -1;
		goto end;
	}
	release_sock(sk);

	PRINT_DEBUG("waiting for reply: sk=%p, sock_id=%llu, sock_index=%d, call_id=%u, call_index=%d", sk, sock_id, sock_index, call_id, call_index);
	if (down_interruptible(&wedge_calls[call_index].wait_sem)) {
		PRINT_ERROR("wedge_calls[%d].wait_sem acquire fail", call_index);
		//TODO potential problem with wedge_calls[call_index].id = -1: frees call after nl_data_ready verify & filling info, 3rd thread inserting call
	}PRINT_DEBUG("relocked my semaphore");

	lock_sock(sk);
	PRINT_DEBUG("shared recv: sock_id=%llu, call_id=%d, reply=%u, ret=%u, msg=%u, len=%d",
			wedge_calls[call_index].sock_id, wedge_calls[call_index].call_id, wedge_calls[call_index].reply, wedge_calls[call_index].ret, wedge_calls[call_index].msg, wedge_calls[call_index].len);
	if (wedge_calls[call_index].reply) {
		rc = checkConfirmation(call_index);
	} else {
		rc = -1;
	}
	wedge_calls[call_index].call_id = -1;

	end: //
	if (down_interruptible(&wedge_sockets_sem)) {
		PRINT_ERROR("sockets_sem acquire fail");
		//TODO error
	}
	wedge_sockets[sock_index].threads[call_type]--;
	PRINT_DEBUG("wedge_sockets[%d].threads[%u]=%u", sock_index, call_type, wedge_sockets[sock_index].threads[call_type]);
	up(&wedge_sockets_sem);

	release_sock(sk);
	PRINT_IMPORTANT("Exited: call_pid=%d, rc=%d", call_pid, rc);
	return rc;
}

/* Data structures needed for protocol registration */
/* A proto struct for the dummy protocol */
static struct proto fins_proto = { .name = "FINS_PROTO", .owner = THIS_MODULE, .obj_size = sizeof(struct fins_sock), };

/* see IPX struct net_proto_family ipx_family_ops for comparison */
static struct net_proto_family fins_net_proto = { .family = PF_FINS, .create = fins_create, // This function gets called when socket() is called from userspace
		.owner = THIS_MODULE, };

/* Defines which functions get called when corresponding calls are made from userspace */
static struct proto_ops fins_proto_ops = { .owner = THIS_MODULE, .family = PF_FINS, //
		.release = fins_release, //sock_no_close,
		.bind = fins_bind, //sock_no_bind,
		.connect = fins_connect, //sock_no_connect,
		.socketpair = fins_socketpair, //sock_no_socketpair,
		.accept = fins_accept, //sock_no_accept,
		.getname = fins_getname, //sock_no_getname,
		.poll = fins_poll, //sock_no_poll,
		.ioctl = fins_ioctl, //sock_no_ioctl,
		.listen = fins_listen, //sock_no_listen,
		.shutdown = fins_shutdown, //sock_no_shutdown,
		.setsockopt = fins_setsockopt, //sock_no_setsockopt,
		.getsockopt = fins_getsockopt, //sock_no_getsockopt,
		.sendmsg = fins_sendmsg, //sock_no_sendmsg,
		.recvmsg = fins_recvmsg, //sock_no_recvmsg,
		.mmap = fins_mmap, //sock_no mmap,
		.sendpage = fins_sendpage, //sock_no_sendpage,
		};

/* Helper function to extract a unique socket ID from a given struct sock */
inline __u64 get_unique_sock_id(struct sock *sk) {
	//	return (__u64) &(sk->__sk_common); // Pointer to sock_common struct as unique ident
	return (__u32) &(sk->__sk_common); // Pointer to sock_common struct as unique ident
}

/* Functions to initialize and teardown the protocol */
static void setup_fins_protocol(void) {
	int rc; // used for reporting return value

	// Changing this value to 0 disables the FINS passthrough by default
	// Changing this value to 1 enables the FINS passthrough by default
	//fins_stack_passthrough_enabled = 1; //0; // Initialize kernel wide FINS data passthrough

	/* Call proto_register and report debugging info */
	rc = proto_register(&fins_proto, 1);
	PRINT_DEBUG("proto_register returned: %d", rc);
	PRINT_DEBUG("Made it through FINS proto_register()");

	/* Call sock_register to register the handler with the socket layer */
	rc = sock_register(&fins_net_proto);
	PRINT_DEBUG("sock_register returned: %d", rc);
	PRINT_DEBUG("Made it through FINS sock_register()");
}

static void teardown_fins_protocol(void) {
	/* Call sock_unregister to unregister the handler with the socket layer */
	sock_unregister(fins_net_proto.family);
	PRINT_DEBUG("Made it through FINS sock_unregister()");

	/* Call proto_unregister and report debugging info */
	proto_unregister(&fins_proto);
	PRINT_DEBUG("Made it through FINS proto_unregister()");
}

/* Functions to initialize and teardown the netlink socket */
static __s32 setup_fins_netlink(void) {
	// nl_data_ready is the name of the function to be called when the kernel receives a datagram on this netlink socket.
	fins_nl_sk = netlink_kernel_create(&init_net, NETLINK_FINS, 0, nl_data_ready, NULL, THIS_MODULE);
	if (fins_nl_sk == NULL) {
		PRINT_ERROR("Error creating socket.");
		return -10;
	}

	sema_init(&link_sem, 1);

	return 0;
}

static void teardown_fins_netlink(void) {
	// closes the netlink socket
	if (fins_nl_sk != NULL) {
		sock_release(fins_nl_sk->sk_socket);
	}
}

/* LKM specific functions */
/*
 * Note: the init and exit functions must be defined (or declared/declared in header file) before the macros are called
 */
static int __init fins_stack_wedge_init(void) {
	PRINT_IMPORTANT("############################################");
	PRINT_IMPORTANT("Unregistering AF_INET");
	sock_unregister(AF_INET);
	PRINT_IMPORTANT("Loading the fins_stack_wedge module");
	setup_fins_protocol();
	setup_fins_netlink();
	wedge_calls_init();
	wedge_sockets_init();
	fins_daemon_pid = -1;
	PRINT_IMPORTANT("Made it through the fins_stack_wedge initialization");

	return 0;
}

static void __exit fins_stack_wedge_exit(void) {
	PRINT_IMPORTANT("Unloading the fins_stack_wedge module");
	teardown_fins_netlink();
	teardown_fins_protocol();
	PRINT_IMPORTANT("Made it through the fins_stack_wedge removal");
	//the system call wrapped by rmmod frees all memory that is allocated in the module
}

/* Macros defining the init and exit functions */
module_init( fins_stack_wedge_init);
module_exit( fins_stack_wedge_exit);

/* Set the license and signing info for the module */
MODULE_LICENSE(M_LICENSE);
MODULE_DESCRIPTION(M_DESCRIPTION);
MODULE_AUTHOR(M_AUTHOR);
