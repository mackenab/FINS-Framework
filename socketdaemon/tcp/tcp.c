/*
 * tcp.c
 *
 *  Created on: Mar 14, 2011
 *      Author: Abdallah Abdallah
 */

//#include <arpa/inet.h>
#include <queueModule.h>
#include "tcp.h"

extern sem_t TCP_to_Switch_Qsem;
extern finsQueue TCP_to_Switch_Queue;

extern sem_t Switch_to_TCP_Qsem;
extern finsQueue Switch_to_TCP_Queue;

struct tcp_connection* conn_list; //The list of current connections we have
int conn_num;

struct tcp_queue* queue_create(uint32_t max) {
	struct tcp_queue *queue = NULL;
	queue = (struct tcp_queue *) malloc(sizeof(struct tcp_queue));

	queue->front = NULL;
	queue->end = NULL;

	queue->max = max;
	queue->len = 0;

	sem_init(&queue->sem, 0, 1);

	return queue;
}

void queue_append(struct tcp_queue *queue, uint8_t* data, uint32_t len,
		uint32_t seq_num, uint32_t seq_end) {
	struct tcp_node *node = NULL;
	struct tcp_node *comp = NULL;

	node = (struct tcp_node *) malloc(sizeof(struct tcp_node));
	node->data = data;
	node->len = len;
	node->seq_num = seq_num;
	node->seq_end = seq_end;

	node->next = NULL;
	if (queue_is_empty(queue)) {
		//queue empty
		queue->front = node;
	} else {
		//node after end
		queue->end->next = node;
	}
	queue->end = node;
	queue->len += len;
}

int queue_insert(struct tcp_queue *queue, uint8_t* data, uint32_t len,
		uint32_t seq_num, uint32_t seq_end) {

	struct tcp_node *node = NULL;
	struct tcp_node *comp = NULL;

	node = (struct tcp_node *) malloc(sizeof(struct tcp_node));
	node->data = data;
	node->len = len;
	node->seq_num = seq_num;
	node->seq_end = seq_end;

	if (queue_is_empty(queue)) {
		//queue empty
		node->next = NULL;
		queue->front = node;
		queue->end = node;
		queue->len += len;
		return 0;
	}

	if (seq_num < queue->front->seq_num) {
		if (queue->front->seq_num < seq_end) {
			free(node);
			return -1;
		}
		//node before front
		node->next = queue->front;
		queue->front = node;
		queue->len += len;
		return 0;
	}

	if (queue->end->seq_num < seq_num) {
		if (seq_end < queue->end->seq_end) {
			free(node);
			return -1;
		}
		//node after end
		node->next = NULL;
		queue->end->next = node;
		queue->end = node;
		queue->len += len;
		return 0;
	}

	comp = queue->front;
	while (comp->next != NULL) {
		if (seq_num < comp->seq_end) {
			free(node);

			return -1;
		}
		if (seq_num < comp->next->seq_num) {
			if (comp->next->seq_num < seq_end) {
				free(node);
				return -1;
			}
			//insert between comp & next
			node->next = comp->next;
			comp->next = node;
			queue->len += len;
			return 0;
		}
		if (seq_num == comp->next->seq_num) {
			free(node);

			return -1;
		}

		comp = comp->next;
	}

	//append to end
	node->next = NULL;
	comp->next = node;
	queue->end = node;
	queue->len += len;
	return 0;
}

void queue_remove_front(struct tcp_queue *queue) {
	struct tcp_node * old;

	old = queue->front;
	if (old) {
		queue->front = old->next;
		queue->len -= old->len;
	}
}

int queue_is_empty(struct tcp_queue *queue) {
	return queue->front == NULL;
}

int queue_has_space(struct tcp_queue *queue, uint32_t len) {
	return queue->len + len <= queue->max;
}

void *to_gbn_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to_gbn_thread thread started");

	while (conn->running_flag) {
		ret = read(conn->to_gbn_fd, &exp, sizeof(uint64_t)); //blocking read
		if (ret != sizeof(uint64_t)) {
			//read error
		}
		conn->to_gbn_flag = 1;
		if (conn->main_wait_flag) {
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	}
}

void *to_delayed_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to_delayed_thread thread started");

	while (conn->running_flag) {
		ret = read(conn->to_delayed_fd, &exp, sizeof(uint64_t)); //blocking read
		if (ret != sizeof(uint64_t)) {
			//read error
		}
		conn->to_delayed_flag = 1;
		if (conn->main_wait_flag) {
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	}
}

void *main_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;
	struct tcp_node *front;
	struct tcp_node *end;

	int on_wire = 0;
	uint8_t * packet;
	struct tcp_segment *tcp_seg;

	while (conn->running_flag) {
		PRINT_DEBUG(
				"flags: to=%d fast=%d gbn=%d delayed=%d delay_to=%d first=%d wait=%d ",
				conn->to_gbn_flag, conn->gbn_flag, conn->delayed_flag,
				conn->to_delayed_flag, conn->first_flag, conn->main_wait_flag);

		if (conn->to_gbn_flag) {
			//gbn timeout
			//set flags
			conn->to_gbn_flag = 0;
			conn->first_flag = 1;
			conn->gbn_flag = 1;
			//conn->fast_flag = 0;

			conn->main_wait_flag = 0; //handle cases where TO after set waitFlag
			sem_init(&conn->main_wait_sem, 0, 0);

			//congestion controll stuff
		}

		if (conn->fast_flag) {
			//fast retransmit
			if (conn->delayed_flag) {
				//add ACK
				conn->delayed_flag = 0;
				conn->to_delayed_flag = 0;
			} else {
				//normal
			}
		} else if (conn->gbn_flag) {
			//GBN
			if (conn->delayed_flag) {
				//add ACK
				conn->delayed_flag = 0;
				conn->to_delayed_flag = 0;
			} else {
				//normal
			}
		} else {
			//normal
			PRINT_DEBUG("Normal");

			if (sem_wait(&conn->send_queue->sem)) {
				PRINT_ERROR("conn->send_queue->sem wait prob");
				exit(-1);
			}

			end = conn->send_queue->end;
			if (queue_is_empty(conn->send_queue)) {
				on_wire = 0;
			} else {
				on_wire = conn->send_queue->end->seq_end - conn->host_seq_num;
			}

			if (sem_wait(&conn->write_queue->sem)) {
				PRINT_ERROR("conn->write_queue wait prob");
				exit(-1);
			}

			if (conn->write_queue->len && conn->window
					&& on_wire < conn->recvWindow /* && cong stuff*/) {
				PRINT_DEBUG("sending packet");

				tcp_seg = (struct tcp_segment *) malloc(
						sizeof(struct tcp_segment));
				tcp_seg->src_port = conn->host_port;
				tcp_seg->dst_port = conn->rem_port;
				tcp_seg->seq_num = conn->host_seq_num;
				tcp_seg->flags = 0;

				if (conn->delayed_flag) {
					//add ACK
					conn->delayed_flag = 0;
					conn->to_delayed_flag = 0;
					stopTimer(conn->to_delayed_fd);

					tcp_seg->ack_num = conn->rem_seq_num;
					tcp_seg->flags |= FLAG_ACK;
				}

				tcp_seg->win_size = conn->host_window;
				//checksum
				tcp_seg->urg_pointer = 0;

				//add options
				//TODO implement options system
				tcp_seg->options = NULL;
				tcp_seg->optlen = 0;

				//add options 5 = no options //TODO add options
				tcp_seg->flags |= (5) << 12;

				/*
				 uint8_t *options; //Options for the TCP segment (If Data Offset > 5)
				 int optlen; //length of the options
				 uint8_t *data; //Actual TCP segment data
				 int datalen;
				 */

			} else {
				PRINT_DEBUG("Normal: flagging waitFlag");
				conn->main_wait_flag = 1;
			}

			sem_post(&conn->write_queue->sem);
			sem_post(&conn->send_queue->sem);
		}

		if (conn->to_delayed_flag) {
			//delayed ACK timeout
			//send act
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;
		}

		if (0/*if finished*/) {
			//exit
		}

		if (conn->main_wait_flag && !conn->to_gbn_flag && !conn->to_delayed_flag
				&& !conn->fast_flag) {
			//wait
			//sem_wait(&wait_sem)
			//waitFlag = 0;
			//sem_init(&wait_sem, 0, 0);
		}
	}
}

void stopTimer(int fd) {
	PRINT_DEBUG("stopping timer=%d", fd);

	struct itimerspec its;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

void startTimer(int fd, double millis) {
	PRINT_DEBUG("starting timer=%d m=%f", fd, millis);

	struct itimerspec its;
	//its.it_value.tv_sec = static_cast<long int> (millis / 1000); //TODO
	//its.it_value.tv_nsec = static_cast<long int> (fmod(millis, 1000) * 1000000);
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

struct tcp_connection* conn_create(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port) {

	struct tcp_connection *conn = NULL;
	conn = (struct tcp_connection *) malloc(sizeof(struct tcp_connection));

	sem_init(&conn->conn_sem, 0, 1);
	conn->state = CONN_SETUP; //TODO: here?
	conn->running_flag = 1;

	conn->host_addr = host_addr;
	conn->host_port = host_port;
	conn->rem_addr = rem_addr;
	conn->rem_port = rem_port;

	sem_init(&conn->write_sem, 0, 1);

	conn->write_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO: could wait on this
	conn->send_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->recv_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->read_queue = queue_create(DEFAULT_MAX_QUEUE);

	//setup threads
	if (pthread_create(&conn->main_thread, NULL, main_thread, (void *) conn)) {
		PRINT_ERROR("ERROR: unable to create main_thread thread.");
		exit(-1);
	}

	//setup timers
	conn->to_gbn_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_gbn_fd == -1) {
		PRINT_ERROR("ERROR: unable to create to_fd.");
		exit(-1);
	}
	if (pthread_create(&conn->to_gbn_thread, NULL, to_gbn_thread,
			(void *) conn)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

	conn->to_delayed_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_delayed_fd == -1) {
		PRINT_ERROR("ERROR: unable to create delayed_fd.");
		exit(-1);
	}
	if (pthread_create(&conn->to_delayed_thread, NULL, to_delayed_thread,
			(void *) conn)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

	//TODO agree on these values during setup
	conn->MSS = 1024;
	conn->host_seq_num = 1;
	conn->host_max_window = 65535;
	conn->host_window = 65535;
	conn->rem_seq_num = 1;
	conn->rem_max_window = 65535;
	conn->rem_window = 65535;

	return conn;
}

void conn_append(struct tcp_connection *conn) {
	struct tcp_connection* temp = NULL;

	if (conn_list == NULL) {
		conn_list = conn;
	} else {
		temp = conn_list;
		while (temp->next != NULL) {
			temp = temp->next;
		}

		temp->next = conn;
		conn->next = NULL;
	}

	conn_num++;
}

//find a TCP connection with given host addr/port and remote addr/port
//NOTE: this means for incoming IP FF call with (dst_ip, src_ip, dst_p, src_p)
struct tcp_connection* conn_find(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port) {
	struct tcp_connection* temp = NULL;

	temp = conn_list;
	while (temp != NULL) {
		if (temp->host_addr == host_addr && temp->host_port == host_port
				&& temp->rem_addr == rem_addr && temp->rem_port == rem_port) {
			return temp;
		}
		temp = temp->next;
	}

	return NULL;
}

void conn_remove(struct tcp_connection *conn) {
	struct tcp_connection* temp = NULL;

	temp = conn_list;
	if (temp == NULL) {
		return;
	}

	if (temp == conn) {
		conn_list = conn_list->next;
		conn_num--;
		return;
	}

	while (temp->next != NULL) {
		if (temp->next == conn) {
			temp->next = conn->next;
			conn_num--;
			break;
		}
		temp = temp->next;
	}
}

int conn_is_empty(void) {
	return conn_num == 0;
}

int conn_has_space(uint32_t len) {
	return conn_num + len <= MAX_CONNECTIONS;
}

void conn_free(struct tcp_connection* conn) {
	//free the memory
}

void tcp_init() {

	PRINT_DEBUG("TCP started");

	conn_list = NULL;
	conn_num = 0;
	sem_init(&conn_list_sem, 0, 1);

	tcp_srand();
	while (1) {
		tcp_get_FF();
		PRINT_DEBUG();
		//	free(pff);
	}
}

void tcp_get_FF() {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_TCP_Qsem);
		ff = read_queue(Switch_to_TCP_Queue);
		sem_post(&Switch_to_TCP_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL) {
		// send to something to deal with FCF
		PRINT_DEBUG("send to CONTROL HANDLER !");
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == UP)) {
		tcp_in(ff);
		PRINT_DEBUG();
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == DOWN)) {
		tcp_out(ff);
		PRINT_DEBUG();
	}

}

void tcp_to_switch(struct finsFrame * ff) {

	sem_wait(&TCP_to_Switch_Qsem);
	write_queue(ff, TCP_to_Switch_Queue);
	sem_post(&TCP_to_Switch_Qsem);

}

//Get a random number to use as a starting sequence number
int tcp_rand() {
	return rand(); //Just use the standard C random number generator for now
}

//Seed the above random number generator
void tcp_srand() {
	srand(time(NULL)); //Just use the standard C random number generator for now
}

//--------------------------------------------
// Calculate the checksum of this TCP segment.
// (basically identical to ICMP_checksum().)
//--------------------------------------------
uint16_t TCP_checksum(struct finsFrame * ff) { //TODO: redo/check
	int sum = 0;
	unsigned char *w = ff->dataFrame.pdu;
	int nleft = ff->dataFrame.pduLength;

	//if(nleft % 2)  //Check if we've got an uneven number of bytes here, and deal with it accordingly if we do.
	//{
	//	nleft--;  //By decrementing the number of bytes we have to add in
	//	sum += ((int)(ff->dataframe.pdu[nleft])) << 8; //And shifting these over, adding them in as if they're the high byte of a 2-byte pair
	//This is as per specification of the checksum from the RFC: "If the total length is odd, the received data is padded with one
	// octet of zeros for computing the checksum." We don't explicitly add an octet of zeroes, but this has the same result.
	//}

	while (nleft > 0) {
		//Deal with the high and low words of each 16-bit value here. I tried earlier to do this 'normally' by
		//casting the pdu to unsigned short, but the little-vs-big-endian thing messed it all up. I'm just avoiding
		//the whole issue now by treating the values as high-and-low-word pairs, and bit-shifting to compensate.
		sum += (int) (*w++) << 8; //First one is high word: shift before adding in
		sum += *w++; //Second one is low word: just add in
		nleft -= 2; //Decrement by 2, since we're taking 2 at a time
	}

	//Fully fill out the checksum
	for (;;) {
		sum = (sum >> 16) + (sum & 0xFFFF); //Get the sum shifted over added into the current sum
		if (!(sum >> 16)) //Continue this until the sum shifted over is zero
			break;
	}
	return ~((uint16_t)(sum)); //Return one's complement of the sum
}

uint8_t* copy_uint8(uint8_t *ptr, uint8_t val) {
	*ptr++ = val;
	return ptr;
}

uint8_t* copy_uint16(uint8_t *ptr, uint16_t val) {
	*ptr++ = (uint8_t)(val >> 8);
	*ptr++ = (uint8_t)((val << 8) >> 8);
	return ptr;
}

uint8_t* copy_uint32(uint8_t *ptr, uint32_t val) {
	*ptr++ = (uint8_t)(val >> 24);
	*ptr++ = (uint8_t)((val << 8) >> 24);
	*ptr++ = (uint8_t)((val << 16) >> 24);
	*ptr++ = (uint8_t)((val << 24) >> 24);
	return ptr;
}

uint8_t* copy_uint64(uint8_t *ptr, uint64_t val) {
	*ptr++ = (uint8_t)(val >> 56);
	*ptr++ = (uint8_t)((val << 8) >> 56);
	*ptr++ = (uint8_t)((val << 16) >> 56);
	*ptr++ = (uint8_t)((val << 24) >> 56);
	*ptr++ = (uint8_t)((val << 32) >> 56);
	*ptr++ = (uint8_t)((val << 40) >> 56);
	*ptr++ = (uint8_t)((val << 48) >> 56);
	*ptr++ = (uint8_t)((val << 56) >> 56);
	return ptr;
}

struct finsFrame* tcp_to_fins(struct tcp_segment* tcp) {
	struct finsFrame* ffreturn = NULL;

	ffreturn = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	//ffreturn->dataOrCtrl; //leave unset?
	//ffreturn->destinationID;	// destination module ID
	//ffreturn->directionFlag;// ingress or egress network data; see above

	ffreturn->dataFrame.metaData = (metadata *) malloc(sizeof(metadata));
	metadata_writeToElement(ffreturn->dataFrame.metaData, "srcport",
			&(tcp->src_port), META_TYPE_INT); //Write the source port in
	metadata_writeToElement(ffreturn->dataFrame.metaData, "dstport",
			&(tcp->dst_port), META_TYPE_INT); //And the destination port

	ffreturn->dataFrame.pduLength = tcp->datalen + HEADERSIZE(tcp->flags); //Add in the header size for this, too
	ffreturn->dataFrame.pdu = (unsigned char*) malloc(
			ffreturn->dataFrame.pduLength);

	uint8_t *ptr = ffreturn->dataFrame.pdu; //Start pointing at the beginning of the pdu data
	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	//Source port

	/*//might be the better way
	 *(uint16_t *) ptr = htons(tcp->dst_port);
	 ptr += 2;
	 *(uint32_t *) ptr = htonl(tcp->seq_num);
	 ptr += 4;
	 */

	ptr = copy_uint16(ptr, tcp->src_port);
	ptr = copy_uint16(ptr, tcp->dst_port);
	ptr = copy_uint32(ptr, tcp->seq_num);
	ptr = copy_uint32(ptr, tcp->ack_num);
	ptr = copy_uint16(ptr, tcp->flags);
	ptr = copy_uint16(ptr, tcp->win_size);
	ptr = copy_uint16(ptr, tcp->checksum);
	ptr = copy_uint16(ptr, tcp->urg_pointer);

	if (tcp->optlen > 0) {
		memcpy(ptr, tcp->options, tcp->optlen);
		ptr += tcp->optlen;
	}

	if (tcp->datalen > 0) {
		memcpy(ptr, tcp->data, tcp->datalen);
		ptr += tcp->datalen;
	}

	return ffreturn;
}

//------------------------------------------------------------------------------
// Fill out a tcp segment from a finsFrame. Gets the data it needs from the PDU.
//------------------------------------------------------------------------------
struct tcp_segment* fins_to_tcp(struct finsFrame* ff) {
	struct tcp_segment* tcpreturn = NULL;
	tcpreturn = (struct tcp_segment*) malloc(sizeof(struct tcp_segment));
	if (!tcpreturn) {
		PRINT_ERROR("tcpreturn malloc error");
		return NULL;
	}

	if (ff->dataFrame.pduLength < MIN_TCP_HEADER_LEN) {
		return NULL;
	}

	uint8_t* ptr = ff->dataFrame.pdu; //Start pointing at the beginning of the pdu data
	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	//Source port
	tcpreturn->src_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->src_port += *ptr++;
	//Destination port
	tcpreturn->dst_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->dst_port += *ptr++;
	//Sequence number
	tcpreturn->seq_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->seq_num += *ptr++;
	//Acknowledgment number
	tcpreturn->ack_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->ack_num += *ptr++;
	//Flags and data offset
	tcpreturn->flags = (uint16_t)(*ptr++) << 8;
	tcpreturn->flags += *ptr++;
	//Window size
	tcpreturn->win_size = (uint16_t)(*ptr++) << 8;
	tcpreturn->win_size += *ptr++;
	//Checksum
	tcpreturn->checksum = (uint16_t)(*ptr++) << 8;
	tcpreturn->checksum += *ptr++;
	//Urgent pointer
	tcpreturn->urg_pointer = (uint16_t)(*ptr++) << 8;
	tcpreturn->urg_pointer += *ptr++;

	//Now copy the rest of the data, starting with the options
	tcpreturn->optlen = HEADERSIZE(tcpreturn->flags) - MIN_TCP_HEADER_LEN;
	if (tcpreturn->optlen > 0) {
		tcpreturn->options = (uint8_t*) malloc(tcpreturn->optlen);
		int i;
		for (i = 0; i < tcpreturn->optlen; i++) {
			tcpreturn->options[i] = *ptr++;
		}
	}

	//And fill in the data length and the data, also
	tcpreturn->datalen = ff->dataFrame.pduLength - HEADERSIZE(tcpreturn->flags);
	if (tcpreturn->datalen > 0) {
		tcpreturn->data = (uint8_t*) malloc(tcpreturn->datalen);
		int i;
		for (i = 0; i < tcpreturn->datalen; i++) {
			tcpreturn->data[i] = *ptr++;
		}
	}

	return tcpreturn; //Done
}

struct tcp_segment* fins_to_tcp(struct finsFrame* ff) {

