#include "interface_internal.h"

/** special functions to print the data within a frame for testing*/

/** ---------------------------------------------------------*/

int interface_setNonblocking(int fd) { //TODO move to common file?
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

int interface_setBlocking(int fd) {
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

void *switch_to_interface(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		interface_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
} // end of Inject Function

void interface_get_ff(struct fins_module *module) {
	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL); //TODO change logic here, combine with switch_to_interface?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	PRINT_DEBUG(" At least one frame has been read from the Switch to Etherstub ff=%p", ff);

	if (ff->dataOrCtrl == CONTROL) {
		interface_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			//interface_in_fdf(module, ff); //TODO remove?
			PRINT_ERROR("todo error");
		} else { //directionFlag==DIR_DOWN
			interface_out_fdf(module, ff);
			PRINT_DEBUG("");
		}
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}
}

void interface_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		interface_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void interface_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct interface_data *data = (struct interface_data *) module->data;
	int i;

	switch (ff->ctrlFrame.param_id) {
	case PARAM_FLOWS:
		PRINT_DEBUG("PARAM_FLOWS");
		uint32_t flows_num = ff->ctrlFrame.data_len / sizeof(uint32_t);
		uint32_t *flows = (uint32_t *) ff->ctrlFrame.data;

		if (module->flows_max < flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = flows_num;

		for (i = 0; i < flows_num; i++) {
			data->flows[i] = flows[i];
		}

		//freeFF frees flows
		break;
	case PARAM_LINKS:
		PRINT_DEBUG("PARAM_LINKS");
		if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		struct linked_list *link_list = (struct linked_list *) ff->ctrlFrame.data;
		data->link_list = link_list;

		ff->ctrlFrame.data = NULL;
		break;
	case PARAM_DUAL:
		PRINT_DEBUG("PARAM_DUAL");

		if (ff->ctrlFrame.data_len != sizeof(struct fins_module_table)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		struct fins_module_table *table = (struct fins_module_table *) ff->ctrlFrame.data;

		if (module->flows_max < table->flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = table->flows_num;

		for (i = 0; i < table->flows_num; i++) {
			data->flows[i] = table->flows[i];
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		data->link_list = table->link_list;

		//freeFF frees table
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		break;
	}

	freeFinsFrame(ff);
}

void interface_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	struct interface_data *data = (struct interface_data *) module->data;

	uint64_t dst_mac;
	uint64_t src_mac;
	uint32_t ether_type;

	uint8_t *frame;
	struct sniff_ethernet *hdr;
	int framelen;
	int numBytes;

	metadata *meta = ff->metaData;
	secure_metadata_readFromElement(meta, "send_dst_mac", &dst_mac);
	secure_metadata_readFromElement(meta, "send_src_mac", &src_mac);
	secure_metadata_readFromElement(meta, "send_ether_type", &ether_type);

	PRINT_DEBUG("send frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

	framelen = ff->dataFrame.pduLength + SIZE_ETHERNET;
	PRINT_DEBUG("framelen=%d", framelen);

	frame = (uint8_t *) secure_malloc(framelen);
	hdr = (struct sniff_ethernet *) frame;

	hdr->ether_dhost[0] = (dst_mac >> 40) & 0xff;
	hdr->ether_dhost[1] = (dst_mac >> 32) & 0xff;
	hdr->ether_dhost[2] = (dst_mac >> 24) & 0xff;
	hdr->ether_dhost[3] = (dst_mac >> 16) & 0xff;
	hdr->ether_dhost[4] = (dst_mac >> 8) & 0xff;
	hdr->ether_dhost[5] = dst_mac & 0xff;

	hdr->ether_shost[0] = (src_mac >> 40) & 0xff;
	hdr->ether_shost[1] = (src_mac >> 32) & 0xff;
	hdr->ether_shost[2] = (src_mac >> 24) & 0xff;
	hdr->ether_shost[3] = (src_mac >> 16) & 0xff;
	hdr->ether_shost[4] = (src_mac >> 8) & 0xff;
	hdr->ether_shost[5] = src_mac & 0xff;

	if (ether_type == ETH_TYPE_ARP) {
		hdr->ether_type = htons(ETH_TYPE_ARP);
	} else if (ether_type == ETH_TYPE_IP4) {
		hdr->ether_type = htons(ETH_TYPE_IP4);
	} else {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	//memcpy(frame + SIZE_ETHERNET, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	memcpy(hdr->data, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	//	print_finsFrame(ff);
	PRINT_DEBUG("daemon inject to ethernet stub ");

	numBytes = write(data->client_inject_fd, &framelen, sizeof(int));
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	numBytes = write(data->client_inject_fd, frame, framelen);
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	freeFinsFrame(ff);
	free(frame);
}

void *capturer_to_interface(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	struct interface_data *data = (struct interface_data *) module->data;
	PRINT_IMPORTANT("Entered: module=%p", module);

	int size_len = sizeof(int);
	int numBytes;
	int frame_len;
	uint8_t frame[10 * ETH_FRAME_LEN_MAX];
	struct sniff_ethernet *hdr = (struct sniff_ethernet *) frame;

	uint64_t dst_mac;
	uint64_t src_mac;
	uint32_t ether_type;
	struct timeval current;

	metadata *meta;
	struct finsFrame *ff;

	while (module->state == FMS_RUNNING) {
		/*
		 if (0) { //works, allows for terminating, though creates unbound while(1) loop
		 interface_setNonblocking(capture_pipe_fd);
		 do {
		 numBytes = read(capture_pipe_fd, &frame_len, sizeof(int));
		 } while (interface_proto.running_flag && numBytes <= 0);

		 if (!interface_proto.running_flag) {
		 break;
		 }

		 interface_setBlocking(capture_pipe_fd);
		 }
		 */
		//if (1) { //works but blocks, so can't shutdown properly, have to double ^C, kill, or wait for frame/kill capturer
		//PRINT_IMPORTANT("Reading");
		do {
			numBytes = read(data->client_capture_fd, &frame_len, size_len);
			if (numBytes <= 0) {
				PRINT_ERROR("numBytes=%d", numBytes);
				break;
			}
		} while (module->state == FMS_RUNNING && numBytes <= 0);

		if (module->state != FMS_RUNNING) {
			break;
		}
		//}

		if (numBytes <= 0) {
			PRINT_ERROR("error reading size: numBytes=%d", numBytes);
			break;
		}

		numBytes = read(data->client_capture_fd, frame, frame_len);
		if (numBytes <= 0) {
			PRINT_ERROR("error reading frame: numBytes=%d", numBytes);
			break;
		}

		if (numBytes != frame_len) {
			PRINT_ERROR("lengths not equal: frame_len=%d, numBytes=%d", frame_len, numBytes);
			continue;
		}

		if (frame_len > ETH_FRAME_LEN_MAX) {
			PRINT_ERROR("len too large: frame_len=%d, max=%d", frame_len, ETH_FRAME_LEN_MAX);
			continue;
		}

		if (frame_len < SIZE_ETHERNET) {
			PRINT_ERROR("frame too small: frame_len=%d, min=%d", frame_len, SIZE_ETHERNET);
			continue;
		}

		PRINT_DEBUG("frame read: frame_len=%d", frame_len);
		//print_hex_block(data,datalen);
		//continue;

		dst_mac = ((uint64_t) hdr->ether_dhost[0] << 40) + ((uint64_t) hdr->ether_dhost[1] << 32) + ((uint64_t) hdr->ether_dhost[2] << 24)
				+ ((uint64_t) hdr->ether_dhost[3] << 16) + ((uint64_t) hdr->ether_dhost[4] << 8) + (uint64_t) hdr->ether_dhost[5];
		src_mac = ((uint64_t) hdr->ether_shost[0] << 40) + ((uint64_t) hdr->ether_shost[1] << 32) + ((uint64_t) hdr->ether_shost[2] << 24)
				+ ((uint64_t) hdr->ether_shost[3] << 16) + ((uint64_t) hdr->ether_shost[4] << 8) + (uint64_t) hdr->ether_shost[5];
		ether_type = ntohs(hdr->ether_type);
		gettimeofday(&current, 0);

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x, stamp=%u.%u",
				dst_mac, src_mac, ether_type, (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "recv_dst_mac", &dst_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(meta, "recv_src_mac", &src_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(meta, "recv_ether_type", &ether_type, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "recv_stamp", &current, META_TYPE_INT64);

		ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff->dataOrCtrl = DATA;
		ff->metaData = meta;

		ff->dataFrame.directionFlag = DIR_UP;
		ff->dataFrame.pduLength = frame_len - SIZE_ETHERNET;
		ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(ff->dataFrame.pdu, frame + SIZE_ETHERNET, ff->dataFrame.pduLength);

		if (!module_send_flow(module, (struct fins_module_table *) module->data, ff, INTERFACE_FLOW_UP)) {
			PRINT_ERROR("send to switch error, ff=%p", ff);
			freeFinsFrame(ff);
		}
	}

	PRINT_IMPORTANT("Exited");
	return NULL;
}

int interface_init(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	//interface_init_params(module);

	module->data = secure_malloc(sizeof(struct interface_data));
	struct interface_data *data = (struct interface_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
	}

	//TODO move to associated thread, so init() is nonblocking
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, CAPTURE_PATH);

	data->client_capture_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (data->client_capture_fd < 0) {
		PRINT_ERROR("socket error: capture_fd=%d, errno=%u, str='%s'", data->client_capture_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", CAPTURE_PATH);
	if (connect(data->client_capture_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: capture_fd=%d, errno=%u, str='%s'", data->client_capture_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: capture_fd=%d, addr='%s'", data->client_capture_fd, addr.sun_path);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, INJECT_PATH);

	data->client_inject_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (data->client_inject_fd < 0) {
		PRINT_ERROR("socket error: inject_fd=%d, errno=%u, str='%s'", data->client_inject_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", INJECT_PATH);
	if (connect(data->client_inject_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: inject_fd=%d, errno=%u, str='%s'", data->client_inject_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: inject_fd=%d, addr='%s'", data->client_inject_fd, addr.sun_path);

	PRINT_IMPORTANT("PCAP processes connected");
	return 1;
}

int interface_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct interface_data *data = (struct interface_data *) module->data;
	secure_pthread_create(&data->switch_to_interface_thread, attr, switch_to_interface, module);
	secure_pthread_create(&data->capturer_to_interface_thread, attr, capturer_to_interface, module);

	return 1;
}

int interface_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int interface_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int interface_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct interface_data *data = (struct interface_data *) module->data;

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_interface_thread");
	pthread_join(data->switch_to_interface_thread, NULL);
	PRINT_IMPORTANT("Joining capturer_to_interface_thread");
	pthread_join(data->capturer_to_interface_thread, NULL);

	return 1;
}

int interface_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct interface_data *data = (struct interface_data *) module->data;
	//TODO free all module related mem

	//delete threads

	if (data->link_list != NULL) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void interface_dummy(void) {

}

static struct fins_module_ops interface_ops = { .init = interface_init, .run = interface_run, .pause = interface_pause, .unpause = interface_unpause,
		.shutdown = interface_shutdown, .release = interface_release, };

struct fins_module *interface_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, INTERFACE_LIB);
	module->flows_max = INTERFACE_MAX_FLOWS;
	module->ops = &interface_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
