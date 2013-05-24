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

//################ ARP/interface stuff //TODO move to common?
int interface_request_ipv4_test(struct interface_request *request, uint32_t *src_ip) {
	return addr4_get_ip(&request->src_ip) == *src_ip;
}

void interface_request_free(struct interface_request *request) {
	PRINT_DEBUG("Entered: request=%p", request);

	if (request->ff != NULL) {
		freeFinsFrame(request->ff);
	}

	free(request);
}

int interface_cache_ipv4_test(struct interface_cache *cache, uint32_t *ip) {
	return cache->ip.ss_family == AF_INET && addr4_get_ip(&cache->ip) == *ip;
}

int interface_cache_ipv6_test(struct interface_cache *cache, uint8_t *ip) {
	return cache->ip.ss_family == AF_INET6 && strcmp((char *) addr6_get_ip(&cache->ip), (char *) ip) == 0;
}

int interface_cache_non_seeking_test(struct interface_cache *cache) {
	return !cache->seeking;
}

void interface_cache_free(struct interface_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (cache->request_list != NULL) {
		list_free(cache->request_list, interface_request_free);
	}

	free(cache);
}

struct interface_store *interface_store_create(uint32_t serial_num, uint32_t sent, struct interface_cache *cache, struct interface_request *request) { //TODO remove request? not used
	PRINT_DEBUG("Entered: serial_num=%u, sent=%u, cache=%p, request=%p", serial_num, sent, cache, request);

	struct interface_store *store = (struct interface_store *) secure_malloc(sizeof(struct interface_store));
	store->serial_num = serial_num;
	store->sent = sent;
	store->cache = cache;
	store->request = request;

	PRINT_DEBUG("Exited: serial_num=%u, store=%p", serial_num, store);
	return store;
}

int interface_store_serial_test(struct interface_store *store, uint32_t *serial_num) {
	return store->serial_num == *serial_num;
}

int interface_store_request_test(struct interface_store *store, struct interface_request *request) {
	return store->request == request;
}

void interface_store_free(struct interface_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store->cache != NULL) {
		interface_cache_free(store->cache);
	}

	free(store);
}
//################

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

	if (ff->dataOrCtrl == FF_CONTROL) {
		interface_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			//interface_in_fdf(module, ff); //TODO remove?
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			interface_out_fdf(module, ff);
			PRINT_DEBUG("");
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else {
		PRINT_ERROR("todo error: dataOrCtrl=%u", ff->dataOrCtrl);
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
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		interface_read_param(module, ff);
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
		interface_exec(module, ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		interface_exec_reply(module, ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		exit(-1);
		break;
	}
}

void interface_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_ERROR("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void interface_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case INTERFACE_SET_PARAM_FLOWS:
		PRINT_DEBUG("INTERFACE_GET_PARAM_FLOWS");
		module_set_param_flows(module, ff);
		break;
	case INTERFACE_SET_PARAM_LINKS:
		PRINT_DEBUG("INTERFACE_GET_PARAM_LINKS");
		module_set_param_links(module, ff);
		break;
	case INTERFACE_SET_PARAM_DUAL:
		PRINT_DEBUG("INTERFACE_GET_PARAM_DUAL");
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_ERROR("param_id=default (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void interface_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_ERROR("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void interface_exec_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case EXEC_INTERFACE_GET_ADDR:
		PRINT_DEBUG("param_id=EXEC_ARP_GET_ADDR (%d)", ff->ctrlFrame.param_id);
		interface_exec_reply_get_addr(module, ff);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void interface_exec_reply_get_addr(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct interface_data *md = (struct interface_data *) module->data;

	struct interface_store *store = (struct interface_store *) list_find1(md->store_list, interface_store_serial_test, &ff->ctrlFrame.serial_num);
	if (store != NULL) {
		PRINT_DEBUG("store=%p, serial_num=%u, sent=%u, cache=%p, request=%p", store, store->serial_num, store->sent, store->cache, store->request);
		if (--store->sent == 0) {
			list_remove(md->store_list, store);
		}

		struct interface_cache *cache = store->cache;
		struct interface_request *request = store->request;

		if (ff->ctrlFrame.ret_val == FCF_TRUE) {
			uint64_t src_mac = request->src_mac;
			uint32_t src_ip = addr4_get_ip(&request->src_ip);
			uint32_t dst_ip = addr4_get_ip(&cache->ip);

			uint64_t dst_mac;
			secure_metadata_readFromElement(ff->metaData, "dst_mac", &dst_mac);

			if (cache->seeking) {
				PRINT_DEBUG("Updating host: cache=%p, mac=0x%llx, ip=%u", cache, dst_mac, dst_ip);
				cache->mac = dst_mac;

				cache->seeking = 0;
				gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

				struct interface_request *request_resp;
				while (!list_is_empty(cache->request_list)) {
					request_resp = (struct interface_request *) list_remove_front(cache->request_list);

					secure_metadata_writeToElement(request_resp->ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);

					PRINT_DEBUG("Injecting frame: ff=%p, src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", ff, src_mac, dst_mac, ETH_TYPE_IP4);
					if (!interface_inject_pdu(md->client_inject_fd, request_resp->ff->dataFrame.pduLength, request_resp->ff->dataFrame.pdu, dst_mac, src_mac,
							ETH_TYPE_IP4)) {
						PRINT_ERROR("todo error");
						exit(-1); //TODO change, send FCF?
					}

					//add interface statistics, injected++
					interface_request_free(request_resp);
				}
			} else {
				PRINT_ERROR("Not seeking addr. Dropping: ff=%p, src=0x%llx/%u, dst=0x%llx/%u, cache=%p", ff, src_mac, src_ip, dst_mac, dst_ip, cache);
			}

			if (store->sent == 0) {
				store->cache = NULL;
				interface_store_free(store);
			}
		} else {
			if (store->sent == 0) {
				uint64_t src_mac = request->src_mac;
				uint32_t src_ip = addr4_get_ip(&request->src_ip);
				uint64_t dst_mac = 0;
				uint32_t dst_ip = addr4_get_ip(&cache->ip);
				PRINT_ERROR("ARP failed to resolve address. Dropping: ff=%p, src=0x%llx/%u, dst=0x%llx/%u, cache=%p",
						ff, src_mac, src_ip, dst_mac, dst_ip, cache);

				//TODO remove all requests from same source //split cache into (src,dst) tuples?
				if (cache->seeking) {
					list_remove(md->cache_list, cache);

					struct interface_request *request_resp;
					struct interface_store *temp_store;
					while (!list_is_empty(cache->request_list)) {
						request_resp = (struct interface_request *) list_remove_front(cache->request_list);

						temp_store = (struct interface_store *) list_find1(md->store_list, interface_store_request_test, request_resp);
						if (temp_store != NULL) {
							temp_store->cache = NULL;
							interface_store_free(temp_store);
						}

						//TODO generate ICMP msg, send FCF error frame?
						//TODO or send icmp msg to ip/transport proto

						interface_request_free(request_resp);
					}

					interface_store_free(store);
				} else {
					//cache already confirmed, so do nothing
					list_remove(cache->request_list, request);

					//TODO generate ICMP msg, send FCF error frame?
					//TODO or send icmp msg to ip/transport proto

					interface_request_free(request);

					store->cache = NULL;
					interface_store_free(store);
				}
			}
		}
	} else {
		PRINT_ERROR("Exited, no corresponding store: ff=%p, serial_num=%u", ff, ff->ctrlFrame.serial_num);
	}

	freeFinsFrame(ff);
}

void interface_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	uint32_t ether_type;
	secure_metadata_readFromElement(ff->metaData, "send_ether_type", &ether_type);

	switch (ether_type) {
	case ETH_TYPE_IP4:
		//32bit addr
		interface_out_ipv4(module, ff);
		break;
	case ETH_TYPE_ARP:
		//send through
		interface_out_arp(module, ff);
		break;
	case ETH_TYPE_IP6:
		//128bit addr
		interface_out_ipv6(module, ff);
		break;
	default:
		break;
	}
}

void interface_out_ipv4(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct interface_data *md = (struct interface_data *) module->data;

	uint32_t if_index;
	secure_metadata_readFromElement(ff->metaData, "send_if_index", &if_index);

	struct if_record *ifr = (struct if_record *) list_find1(md->if_list, ifr_index_test, &if_index);
	if (ifr != NULL) {
		uint32_t src_ip;
		uint32_t dst_ip;

		secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
		secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);

		uint64_t dst_mac;
		uint64_t src_mac = ifr->mac;
		secure_metadata_writeToElement(ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
		PRINT_DEBUG("src: ifr=%p, mac=0x%llx, ip=%u", ifr, src_mac, src_ip);

		struct interface_cache *cache = (struct interface_cache *) list_find1(md->cache_list, interface_cache_ipv4_test, &dst_ip);
		if (cache != NULL) {
			if (cache->seeking) {
				PRINT_DEBUG("cache seeking: cache=%p", cache);

				if (list_has_space(cache->request_list)) {

					//TODO if src is first of unique in request_list, send FCF!

					struct interface_request *request = (struct interface_request *) secure_malloc(sizeof(struct interface_request));
					addr4_set_ip(&request->src_ip, src_ip);
					request->src_mac = src_mac;
					request->ff = ff;
					list_append(cache->request_list, request);

					gettimeofday(&cache->updated_stamp, 0);
				} else {
					PRINT_ERROR("Error: request_list full, request_list->len=%u, ff=%p", cache->request_list->len, ff);
					PRINT_ERROR("todo error");
					freeFinsFrame(ff);
				}
			} else {
				dst_mac = cache->mac;
				PRINT_DEBUG("dst: cache=%p, mac=0x%llx, ip=%u", cache, dst_mac, dst_ip);

				struct timeval current;
				gettimeofday(&current, 0);

				if (time_diff(&cache->updated_stamp, &current) <= INTERFACE_CACHE_TO_DEFAULT) {
					PRINT_DEBUG("up to date cache: cache=%p", cache);

					PRINT_DEBUG("Injecting frame: ff=%p, src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", ff, src_mac, dst_mac, ETH_TYPE_IP4);
					if (interface_inject_pdu(md->client_inject_fd, ff->dataFrame.pduLength, ff->dataFrame.pdu, dst_mac, src_mac, ETH_TYPE_IP4)) {
						//add interface statistics, injected++
						freeFinsFrame(ff);
					} else {
						PRINT_ERROR("todo error");
						exit(-1); //TODO change, send FCF?
					}
				} else {
					PRINT_DEBUG("cache expired: cache=%p", cache);
					if (list_has_space(cache->request_list) && list_has_space(md->store_list)) {
						uint32_t serial_num = gen_control_serial_num();
						int sent = interface_send_request(module, src_ip, dst_ip, serial_num);
						if (sent == -1 || sent == 0) {
							PRINT_ERROR("todo erro");
						}

						struct interface_request *request = (struct interface_request *) secure_malloc(sizeof(struct interface_request));
						addr4_set_ip(&request->src_ip, src_ip);
						request->src_mac = src_mac;
						request->ff = ff;
						list_append(cache->request_list, request);

						struct interface_store *store = interface_store_create(serial_num, sent, cache, request);
						list_append(md->store_list, store);

						cache->seeking = 1;
						gettimeofday(&cache->updated_stamp, 0);
					} else {
						if (list_has_space(cache->request_list)) {
							PRINT_ERROR("Error: no space, request_list->len=%u, ff=%p", cache->request_list->len, ff);
						} else {
							PRINT_ERROR("Error: no space, store_list full, ff=%p", ff);
						}
						freeFinsFrame(ff);
					}
				}
			}
		} else {
			PRINT_DEBUG("create cache: start seeking");
			if (list_has_space(md->store_list)) {
				uint32_t serial_num = gen_control_serial_num();
				int sent = interface_send_request(module, src_ip, dst_ip, serial_num);
				if (sent == -1 || sent == 0) {
					PRINT_ERROR("todo erro");
				}

				//TODO change this remove 1 cache by order of: nonseeking then seeking, most retries, oldest timestamp
				if (!list_has_space(md->cache_list)) {
					PRINT_DEBUG("Making space in cache_list");

					struct interface_cache *temp_cache = (struct interface_cache *) list_find(md->cache_list, interface_cache_non_seeking_test);
					if (temp_cache != NULL) {
						list_remove(md->cache_list, temp_cache);

						struct interface_request *temp_request;
						struct finsFrame *temp_ff;

						while (!list_is_empty(temp_cache->request_list)) {
							temp_request = (struct interface_request *) list_remove_front(temp_cache->request_list);
							temp_ff = temp_request->ff;
							module_reply_fcf(module, temp_ff, FCF_FALSE, 0);

							temp_request->ff = NULL;
							interface_request_free(temp_request);
						}

						interface_cache_free(temp_cache);
					} else {
						PRINT_ERROR("todo error");
						freeFinsFrame(ff);
						return;
					}
				}

				struct interface_cache *cache = (struct interface_cache *) secure_malloc(sizeof(struct interface_cache));
				addr4_set_ip(&cache->ip, dst_ip);
				cache->request_list = list_create(INTERFACE_REQUEST_LIST_MAX);
				list_append(md->cache_list, cache);

				struct interface_request *request = (struct interface_request *) secure_malloc(sizeof(struct interface_request));
				addr4_set_ip(&request->src_ip, src_ip);
				request->src_mac = src_mac;
				request->ff = ff;
				list_append(cache->request_list, request);

				struct interface_store *store = interface_store_create(serial_num, sent, cache, request);
				list_append(md->store_list, store);

				cache->seeking = 1;
				gettimeofday(&cache->updated_stamp, 0);
			} else {
				PRINT_ERROR("Error: no space, store_list full, ff=%p", ff);
				freeFinsFrame(ff);
			}
		}
	} else {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
	}
}

void interface_out_arp(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct interface_data *md = (struct interface_data *) module->data;

	uint64_t dst_mac;
	uint64_t src_mac;
	secure_metadata_readFromElement(ff->metaData, "send_dst_mac", &dst_mac);
	secure_metadata_readFromElement(ff->metaData, "send_src_mac", &src_mac);

	PRINT_DEBUG("Injecting frame: ff=%p, src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", ff, src_mac, dst_mac, ETH_TYPE_ARP);
	if (interface_inject_pdu(md->client_inject_fd, ff->dataFrame.pduLength, ff->dataFrame.pdu, dst_mac, src_mac, ETH_TYPE_ARP)) {
		//add interface statistics, injected++
		freeFinsFrame(ff);
	} else {
		PRINT_ERROR("todo error");
		exit(-1); //TODO change, send FCF?
	}
}

void interface_out_ipv6(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}

int interface_inject_pdu(int fd, uint32_t pduLength, uint8_t *pdu, uint64_t dst_mac, uint64_t src_mac, uint32_t ether_type) {
	PRINT_DEBUG("Entered: fd=%d, pduLength=%u, pdu=%p", fd, pduLength, pdu);

	int framelen = pduLength + SIZE_ETHERNET;
	PRINT_DEBUG("framelen=%d", framelen);

	uint8_t *frame = (uint8_t *) secure_malloc(framelen);
	struct sniff_ethernet *hdr = (struct sniff_ethernet *) frame;

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
		free(frame);
		return 0;
	}

	memcpy(hdr->data, pdu, pduLength);

	int numBytes = write(fd, &framelen, sizeof(int));
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		free(frame);
		return 0;
	}

	numBytes = write(fd, frame, framelen);
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		free(frame);
		return 0;
	}

	free(frame);
	return 1;
}

int interface_send_request(struct fins_module *module, uint32_t src_ip, uint32_t dst_ip, uint32_t serial_num) {
	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	secure_metadata_writeToElement(meta, "src_ip", &src_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "dst_ip", &dst_ip, META_TYPE_INT32);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = serial_num;
	ff->ctrlFrame.opcode = CTRL_EXEC;
	ff->ctrlFrame.param_id = EXEC_INTERFACE_GET_ADDR;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	int sent = module_send_flow(module, ff, INTERFACE_FLOW_ARP);
	if (sent == 0) {
		freeFinsFrame(ff);
	}
	return sent;
}

void *capturer_to_interface(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	struct interface_data *md = (struct interface_data *) module->data;
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
		//works but blocks, so can't shutdown properly, have to double ^C, kill, or wait for frame/kill capturer
		do {
			numBytes = read(md->client_capture_fd, &frame_len, size_len);
			if (numBytes <= 0) {
				PRINT_ERROR("numBytes=%d", numBytes);
				break;
			}
		} while (module->state == FMS_RUNNING && numBytes <= 0);

		if (module->state != FMS_RUNNING) {
			break;
		}

		if (numBytes <= 0) {
			PRINT_ERROR("error reading size: numBytes=%d", numBytes);
			break;
		}

		numBytes = read(md->client_capture_fd, frame, frame_len);
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
		ff->dataOrCtrl = FF_DATA;
		ff->metaData = meta;

		uint32_t flow;
		switch (ether_type) {
		case ETH_TYPE_IP4:
			PRINT_DEBUG("IPv4: proto=0x%x (%u)", ether_type, ether_type);
			flow = INTERFACE_FLOW_IPV4;
			break;
		case ETH_TYPE_ARP:
			PRINT_DEBUG("ARP: proto=0x%x (%u)", ether_type, ether_type);
			flow = INTERFACE_FLOW_ARP;
			break;
		case ETH_TYPE_IP6:
			PRINT_DEBUG("IPv6: proto=0x%x (%u)", ether_type, ether_type);
			flow = INTERFACE_FLOW_IPV6;
			continue;
		default:
			PRINT_DEBUG("default: proto=0x%x (%u)", ether_type, ether_type);
			freeFinsFrame(ff);
			continue;
		}

		ff->dataFrame.directionFlag = DIR_UP;
		ff->dataFrame.pduLength = frame_len - SIZE_ETHERNET;
		ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(ff->dataFrame.pdu, frame + SIZE_ETHERNET, ff->dataFrame.pduLength);

		if (!module_send_flow(module, ff, flow)) {
			PRINT_ERROR("send to switch error, ff=%p", ff);
			freeFinsFrame(ff);
		}
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void interface_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, "exec", CONFIG_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, "get", CONFIG_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(get_elem, LOGGER_GET_INTERVAL__str, LOGGER_GET_INTERVAL__id, LOGGER_GET_INTERVAL__type);
	//elem_add_param(get_elem, LOGGER_GET_REPEATS__str, LOGGER_GET_REPEATS__id, LOGGER_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, "set", CONFIG_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(set_elem, LOGGER_SET_INTERVAL__str, LOGGER_SET_INTERVAL__id, LOGGER_SET_INTERVAL__type);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int interface_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	interface_init_params(module);

	module->data = secure_malloc(sizeof(struct interface_data));
	struct interface_data *md = (struct interface_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	md->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		md->flows[i] = flows[i];
	}

	md->if_list = list_clone(envi->if_list, ifr_clone);
	if (md->if_list->len > INTERFACE_IF_LIST_MAX) {
		PRINT_ERROR("todo");
		struct linked_list *leftover = list_split(md->if_list, INTERFACE_IF_LIST_MAX - 1);
		list_free(leftover, free);
	}
	md->if_list->max = INTERFACE_IF_LIST_MAX;
	PRINT_IMPORTANT("if_list: list=%p, max=%u, len=%u", md->if_list, md->if_list->max, md->if_list->len);

	md->cache_list = list_create(INTERFACE_CACHE_LIST_MAX);
	md->store_list = list_create(INTERFACE_STORE_LIST_MAX);

	//TODO move to associated thread, so init() is nonblocking
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, CAPTURE_PATH);

	md->client_capture_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (md->client_capture_fd < 0) {
		PRINT_ERROR("socket error: capture_fd=%d, errno=%u, str='%s'", md->client_capture_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", CAPTURE_PATH);
	if (connect(md->client_capture_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: capture_fd=%d, errno=%u, str='%s'", md->client_capture_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: capture_fd=%d, addr='%s'", md->client_capture_fd, addr.sun_path);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, INJECT_PATH);

	md->client_inject_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (md->client_inject_fd < 0) {
		PRINT_ERROR("socket error: inject_fd=%d, errno=%u, str='%s'", md->client_inject_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", INJECT_PATH);
	if (connect(md->client_inject_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: inject_fd=%d, errno=%u, str='%s'", md->client_inject_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: inject_fd=%d, addr='%s'", md->client_inject_fd, addr.sun_path);

	PRINT_IMPORTANT("PCAP processes connected");
	return 1;
}

int interface_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct interface_data *md = (struct interface_data *) module->data;
	secure_pthread_create(&md->switch_to_interface_thread, attr, switch_to_interface, module);
	secure_pthread_create(&md->capturer_to_interface_thread, attr, capturer_to_interface, module);

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

	struct interface_data *md = (struct interface_data *) module->data;

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_interface_thread");
	pthread_join(md->switch_to_interface_thread, NULL);
	PRINT_IMPORTANT("Joining capturer_to_interface_thread");
	pthread_join(md->capturer_to_interface_thread, NULL);

	return 1;
}

int interface_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct interface_data *md = (struct interface_data *) module->data;
	PRINT_IMPORTANT("if_list->len=%u", md->if_list->len);
	list_free(md->if_list, ifr_free);
	PRINT_IMPORTANT("cache_list->len=%u", md->cache_list->len);
	list_free(md->cache_list, interface_cache_free);
	PRINT_IMPORTANT("store_list->len=%u", md->store_list->len);
	list_free(md->store_list, free);

	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
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
