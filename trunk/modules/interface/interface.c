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
	PRINT_DEBUG("Entered: module=%p", module);
	PRINT_IMPORTANT("Thread started: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);

	while (module->state == FMS_RUNNING) {
		interface_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Thread exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	PRINT_DEBUG("Exited: module=%p", module);
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

	if (ff->dataOrCtrl == FF_CONTROL) {
		interface_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			//interface_in_fdf(module, ff); //TODO remove?
			PRINT_WARN("todo error");
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
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		interface_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		interface_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_WARN("todo");
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
		PRINT_WARN("todo");
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
	PRINT_WARN("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void interface_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case INTERFACE_SET_PARAM_FLOWS:
		PRINT_DEBUG("param_id=INTERFACE_SET_PARAM_FLOWS (%d)", ff->ctrlFrame.param_id);
		module_set_param_flows(module, ff);
		break;
	case INTERFACE_SET_PARAM_LINKS:
		PRINT_DEBUG("param_id=INTERFACE_SET_PARAM_LINKS (%d)", ff->ctrlFrame.param_id);
		module_set_param_links(module, ff);
		break;
	case INTERFACE_SET_PARAM_DUAL:
		PRINT_DEBUG("param_id=INTERFACE_SET_PARAM_DUAL (%d)", ff->ctrlFrame.param_id);
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_WARN("param_id=default (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void interface_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_WARN("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void interface_exec_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case INTERFACE_EXEC_GET_ADDR:
		PRINT_DEBUG("param_id=INTERFACE_EXEC_GET_ADDR (%d)", ff->ctrlFrame.param_id);
		interface_exec_reply_get_addr(module, ff);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");
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
				PRINT_DEBUG("Updating host: cache=%p, mac=0x%012llx, ip=%u", cache, dst_mac, dst_ip);
				cache->mac = dst_mac;

				cache->seeking = 0;
				gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

				struct interface_request *request_resp;
				while (!list_is_empty(cache->request_list)) {
					request_resp = (struct interface_request *) list_remove_front(cache->request_list);

					//secure_metadata_writeToElement(request_resp->ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);

					PRINT_DEBUG("Injecting frame: ff=%p, src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", request_resp->ff, src_mac, dst_mac, ETH_TYPE_IP4);
					if (!interface_inject_pdu(md->inject_fd, request_resp->ff->dataFrame.pduLength, request_resp->ff->dataFrame.pdu, dst_mac, src_mac,
							ETH_TYPE_IP4)) {
						PRINT_ERROR("todo error");
						exit(-1); //TODO change, send FCF?
					}

					//add interface statistics, injected++
					interface_request_free(request_resp);
				}
			} else {
				PRINT_WARN("Not seeking addr. Dropping: ff=%p, src=0x%llx/'%u.%u.%u.%u', dst=0x%llx/'%u.%u.%u.%u', cache=%p",
						ff, src_mac, (src_ip&0xFF000000)>>24, (src_ip&0x00FF0000)>>16, (src_ip&0x0000FF00)>>8, (src_ip&0x000000FF), dst_mac, (dst_ip&0xFF000000)>>24, (dst_ip&0x00FF0000)>>16, (dst_ip&0x0000FF00)>>8, (dst_ip&0x000000FF), cache);
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

				PRINT_WARN("ARP failed to resolve address. Dropping: ff=%p, src=0x%llx/'%u.%u.%u.%u', dst=0x%llx/'%u.%u.%u.%u', cache=%p",
						ff, src_mac, (src_ip&0xFF000000)>>24, (src_ip&0x00FF0000)>>16, (src_ip&0x0000FF00)>>8, (src_ip&0x000000FF), dst_mac, (dst_ip&0xFF000000)>>24, (dst_ip&0x00FF0000)>>16, (dst_ip&0x0000FF00)>>8, (dst_ip&0x000000FF), cache);

				//TODO remove all requests from same source //split cache into (src,dst) tuples?
				if (cache->seeking) {
					list_remove(md->cache_list, cache);

					struct interface_request *request_resp;
					struct interface_store *temp_store;
					struct finsFrame *ff_err;
					int sent;
					while (!list_is_empty(cache->request_list)) {
						request_resp = (struct interface_request *) list_remove_front(cache->request_list);

						temp_store = (struct interface_store *) list_find1(md->store_list, interface_store_request_test, request_resp);
						if (temp_store != NULL) {
							temp_store->cache = NULL;
							interface_store_free(temp_store);
						}

						uint32_t flow;
						switch (request_resp->src_ip.ss_family) {
						case AF_INET:
							//32bit addr
							flow = INTERFACE_FLOW_ICMP; //INTERFACE_FLOW_IPV4;
							break;
						case AF_INET6:
							//128bit addr
							//flow = INTERFACE_FLOW_ICMPV6; //INTERFACE_FLOW_IPV6;
							//break;
							interface_request_free(request_resp);
							continue;
						default:
							PRINT_WARN("todo: family=%u", request_resp->src_ip.ss_family);
							interface_request_free(request_resp);
							continue;
						}

						ff_err = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
						ff_err->dataOrCtrl = FF_CONTROL;
						ff_err->metaData = request_resp->ff->metaData;
						request_resp->ff->metaData = NULL;

						ff_err->ctrlFrame.sender_id = module->index;
						ff_err->ctrlFrame.serial_num = gen_control_serial_num();
						ff_err->ctrlFrame.opcode = CTRL_ERROR;
						ff_err->ctrlFrame.param_id = INTERFACE_ERROR_GET_ADDR;

						ff_err->ctrlFrame.data_len = request_resp->ff->dataFrame.pduLength;
						ff_err->ctrlFrame.data = request_resp->ff->dataFrame.pdu;
						request_resp->ff->dataFrame.pduLength = 0;
						request_resp->ff->dataFrame.pdu = NULL;

						//should we separate icmp & error messages? what about disabling ICMP, what errors should it stop?
						//if yes, eth->ip->icmp or ip->proto
						//if no, eth->icmp->proto
						//if partial, eth->ip->icmp->proto (allows for similar to iptables)
						//Sending to ICMP mimic kernel func, if remove icmp stops error
						sent = module_send_flow(module, ff_err, flow);
						if (sent == 0) {
							freeFinsFrame(ff_err);
						}

						interface_request_free(request_resp);
					}

					interface_store_free(store);
				} else {
					//cache already confirmed, so do nothing
					list_remove(cache->request_list, request);

					//Send FCF error to IPv4, then? IPv4 send to ICMP or to each proto?

					interface_request_free(request);

					store->cache = NULL;
					interface_store_free(store);
				}
			} else {
				//do nothing, other requests sent
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
		secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
		uint32_t dst_ip;
		secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);

		uint64_t dst_mac;
		uint64_t src_mac = ifr->mac;
		//secure_metadata_writeToElement(ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
		PRINT_DEBUG("src: ifr=%p, mac=0x%012llx, ip=%u", ifr, src_mac, src_ip);
		PRINT_DEBUG("next hop: ip=%u", dst_ip);

		struct interface_cache *cache = (struct interface_cache *) list_find1(md->cache_list, interface_cache_ipv4_test, &dst_ip);
		if (cache != NULL) {
			if (cache->seeking) {
				PRINT_DEBUG("cache seeking: cache=%p, ip=%u", cache, dst_ip);

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
					PRINT_WARN("todo error");
					freeFinsFrame(ff);
				}
			} else {
				dst_mac = cache->mac;
				PRINT_DEBUG("next hop: cache=%p, mac=0x%012llx, ip=%u", cache, dst_mac, dst_ip);

				struct timeval current;
				gettimeofday(&current, 0);

				if (time_diff(&cache->updated_stamp, &current) <= INTERFACE_CACHE_TO_DEFAULT) {
					PRINT_DEBUG("up to date cache: cache=%p", cache);

					PRINT_DEBUG("Injecting frame: ff=%p, src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", ff, src_mac, dst_mac, ETH_TYPE_IP4);
					if (interface_inject_pdu(md->inject_fd, ff->dataFrame.pduLength, ff->dataFrame.pdu, dst_mac, src_mac, ETH_TYPE_IP4)) {
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
			PRINT_DEBUG("create cache, start seeking: ip=%u", dst_ip);
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
						PRINT_WARN("todo error");
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
		PRINT_WARN("todo error");
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
	if (interface_inject_pdu(md->inject_fd, ff->dataFrame.pduLength, ff->dataFrame.pdu, dst_mac, src_mac, ETH_TYPE_ARP)) {
		//add interface statistics, injected++
		freeFinsFrame(ff);
	} else {
		PRINT_ERROR("todo error");
		exit(-1); //TODO change, send FCF?
	}
}

void interface_out_ipv6(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_WARN("todo");
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
		PRINT_WARN("todo error");
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
	ff->ctrlFrame.param_id = INTERFACE_EXEC_GET_ADDR;

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
	PRINT_DEBUG("Entered: module=%p", module);
	PRINT_IMPORTANT("Thread started: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	struct interface_data *md = (struct interface_data *) module->data;

	int size_len = sizeof(int);
	int numBytes;
	int frame_len;
	uint8_t frame[ETH_FRAME_LEN_MAX];
	struct sniff_ethernet *hdr = (struct sniff_ethernet *) frame;

	uint64_t dst_mac;
	uint64_t src_mac;
	uint32_t ether_type;
	struct timeval current;

	metadata *meta;
	struct finsFrame *ff;

#ifdef DEBUG
	uint32_t count = 0;
#endif
	while (module->state == FMS_RUNNING) {
		//works but blocks, so can't shutdown properly, have to double ^C, kill, or wait for frame/kill capturer
		do {
			numBytes = read(md->capture_fd, &frame_len, size_len);
			if (numBytes <= 0) {
				if (module->state == FMS_RUNNING) {
					PRINT_ERROR("numBytes=%d", numBytes);
					exit(-1);
				} else {
					break;
				}
			}
		} while (module->state == FMS_RUNNING && numBytes <= 0);

		if (module->state != FMS_RUNNING) {
			break;
		}

		if (numBytes <= 0) {
			PRINT_ERROR("error reading size: numBytes=%d", numBytes);
			exit(-1);
			//break;
		}

		numBytes = read(md->capture_fd, frame, frame_len);
		if (numBytes <= 0) {
			PRINT_ERROR("error reading frame: numBytes=%d", numBytes);
			exit(-1);
			//break;
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

#ifdef DEBUG
		count++;
		PRINT_DEBUG("frame read: count=%u, frame_len=%d", count, frame_len);
		//TODO change back to PRINT_DEBUG?
		//print_hex_block(data,datalen);
#endif

		dst_mac = ((uint64_t) hdr->ether_dhost[0] << 40) + ((uint64_t) hdr->ether_dhost[1] << 32) + ((uint64_t) hdr->ether_dhost[2] << 24)
				+ ((uint64_t) hdr->ether_dhost[3] << 16) + ((uint64_t) hdr->ether_dhost[4] << 8) + (uint64_t) hdr->ether_dhost[5];
		src_mac = ((uint64_t) hdr->ether_shost[0] << 40) + ((uint64_t) hdr->ether_shost[1] << 32) + ((uint64_t) hdr->ether_shost[2] << 24)
				+ ((uint64_t) hdr->ether_shost[3] << 16) + ((uint64_t) hdr->ether_shost[4] << 8) + (uint64_t) hdr->ether_shost[5];
		ether_type = ntohs(hdr->ether_type);
		gettimeofday(&current, 0);

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x, stamp=%u.%u",
				dst_mac, src_mac, ether_type, (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);

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
			//break;
		default:
			PRINT_DEBUG("default: proto=0x%x (%u)", ether_type, ether_type);
			continue;
		}

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "recv_dst_mac", &dst_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(meta, "recv_src_mac", &src_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(meta, "recv_ether_type", &ether_type, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "recv_stamp", &current, META_TYPE_INT64);

		ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff->dataOrCtrl = FF_DATA;
		ff->metaData = meta;

		ff->dataFrame.directionFlag = DIR_UP;
		ff->dataFrame.pduLength = frame_len - SIZE_ETHERNET;
		ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(ff->dataFrame.pdu, frame + SIZE_ETHERNET, ff->dataFrame.pduLength);

		if (!module_send_flow(module, ff, flow)) {
			PRINT_ERROR("send to switch error, module=%p, ff=%p, flow=%u", module, ff, flow);
			freeFinsFrame(ff);
		}
	}

	PRINT_IMPORTANT("Thread exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	PRINT_DEBUG("Exited: module=%p", module);
	return NULL;
}

void interface_init_knobs(struct fins_module *module) {
	//metadata_element *root = config_root_setting(module->knobs);

	//metadata_element *exec_elem = secure_config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);

	//metadata_element *get_elem = secure_config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);

	//metadata_element *set_elem = secure_config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int interface_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_DEBUG("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	interface_init_knobs(module);

	module->data = secure_malloc(sizeof(struct interface_data));
	struct interface_data *md = (struct interface_data *) module->data;

	md->if_list = list_clone(envi->if_list, ifr_clone);
	if (md->if_list->len > INTERFACE_IF_LIST_MAX) {
		PRINT_WARN("todo");
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
	snprintf(addr.sun_path, UNIX_PATH_MAX, INJECT_PATH);

	md->inject_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (md->inject_fd < 0) {
		PRINT_ERROR("socket error: inject_fd=%d, errno=%u, str='%s'", md->inject_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", INJECT_PATH);
	if (connect(md->inject_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: inject_fd=%d, errno=%u, str='%s'", md->inject_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: inject_fd=%d, addr='%s'", md->inject_fd, addr.sun_path);

	PRINT_DEBUG("Creating dev/mac list");
	//TODO send device/mac info
	struct if_record *ifr;

	uint8_t buf[ETH_FRAME_LEN_MAX];
	memset(&buf, 0, ETH_FRAME_LEN_MAX);
	struct interface_to_inject_hdr *hdr = (struct interface_to_inject_hdr *) buf;

	int i, j;
	for (i = 0, j = 0; i < md->if_list->len; i++) {
		ifr = (struct if_record *) list_look(md->if_list, i);
		if (ifr_running_test(ifr) && ifr->mac != 0) {
			memcpy(hdr->iis[j].name, ifr->name, IFNAMSIZ);
			//hdr->iis[j].mac = ifr->mac;
			snprintf((char *) hdr->iis[j].mac, 2 * MAC_ADDR_LEN + 1, "%012llx", ifr->mac);

			//PRINT_IMPORTANT("iis[%d]: name='%s', mac=0x%012llx", j, hdr->iis[j].name, hdr->iis[j].mac);
			PRINT_IMPORTANT("iis[%d]: name='%s', mac='%s'", j, hdr->iis[j].name, hdr->iis[j].mac);
			j++;
		}
	}
	hdr->ii_num = (uint32_t) j;
	uint32_t buf_len = INTERFACE_INFO_SIZE(hdr->ii_num);

	int numBytes = write(md->inject_fd, &buf_len, sizeof(uint32_t));
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes=%d", numBytes);
		return 0;
	}

	numBytes = write(md->inject_fd, buf, buf_len);
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes=%d", numBytes);
		return 0;
	}
	sleep(1); //wait for Capturer to receive & setup capture socket

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, CAPTURE_PATH);

	md->capture_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (md->capture_fd < 0) {
		PRINT_ERROR("socket error: capture_fd=%d, errno=%u, str='%s'", md->capture_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("connecting to: addr='%s'", CAPTURE_PATH);
	if (connect(md->capture_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: capture_fd=%d, errno=%u, str='%s'", md->capture_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_DEBUG("connected at: capture_fd=%d, addr='%s'", md->capture_fd, addr.sun_path);

	PRINT_IMPORTANT("PCAP processes connected");
	return 1;
}

int interface_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_DEBUG("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	interface_get_ff(module);

	struct interface_data *md = (struct interface_data *) module->data;
	secure_pthread_create(&md->switch_to_interface_thread, attr, switch_to_interface, module);
	secure_pthread_create(&md->capturer_to_interface_thread, attr, capturer_to_interface, module);

	return 1;
}

int interface_pause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int interface_unpause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int interface_shutdown(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct interface_data *md = (struct interface_data *) module->data;
	//TODO expand this
	shutdown(md->capture_fd, SHUT_RDWR);
	close(md->capture_fd);
	shutdown(md->inject_fd, SHUT_RDWR);
	close(md->inject_fd);

	PRINT_IMPORTANT("Joining switch_to_interface_thread");
	pthread_join(md->switch_to_interface_thread, NULL);
	PRINT_IMPORTANT("Joining capturer_to_interface_thread");
	pthread_join(md->capturer_to_interface_thread, NULL);

	return 1;
}

int interface_release(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct interface_data *md = (struct interface_data *) module->data;
	PRINT_IMPORTANT("if_list->len=%u", md->if_list->len);
	list_free(md->if_list, ifr_free);
	PRINT_IMPORTANT("cache_list->len=%u", md->cache_list->len);
	list_free(md->cache_list, interface_cache_free);
	PRINT_IMPORTANT("store_list->len=%u", md->store_list->len);
	list_free(md->store_list, free);

	//free common module data
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
	PRINT_DEBUG("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, INTERFACE_LIB);
	module->flows_max = INTERFACE_MAX_FLOWS;
	module->ops = &interface_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_DEBUG("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
