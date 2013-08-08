/*
 *  *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 *
 * @file ethermod.c This code is based on the modified version mentioned above
 * which is provided by the Tcpdump group
 *
 * @date Nov 21, 2010
 * @author: Abdallah Abdallah
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <signal.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "ethermod.h"
#include "wifistub.h"

/*
 * app name/banner
 */
void print_app_banner(void) {

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
	printf("\n The message printed above is a part of ");
	printf("\n the redistribution conditions requested by the Tcpdump group \n");

	return;
}

/** handling termination ctrl+c signal
 * */
void capturer_termination_handler(int sig) {
	PRINT_IMPORTANT("*****************");
	PRINT_IMPORTANT("pid=%d", getpid());

	/*
	 PRINT_IMPORTANT("Capture: capture count=%llu", server_capture_count);
	 PRINT_IMPORTANT("Capture: inject count=%llu", server_inject_count);

	 if (inject_handle != NULL) {
	 pcap_close(inject_handle);
	 }

	 if (capture_handle != NULL) {
	 pcap_close(capture_handle);
	 }
	 */
	exit(2);
}

void capturer_dummy(void) {

}

void print_hex(uint32_t msg_len, uint8_t *msg_pt) {
	uint8_t *temp = (uint8_t *) malloc(3 * msg_len + 1);
	uint8_t *pt = temp;
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
	PRINT_IMPORTANT("msg='%s'\n", temp);
	free(temp);
}

#include <errno.h>
#include <semaphore.h>
#include <sys/time.h>
#include <unistd.h>

void processes_init(int inject_fd) {
	PRINT_DEBUG("Entered: inject_fd=%d", inject_fd);

	int numBytes;
	uint32_t buf_len;
	uint8_t buf[ETH_FRAME_LEN_MAX];

	numBytes = read(inject_fd, &buf_len, sizeof(uint32_t));
	if (numBytes <= 0) {
		PRINT_ERROR("size read fail: numBytes=%u", numBytes);
		close(inject_fd);
		return;
	}

	if (buf_len > ETH_FRAME_LEN_MAX) {
		PRINT_ERROR("len too large: buf_len=%u, max=%d", buf_len, ETH_FRAME_LEN_MAX);
		close(inject_fd);
		return;
	}

	numBytes = read(inject_fd, buf, buf_len);
	if (numBytes <= 0) {
		PRINT_ERROR("error reading frame: numBytes=%d", numBytes);
		close(inject_fd);
		return;
	}

	if (numBytes != buf_len) {
		PRINT_ERROR("lengths not equal: buf_len=%u, numBytes=%d", buf_len, numBytes);
		close(inject_fd);
		return;
	}

	if (buf_len < INTERFACE_INFO_MIN_SIZE) {
		PRINT_ERROR("frame too small: buf_len=%u, min=%u", buf_len, INTERFACE_INFO_MIN_SIZE);
		close(inject_fd);
		return;
	}

	//print_hex(buf_len*2, buf);

	struct interface_to_inject_hdr *hdr = (struct interface_to_inject_hdr *) buf;
	if (buf_len != INTERFACE_INFO_SIZE(hdr->ii_num)) {
		PRINT_ERROR("lengths not equal: buf_len=%u, ii_num=%u, info_size=%u", buf_len, hdr->ii_num, INTERFACE_INFO_SIZE(hdr->ii_num));
		close(inject_fd);
		return;
	}
	PRINT_IMPORTANT("ii read: buf_len=%u, ii_num=%u", buf_len, hdr->ii_num);

	int i;
	for (i = 0; i < hdr->ii_num; i++) {
		//PRINT_IMPORTANT("iis[%d]: name='%s', mac=0x%012llx", i, hdr->iis[i].name, hdr->iis[i].mac);
		PRINT_IMPORTANT("iis[%d]: name='%s', mac='%s'", i, hdr->iis[i].name, hdr->iis[i].mac);
	}

	if (hdr->ii_num == 0) {
		PRINT_ERROR("no active interfaces: ii_num=%u", hdr->ii_num);
		close(inject_fd);
		return;
	}

	//TODO eventually remove this
	if (hdr->ii_num != 1) {
		PRINT_ERROR("Currently only able to support 1 interface: if_num=%u", hdr->ii_num);
		close(inject_fd);
		return;
	}

	struct processes_shared *shared = (struct processes_shared *) mmap(NULL, sizeof(struct processes_shared), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED) {
		PRINT_ERROR("mmap fail: errno=%u, str='%s'", errno, strerror(errno));
		close(inject_fd);
		return;
	}
	memset(shared, 0, sizeof(struct processes_shared));

	shared->running_flag = 1;
	shared->inject_fd = inject_fd;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, CAPTURE_PATH);
	unlink(addr.sun_path);

	int server_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (server_fd < 0) {
		PRINT_ERROR("socket error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		close_pipes(shared);
		return;
	}
	if (fchmod(server_fd, ALLPERMS) < 0) {
		PRINT_ERROR("fchmod capture: capture_path='%s', errno=%u, str='%s'", CAPTURE_PATH, errno, strerror(errno));
		close_pipes(shared);
		close(server_fd);
		return;
	}

	mode_t old_mask = umask(0);
	PRINT_IMPORTANT("binding to: addr='%s'", CAPTURE_PATH);
	if (bind(server_fd, (struct sockaddr *) &addr, size) < 0) {
		PRINT_ERROR("bind error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		close_pipes(shared);
		close(server_fd);
		return;
	}
	umask(old_mask);

	if (listen(server_fd, 1) < 0) {
		PRINT_ERROR("listen error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		close_pipes(shared);
		close(server_fd);
		return;
	}

	shared->capture_fd = accept(server_fd, (struct sockaddr *) &addr, (socklen_t *) &size);
	close(server_fd);
	if (shared->capture_fd < 0) {
		PRINT_ERROR("accept error: capture_fd=%d, errno=%u, str='%s'", shared->capture_fd, errno, strerror(errno));
		close_pipes(shared);
		return;
	}
	PRINT_DEBUG("accepted at: capture_fd=%d, addr='%s'", shared->capture_fd, addr.sun_path);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	PRINT_IMPORTANT("sleeping 5s, so daemon will connect: time=%12u.%06u", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);
	sleep(5);
	gettimeofday(&tv, NULL);
	PRINT_IMPORTANT("Active: time=%12u.%06u", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

	for (i = 0; i < hdr->ii_num; i++) {
		//PRINT_IMPORTANT("iis[%d]: name='%s', mac=0x%012llx", i, hdr->iis[i].name, hdr->iis[i].mac);
		PRINT_IMPORTANT("iis[%d]: name='%s', mac='%s'", i, hdr->iis[i].name, hdr->iis[i].mac);
	}

	uint8_t *dev = hdr->iis[0].name; //TODO remove/fix!
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

	/** Setup the Injection Interface */
	shared->inject_handle = pcap_open_live((char *) dev, BUFSIZ, 0, -1, errbuf);
	if (shared->inject_handle == NULL) {
		PRINT_ERROR("Couldn't open device: dev='%s', err='%s', errno=%u, str='%s'", dev, errbuf, errno, strerror(errno));
		close_pipes(shared);
		return;
	}

	char filter_exp[MAX_FILTER_LEN];
	memset(filter_exp, 0, MAX_FILTER_LEN);
	char *pt = filter_exp;

	int total = 0;

	int ret;
	uint8_t mac_str[MAC_STR_LEN];
	for (i = 0; i < hdr->ii_num && total < MAX_FILTER_LEN; i++) {
		/*
		 ret = sprintf((char *) mac_str, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx", (hdr->iis[i].mac & (0x0000FF0000000000ull)) >> 40,
		 (hdr->iis[i].mac & (0x000000FF00000000ull)) >> 32, (hdr->iis[i].mac & (0x00000000FF000000ull)) >> 24,
		 (hdr->iis[i].mac & (0x0000000000FF0000ull)) >> 16, (hdr->iis[i].mac & (0x000000000000FF00ull)) >> 8,
		 (hdr->iis[i].mac & (0x00000000000000FFull)));
		 */
		ret = sprintf((char *) mac_str, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", hdr->iis[i].mac[0], hdr->iis[i].mac[1], hdr->iis[i].mac[2], hdr->iis[i].mac[3],
				hdr->iis[i].mac[4], hdr->iis[i].mac[5], hdr->iis[i].mac[6], hdr->iis[i].mac[7], hdr->iis[i].mac[8], hdr->iis[i].mac[9], hdr->iis[i].mac[10],
				hdr->iis[i].mac[11]);

		if (i == 0) {
			ret = sprintf(pt, "(ether dst %s) or (ether broadcast and (not ether src %s))", mac_str, mac_str);
		} else {
			ret = sprintf(pt, " or (ether dst %s) or (ether broadcast and (not ether src %s))", mac_str, mac_str);
		}
		if (ret > 0) {
			total += ret;
			pt += ret;
		}
	}

	if (total > MAX_FILTER_LEN) {
		PRINT_ERROR("todo error");
		close_handles(shared);
		close_pipes(shared);
		return;
	}

	//uint8_t *dev = hdr->iis[0].name; //TODO Fix/replace this!
	//char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	bpf_u_int32 net; /* ip */
	bpf_u_int32 mask; /* subnet mask */

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet((char *) dev, &net, &mask, errbuf) == -1) {
		PRINT_WARN("Couldn't get netmask for device '%s': '%s'", dev, errbuf);
		net = 0;
		mask = 0;
		//THIS failing seems to always cause an error
	}
	/* print capture info */
	PRINT_IMPORTANT("Device='%s'", dev);
	PRINT_IMPORTANT("Filter expression='%s'", filter_exp);

	/* open capture device */
	shared->capture_handle = pcap_open_live((char *) dev, SNAP_LEN, 0, 1000, errbuf);
	if (shared->capture_handle == NULL) {
		PRINT_ERROR("Couldn't open device: dev='%s', err='%s', errno=%u, str='%s'", dev, errbuf, errno, strerror(errno));
		close_handles(shared);
		close_pipes(shared);
		return;
	}
	PRINT_IMPORTANT("capture_handle=%p", shared->capture_handle);

	/* make sure we're capturing on an Ethernet device [2] */
	int data_linkValue = pcap_datalink(shared->capture_handle);
	if (data_linkValue != DLT_EN10MB) {
		PRINT_ERROR("'%s' is not an Ethernet", dev);
		close_handles(shared);
		close_pipes(shared);
		return;
	}
	PRINT_IMPORTANT("Datalink layer Description: '%s' (%d) ", pcap_datalink_val_to_description(data_linkValue), data_linkValue);

	/* compile the filter expression */

	struct bpf_program fp; /* compiled filter program (expression) */
	if (pcap_compile(shared->capture_handle, &fp, filter_exp, 0, net) == -1) {
		PRINT_ERROR("Couldn't parse filter '%s': '%s'", filter_exp, pcap_geterr(shared->capture_handle));
		close_handles(shared);
		close_pipes(shared);
		return;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(shared->capture_handle, &fp) == -1) {
		PRINT_ERROR("Couldn't install filter '%s': '%s'", filter_exp, pcap_geterr(shared->capture_handle));
		close_handles(shared);
		close_pipes(shared);
		return;
	}

#ifndef BUILD_FOR_ANDROID
	int check_monitor_mode = pcap_can_set_rfmon(shared->capture_handle); //Not supported in Bionic
	if (check_monitor_mode) {
		PRINT_DEBUG(" Monitor mode can be set");
	} else if (check_monitor_mode == 0) {
		PRINT_DEBUG(" Monitor mode could not be set");
	}
#endif

	pid_t pID = 0;
	pID = fork();
	if (pID < 0) { // failed to fork
		PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
		exit(1);
	} else if (pID == 0) { // child
		prctl(PR_SET_PDEATHSIG, SIGHUP); //close when parent does

		pID = getpid();
		PRINT_DEBUG("capture: pID=%d", (int)pID);

		capture_init(hdr, shared);
		pcap_freecode(&fp);

		PRINT_IMPORTANT("******** Capture Process Closing ********");
		PRINT_IMPORTANT("Capture: pID=%d, capture_count=%llu", pID, shared->capture_count);
	} else { // parent
		PRINT_DEBUG("inject: pID=%d", (int)pID);
		inject_init(hdr, shared);

		PRINT_IMPORTANT("******** Inject Process Closing ********");
		PRINT_IMPORTANT("Inject: pID=%d, inject_count=%llu", pID, shared->inject_count);
	}
}

void capturer_main(void) {
	PRINT_IMPORTANT("Entered");

	print_app_banner();
	int ret;

	/*
	 PRINT_IMPORTANT("Gaining su status");
	 if ((ret = system("su"))) {
	 PRINT_ERROR("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	 }
	 */

	(void) signal(SIGINT, capturer_termination_handler);

	PRINT_IMPORTANT("Attempting to make " FINS_TMP_ROOT "");
	ret = mkdir(FINS_TMP_ROOT, ALLPERMS);
	if (ret != 0 && errno != EEXIST) {
		//PRINT_IMPORTANT(FINS_TMP_ROOT " already exists! Cleaning...");
		// if cannot create directory, assume it contains files and try to delete them
		PRINT_ERROR("mkdir tmp: tmp='%s', errno=%u, str='%s'", FINS_TMP_ROOT, errno, strerror(errno));
		exit(-1);
	}
	if (chmod(FINS_TMP_ROOT, ALLPERMS)) {
		PRINT_ERROR("chmod tmp: tmp='%s', errno=%u, str='%s'", FINS_TMP_ROOT, errno, strerror(errno));
		exit(-1);
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, INJECT_PATH);
	unlink(addr.sun_path);

	int server_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (server_fd < 0) {
		PRINT_ERROR("socket error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}
	if (fchmod(server_fd, ALLPERMS) < 0) {
		PRINT_ERROR("fchmod inject: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		exit(-1);
	}

	mode_t old_mask = umask(0);
	PRINT_IMPORTANT("binding to: addr='%s'", INJECT_PATH);
	if (bind(server_fd, (struct sockaddr *) &addr, size) < 0) {
		PRINT_ERROR("bind error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}
	umask(old_mask);

	if (listen(server_fd, 5) < 0) {
		PRINT_ERROR("listen error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}

	int inject_fd;
	while (1) {
		PRINT_IMPORTANT("Waiting for core connection...");
		inject_fd = accept(server_fd, (struct sockaddr *) &addr, (socklen_t *) &size);
		if (inject_fd < 0) {
			PRINT_ERROR("accept error: inject_fd=%d, errno=%u, str='%s'", inject_fd, errno, strerror(errno));
			continue;
		}
		PRINT_IMPORTANT("******** Core Process Connected ********");
		PRINT_IMPORTANT("accepted at: inject_fd=%d, addr='%s'", inject_fd, addr.sun_path);

		pid_t pID = 0;
		pID = fork();
		if (pID < 0) { // failed to fork
			PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
			exit(1);
		} else if (pID == 0) { // child -- new capturer pair
			//prctl(PR_SET_PDEATHSIG, SIGHUP);

			pID = getpid();
			PRINT_DEBUG("new capturer pair: pID=%d", (int)pID);

			processes_init(inject_fd);
			//exit(1);
			return;
		} else { // parent
			PRINT_DEBUG("accept process: pID=%d", (int)pID);
			//Continue accepting
		}
	}

	close(server_fd);
	PRINT_DEBUG("Unlinking inject='%s'", INJECT_PATH);
	unlink(INJECT_PATH);
	exit(0);
}

int main(int argc, char *argv[]) {
	capturer_main();
	return 0;
}
