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
	 PRINT_IMPORTANT("Capture: capture count=%d", server_capture_count);
	 PRINT_IMPORTANT("Capture: inject count=%d", server_inject_count);

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
	shared->capture_fd = 0;

	pid_t pID = 0;
	pID = fork();
	if (pID < 0) { // failed to fork
		PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
		exit(1);
	} else if (pID == 0) { // child
		//prctl(PR_SET_PDEATHSIG, SIGHUP);

		pID = getpid();
		PRINT_DEBUG("capture: pID=%d", (int)pID);

		capture_init(hdr, shared);

		PRINT_IMPORTANT("******** Capture Process Closing ********");
		PRINT_IMPORTANT("Capture: pID=%d, capture_count=%d", pID, shared->capture_count);
	} else { // parent
		PRINT_DEBUG("inject: pID=%d", (int)pID);
		inject_init(hdr, shared);

		PRINT_IMPORTANT("******** Inject Process Closing ********");
		PRINT_IMPORTANT("Inject: pID=%d, inject_count=%d", pID, shared->inject_count);
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

	int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
