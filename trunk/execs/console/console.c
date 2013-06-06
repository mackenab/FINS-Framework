/*
 * console.h
 *
 *  Created on: Apr 19, 2013
 *      Author: Jonathan Reed
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

//#include <netdb.h>

#include <finsdebug.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

//TODO these definitions need to be gathered
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/local/fins"
//#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_PATH FINS_TMP_ROOT "/fins_rtm"
#define MAX_CMD_LEN 500
#define MAX_REPLY_LEN 1000

int get_line(char *line, int *max_size) {
	if (*max_size <= 0) {
		return -1;
	}

	if (line == NULL) {
		return -1;
	}
	char *pt = line;

	int c;
	size_t len = 0;

	for (;;) {
		c = fgetc(stdin);
		if (c == EOF) {
			break;
		}

		if (c == '\n') {
			break;
		}
		*pt = c;
		pt++;

		len++;
		if (len == *max_size) {
			printf("\ntodo error");
			return -1;
		}
	}

	*pt = '\0';
	return len;
}

int main() {
	PRINT_IMPORTANT("Entered");

	///*
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, RTM_PATH);

	int console_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (console_fd < 0) {
		PRINT_ERROR("socket error: console_fd=%d, errno=%u, str='%s'", console_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_IMPORTANT("connecting to: addr='%s'", RTM_PATH);
	if (connect(console_fd, (struct sockaddr *) &addr, size) != 0) {
		PRINT_ERROR("connect error: console_fd=%d, errno=%u, str='%s'", console_fd, errno, strerror(errno));
		return 0;
	}
	PRINT_IMPORTANT("connected at: console_fd=%d, addr='%s'", console_fd, addr.sun_path);
	//*/

	//TODO fork for recv process that or do nonblocking read on STDIN
	int buf_size = MAX_CMD_LEN;
	int cmd_len;
	char cmd_buf[MAX_REPLY_LEN + 1];
	int numBytes;

	PRINT_IMPORTANT("Enter 'quit' or 'q' to exit console.");
	while (1) {
		printf("\n(FINS) ");
		fflush(stdout);

		cmd_len = get_line(cmd_buf, &buf_size);
		//printf("\tcmd: len=%d, str='%s'", cmd_len, cmd_buf);
		//fflush(stdout);

		if (cmd_len > 0) {
			if ((strcmp(cmd_buf, "quit") == 0) || strcmp(cmd_buf, "q") == 0) {
				break;
				//} else if ((strcmp(cmd_buf, "help") == 0) || strcmp(cmd_buf, "?") == 0) { printf("todo!!!");
			} else {
				//##### write
				numBytes = write(console_fd, &cmd_len, sizeof(int));
				if (numBytes <= 0) {
					PRINT_ERROR("\nerror write len: numBytes=%d", numBytes);
					return 0;
				}

				numBytes = write(console_fd, cmd_buf, cmd_len);
				if (numBytes <= 0) {
					PRINT_ERROR("\nerror write buf: numBytes=%d", numBytes);
					return 0;
				}

				if (1) {
					//##### read
					numBytes = read(console_fd, &cmd_len, sizeof(int));
					if (numBytes <= 0) {
						PRINT_ERROR("\nerror read len: numBytes=%d", numBytes);
						return 0;
					}

					numBytes = read(console_fd, cmd_buf, cmd_len);
					if (numBytes <= 0) {
						PRINT_ERROR("\nerror read buf: numBytes=%d", numBytes);
						return 0;
					}

					if (cmd_len != numBytes) {
						PRINT_ERROR("\nwrite len different: cmd_len=%d, numBytes=%d", cmd_len, numBytes);
						exit(-1);
					}
					cmd_buf[cmd_len] = '\0';
					//printf("\n\trecv: len=%u, buf='%s'", cmd_len, cmd_buf); //TODO remove
					printf("%s", cmd_buf);
				}
			}
		} else if (cmd_len < 0) {
			sleep(1);
		}
	}

	return 0;
}
