//#include <signal.h>
//#include <stddef.h>
//#include <sys/prctl.h>
//#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
//#include <ctype.h>
//#include <limits.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
//#include <sys/un.h>

#include <unistd.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define DEBUG
#define IMPORTANT
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) printf("IMPORTANT(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_ERROR(format, args...)
#endif

#include <sys/stat.h>
int main(int argc, char *argv[]) {
	PRINT_IMPORTANT("Entered");

	int ret;
	if ((ret = mkdir("/data/local/fins/test_mkdir", 0770))) {
		PRINT_ERROR("mkdir failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	}
	if ((ret = system("mkdir /data/local/fins/test_sys_mkdir"))) {
		PRINT_ERROR("sysmkdir failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	}
	if (0) {
		if ((ret = system("su -c mkdir /data/local/fins/test_su_mkdir"))) {
			PRINT_ERROR("SU mkdir failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}

	if (0) {
		PRINT_IMPORTANT("Gaining su status");
		if ((ret = system("su"))) {
			PRINT_ERROR("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}

	if (1) { //tests socket creation
		//char recv_data[4000];
		//while (1) {
		//gets(recv_data);
		//sleep(15);
		errno = 0;
		int fd1 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		PRINT_IMPORTANT("fd1=%d, errno=%u, str='%s'", fd1, errno, strerror(errno));
		int fd2 = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
		PRINT_IMPORTANT("fd2=%d, errno=%u, str='%s'", fd2, errno, strerror(errno));
		int fd3 = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
		PRINT_IMPORTANT("fd3=%d, errno=%u, str='%s'", fd3, errno, strerror(errno));
		int fd4 = socket(AF_UNIX, SOCK_STREAM, 0);
		PRINT_IMPORTANT("fd4=%d, errno=%u, str='%s'", fd4, errno, strerror(errno));
		int fd5 = socket(AF_INET, SOCK_DGRAM, 0);
		PRINT_IMPORTANT("fd5=%d, errno=%u, str='%s'", fd5, errno, strerror(errno));
		int fd6 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		PRINT_IMPORTANT("fd6=%d, errno=%u, str='%s'", fd6, errno, strerror(errno));
		int fd7 = socket(AF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
		PRINT_IMPORTANT("fd7=%d, errno=%u, str='%s'", fd7, errno, strerror(errno));
		int fd8 = socket(AF_INET, SOCK_STREAM, 0);
		PRINT_IMPORTANT("fd8=%d, errno=%u, str='%s'", fd8, errno, strerror(errno));
		int fd9 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		PRINT_IMPORTANT("fd9=%d, errno=%u, str='%s'", fd9, errno, strerror(errno));
		int fd10 = socket(AF_INET, SOCK_STREAM | O_NONBLOCK, IPPROTO_TCP);
		PRINT_IMPORTANT("fd10=%d, errno=%u, str='%s'", fd10, errno, strerror(errno));
		int fd11 = socket(AF_INET, SOCK_RAW, 0);
		PRINT_IMPORTANT("fd11=%d, errno=%u, str='%s'", fd11, errno, strerror(errno));
		int fd12 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		PRINT_IMPORTANT("fd12=%d, errno=%u, str='%s'", fd12, errno, strerror(errno));
		int fd13 = socket(AF_INET, SOCK_RAW | O_NONBLOCK, IPPROTO_ICMP);
		PRINT_IMPORTANT("fd13=%d, errno=%u, str='%s'", fd13, errno, strerror(errno));
		//}
	}

	if (0) { //test assembly instructions (replaced in glue.h)
		uint32_t test1 = 7;
		uint32_t test2 = 2;
		PRINT_IMPORTANT("test1=%d", test1/test2);
		test1 = 9;
		test2 = 3;
		PRINT_IMPORTANT("test2=%d", test1/test2);
		test1 = 4;
		test2 = 5;
		PRINT_IMPORTANT("test3=%d", test1/test2);

		int32_t test3 = 7;
		int32_t test4 = 2;
		PRINT_IMPORTANT("test4=%d", test3/test4);
		test3 = 9;
		test4 = 3;
		PRINT_IMPORTANT("test5=%d", test3/test4);
		test3 = 4;
		test4 = 5;
		PRINT_IMPORTANT("test6=%d", test3/test4);

		double test5 = 7;
		double test6 = 2;
		PRINT_IMPORTANT("test7=%f", test5/test6);
		test5 = 9;
		test6 = 3;
		PRINT_IMPORTANT("test8=%f", test5/test6);
		test5 = 4;
		test6 = 5;
		PRINT_IMPORTANT("test9=%f", test5/test6);
	}

	if (0) { //test interfaces
		int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		struct ifreq ifr;
		int num;
		for (num = 0; num < 20; num++) {
			ifr.ifr_ifindex = num;
			ret = ioctl(fd, SIOCGIFNAME, &ifr);
			PRINT_IMPORTANT("ifr_ifindex=%d, ifr_name='%s'", ifr.ifr_ifindex, ifr.ifr_name);
			//printf("ifr_ifindex=%d, ifr_name='%s'\n", ifr.ifr_ifindex, ifr.ifr_name);
		}

		close(fd);
		printf("FIN, waiting\n");
		while (1)
			;
		return 0;
	}
	return 1;
}
