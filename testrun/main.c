
#include "IP4.h"
#include "udp.h"

IP4addr my_ip_addr = IP4_ADR_P2N(172,31,165,252);
IP4addr my_mask = IP4_ADR_P2N(255, 255, 255, 0);
struct ip4_routing_table* routing_table;
struct ip4_stats stats;
struct udp_statistics udpStat;

int main(int argc, char *argv[]) {

	IP4_init(argc, argv);

	struct udp_metadata_parsed meta;
	struct finsFrame* pff;
	struct finsFrame ff;

	unsigned char str[] = "00000000ALEX";

	ff.dataFrame.pdu = &str[0];

	meta.u_IPdst = IP4_ADR_P2N(171,2,14,100);
	meta.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
	meta.u_destPort = 13;
	meta.u_srcPort = 1087;

	ff.dataFrame.pduLength = 4;
	ff.dataOrCtrl = DATA;
	ff.destinationID = UDPID;
	ff.dataFrame.directionFlag = DOWN;

	memcpy(&ff.dataFrame.metaData, &meta, 16);
	udp_out(&ff);
	return EXIT_SUCCESS;
}
