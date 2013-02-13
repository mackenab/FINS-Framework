#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <sys/types.h>
#include <stdint.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <queueModule.h>

/** Ethernet Stub Variables  */
#ifdef BUILD_FOR_ANDROID
	//#define FINS_TMP_ROOT "/data/data/fins"
	#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
	#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define CAPTURE_PIPE FINS_TMP_ROOT "/fins_capture"
#define INJECT_PIPE FINS_TMP_ROOT "/fins_inject"


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define ETH_TYPE_IP4  0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IP6  0x86dd

#define ETH_FRAME_LEN_MAX 1538

/* Ethernet header */
struct sniff_ethernet {
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
	uint8_t data[1];
};

void interface_init(void);
void interface_run(pthread_attr_t *fins_pthread_attr);
void interface_shutdown(void);
void interface_release(void);

void interface_get_ff(void);
int interface_to_switch(struct finsFrame *ff); //Send a finsFrame to the switch's queue
//int interface_fcf_to_daemon(uint32_t status, uint32_t param_id, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, uint32_t ret_val);
//int interface_fdf_to_daemon(u_char *dataLocal, int len, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);

void interface_out_fdf(struct finsFrame *ff);
void interface_in_fdf(struct finsFrame *ff);
void interface_fcf(struct finsFrame *ff);
void interface_exec(struct finsFrame *ff);

#endif
