/*
 * @file socketgeni.h
 *
 *  @date Nov 26, 2010
 *      @author Abdallah Abdallah
 */

#ifndef CORE_H_
#define CORE_H_

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

//#include <stdint.h>

//uint8_t my_host_if_name[IFNAMSIZ];
//uint8_t my_host_if_num;
//uint64_t my_host_mac_addr;
//uint32_t my_host_ip_addr;
//uint32_t my_host_mask;
//uint32_t loopback_ip_addr;
//uint32_t loopback_mask;
//uint32_t any_ip_addr;

void core_dummy(void);
void core_main(void);

#endif /* CORE_H_ */

