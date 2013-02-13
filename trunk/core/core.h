/*
 * @file socketgeni.h
 *
 *  @date Nov 26, 2010
 *      @author Abdallah Abdallah
 */

#ifndef CORE_H_
#define CORE_H_

int read_configurations();
//void commChannel_init();

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

void core_main();

#endif /* CORE_H_ */

