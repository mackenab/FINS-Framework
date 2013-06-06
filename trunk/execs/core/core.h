/*
 * @file socketgeni.h
 *
 *  @date Nov 26, 2010
 *      @author Abdallah Abdallah
 */

#ifndef CORE_H_
#define CORE_H_

//TODO these definitions need to be gathered
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/local/fins"
//#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

//#include <stdint.h>

#define FILE_NAME_SIZE 100
#define DEFAULT_ENVI_FILE "envi.cfg"
#define DEFAULT_STACK_FILE "stack.cfg"
#define DEFAULT_CORE_FILE "output_core.txt"
#define DEFAULT_CAPTURER_FILE "output_capturer.txt"

void core_dummy(void);
void core_main(uint8_t *envi_name, uint8_t *stack_name);

#endif /* CORE_H_ */

