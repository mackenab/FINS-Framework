/*
 * finsdebug.h
 *
 *
 */
#include <android/log.h>

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

#ifndef BUILD_FOR_ANDROID
#define DEBUG
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif

#endif

#ifdef BUILD_FOR_ANDROID
#warning "building in debugging for android"
#define DEBUG
#define ERROR

#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);
#define perror(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", format);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) __android_log_print(ANDROID_LOG_ERROR, "FINS", format);
#else
#define PRINT_ERROR(format, args...)
#endif

#endif /*BUILD_FOR_ANDROID*/

#endif /* FINSDEBUG_H_ */
