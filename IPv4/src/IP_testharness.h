
/**
 * @file IP_testharness.h
 *
 * @date Jun 14, 2010
 * @brief Testharness with both FCF and FDF
 * @author Abdallah Abdallah
 */


#ifndef IP_TESTHARNESS_H_
#define IP_TESTHARNESS_H_

#include "finstypes.h"

void InputQueue_Read (struct finsFrame *ff);
void IP_testharness_init(char *argv);
void IP_testharness_terminate();




#endif /* IP_TESTHARNESS_H_ */
