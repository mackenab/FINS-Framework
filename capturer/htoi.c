/*
 * htoi.c
 *
 *  Created on: Jun 9, 2010
 *      Author: Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

unsigned char htoi(char s[]) {
	/** val modified from unsigned int to unsgined char
	 * at August 4,2010
	 */
	unsigned char val = 0;
	int x = 0;

	if (s[x] == '0' && (s[x + 1] == 'x' || s[x + 1] == 'X'))
		x += 2;

	while (s[x] != '\0') {
		if (val > UINT_MAX)
			return 0;
		else if (s[x] >= '0' && s[x] <= '9') {
			val = val * 16 + s[x] - '0';
		} else if (s[x] >= 'A' && s[x] <= 'F') {
			val = val * 16 + s[x] - 'A' + 10;
		} else if (s[x] >= 'a' && s[x] <= 'f') {
			val = val * 16 + s[x] - 'a' + 10;
		} else
			return 0;

		x++;
	}
	return val;
}
