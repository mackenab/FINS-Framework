/**
 * @file metadata.h
 *
 * @date Aug 2, 2010
 * @version 1
 * @author Abdallah Abdallah
 */

#ifndef METADATA_H_
#define METADATA_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include "finsdebug.h"

/* over riding the original types of the Config library */

#define META_TYPE_INT32 	CONFIG_TYPE_INT
#define META_TYPE_INT64 	CONFIG_TYPE_INT64
#define META_TYPE_STRING 	CONFIG_TYPE_STRING
#define META_TRUE 			CONFIG_TRUE
#define META_FALSE 			CONFIG_FALSE

typedef config_t metadata;
typedef config_setting_t metadata_element;

void addSettings(metadata *params);
void metadata_create(metadata *params);

void metadata_destroy(metadata *params);

int metadata_readFromElement(metadata *params, const char *target, void *value);

int metadata_writeToElement(metadata *params, char *target, void *value, int type);
int metadata_setElement(metadata_element *element, void *value);
metadata_element *metadata_addElement(metadata *params, char *elementName, int type);
int metadata_print(metadata *params);

int metadata_copy(metadata *params, metadata *params_copy);
metadata *metadata_clone(metadata *params);

#endif /* METADATA_H_ */
