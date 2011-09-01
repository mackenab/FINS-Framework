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

#define META_TYPE_INT CONFIG_TYPE_INT
#define META_TYPE_STRING CONFIG_TYPE_STRING
#define META_TRUE CONFIG_TRUE
#define META_FALSE CONFIG_FALSE

typedef config_t metadata;
typedef config_setting_t metadata_element;

void addSettings(metadata *cfgptr);
void metadata_create(metadata *metadata);
void metadata_destroy(metadata *metadata);

int metadata_readFromElement(metadata *cfgptr, const char *target, void *value);

int metadata_writeToElement(metadata *cfgptr, char *target, void *value,
		int type);
int metadata_setElement(metadata_element *element, void *value);
metadata_element *metadata_addElement(metadata *cfgptr, char *elementName,
		int type);
int metadata_print(metadata *cfgptr);

#endif /* METADATA_H_ */
