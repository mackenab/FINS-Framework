/**
 * @file metadata.h
 *
 * @date Aug 2, 2010
 * @version 1
 * @author Abdallah Abdallah
 */

#ifndef METADATA_H_
#define METADATA_H_

#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "finsdebug.h"

/* over riding the original types of the Config library */

#define META_TYPE_GROUP 	CONFIG_TYPE_GROUP
#define META_TYPE_INT32 	CONFIG_TYPE_INT
#define META_TYPE_INT64 	CONFIG_TYPE_INT64
#define META_TYPE_FLOAT 	CONFIG_TYPE_FLOAT
#define META_TYPE_STRING 	CONFIG_TYPE_STRING
#define META_TRUE 			CONFIG_TRUE
#define META_FALSE 			CONFIG_FALSE

typedef config_t metadata;
typedef config_setting_t metadata_element;

void addSettings(metadata *meta);
void metadata_create(metadata *meta);

void metadata_destroy(metadata *meta);

int metadata_readFromElement(metadata *meta, const char *target, void *value);

int metadata_writeToElement(metadata *meta, char *target, void *value, int type);
int metadata_setElement(metadata_element *element, void *value);
metadata_element *metadata_addElement(metadata *meta, char *elementName, int type);
int metadata_print(metadata *meta);

int metadata_copy(metadata *meta, metadata *meta_copy);
metadata *metadata_clone(metadata *meta);

//tags need to start with letter
#define secure_config_setting_add(root, name, type) secure_config_setting_add_macro(__FILE__, __FUNCTION__, __LINE__, root, name, type)
metadata_element *secure_config_setting_add_macro(const char *file, const char *func, int line, metadata_element *root, char *name, int type);

#define PARAM_ID "info___id"
#define PARAM_TYPE "info___type"
void elem_add_param(metadata_element *elem, char *param_str, int param_id, int param_type);

#endif /* METADATA_H_ */
