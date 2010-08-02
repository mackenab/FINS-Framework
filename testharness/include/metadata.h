/**
 * @file metadata.h
 *
 *  @date Aug 2, 2010
 *  @version 1
 *  @author Abdallah Abdallah
 */

#ifndef METADATA_H_
#define METADATA_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include "finsdebug.h"


#define META_TYPE_INT CONFIG_TYPE_INT
#define META_TYPE_STRING CONFIG_TYPE_STRING
typedef config_t metadata;
typedef config_setting_t metadata_element;



void addSettings(metadata *cfgptr);
void metadata_create();
metadata *metadata_create2();

void *metadata_read(metadata *cfgptr,char *target);
int metadata_read2(metadata *cfgptr,const char *target, void *value);

int metadata_write(metadata *cfgptr,char *target, void *value, int type);
int metadata_set_element(metadata_element *element, void *value);
metadata_element *metadata_add(metadata *cfgptr,char *elementName, int type);
int metadata_element_delete(metadata *cfgptr,char *elementName);

void metadata_print(metadata *cfgptr);


#endif /* METADATA_H_ */
