/**
 * @file metadata.c
 *
 *  @date Aug 2, 2010
 *  @version 1 Basic functionality has been tested
 *  @version 2 "September 20,2010" Clearing the code and adding extra
 *  documentation per each function
 *  @author Abdallah Abdallah
 */

#include "metadata.h"
#include <stdint.h>

/** @example <USEmetadata>
 * int main(int argc, char **argv)
 {


 metadata cfg, *cfgptr;
 metadata_element *ethernet, *network;

 int l=45454;
 char *lolo;
 lolo = (char *)malloc(10);
 strcpy(lolo,"lolo");

 cfgptr=&cfg;
 metadata_create(cfgptr);
 //cfgptr = metadata_create2();


 ethernet = metadata_add(cfgptr,"ethernet",META_TYPE_INT32);
 network = metadata_add(cfgptr, "network", META_TYPE_STRING);

 metadata_write(cfgptr,"ethernet",&l,META_TYPE_INT32);
 metadata_set_element(network,lolo);

 metadata_write(cfgptr,"transport",lolo, META_TYPE_STRING);

 metadata_print(cfgptr);

 metadata_destroy(cfgptr);
 return 1;
 }

 */

void metadata_create(metadata *mptr) {

	PRINT_DEBUG("Entered: meta=%p", mptr);
	config_init(mptr);

}

void metadata_destroy(metadata *metadata) {
	PRINT_DEBUG("Entered: meta=%p", metadata);

	if (metadata) {
		config_destroy(metadata);
		free(metadata);
	}
}

/** @function read the value of a metaData element
 * returns the reading status FALSE/ TRUE
 */

int metadata_readFromElement(metadata *cfgptr, const char *target, void *value) {

	metadata_element *root, *handle;
	int status;

	root = config_root_setting(cfgptr);
	handle = config_setting_get_member(root, target);
	if (handle == NULL) {
		//PRINT_DEBUG("%s is not found in the metadata", target);
		status = META_FALSE;
		PRINT_DEBUG("meta=%p, '%s', %d", cfgptr, target, status);

	} else {
		switch (config_setting_type(handle)) {
		case META_TYPE_INT32:
			status = config_setting_lookup_int(root, target, (int *) value);
			break;
		case META_TYPE_INT64:
			status = config_setting_lookup_int64(root, target, (int64_t *) value);
			break;
		case META_TYPE_STRING:
			status = config_setting_lookup_string(root, target, (const char **) value); //unsure of credibility, check strings?
			break;
		default:
			PRINT_ERROR(" Asking for wrong type ");
			status = META_FALSE;
			break;

		}
		PRINT_DEBUG("meta=%p, '%s', %d", cfgptr, target, status);
	}

	return (status);

}

/** @function set a value of metadata element that might exist or not exist
 * if it does not exist, it creates the element and set its value
 * if it already exists , it sets its value only
 */
int metadata_writeToElement(metadata *cfgptr, char *target, void *value, int type) {

	int status;
	metadata_element *root, *handle;
	root = config_root_setting(cfgptr);

	switch (type) {
	case META_TYPE_INT32:
		handle = config_setting_get_member(root, target);
		if (handle == NULL)
			handle = config_setting_add(root, target, CONFIG_TYPE_INT);
		status = config_setting_set_int(handle, *(int *) value);
		break;

	case META_TYPE_INT64:
		handle = config_setting_get_member(root, target);
		if (handle == NULL)
			handle = config_setting_add(root, target, CONFIG_TYPE_INT64);
		status = config_setting_set_int64(handle, *(int64_t *) value);
		break;

	case META_TYPE_STRING:
		handle = config_setting_get_member(root, target);
		if (handle == NULL)
			handle = config_setting_add(root, target, CONFIG_TYPE_STRING);
		status = config_setting_set_string(handle, (char *) value);
		break;
	default:
		PRINT_ERROR(" wrong type to be written");
		printf("wrong type to be written to meta data!! ");
		status = META_FALSE;
		break;
	}

	PRINT_DEBUG("meta=%p, '%s', %d", cfgptr, target, status);
	return (status);
}

/** @function set the value of a MetaData element which is already
 * exist. If it is not found it returns an Error False Status
 */

int metadata_setElement(metadata_element *element, void *value) {

	int status;
	switch (config_setting_type(element)) {
	case META_TYPE_INT32:
		status = config_setting_set_int(element, *((int *) value));
		break;
	case META_TYPE_INT64:
		status = config_setting_set_int64(element, *((int64_t *) value));
		break;
	case META_TYPE_STRING:
		status = config_setting_set_string(element, (char *) value);
		break;
	default:
		PRINT_ERROR(" wrong type to be written");
		printf("wrong type to be written to meta data!! ");
		status = META_FALSE;
		break;

	}
	return (status);
}

/** @function add a new metadata element to a pre-existing metadata
 * structure but doesn't set any value for that element
 * it returns a pointer to that new added element
 */

metadata_element *metadata_addElement(metadata *cfgptr, char *elementName, int type) {
	metadata_element *root;
	root = config_root_setting(cfgptr);
	return (config_setting_add(root, elementName, type));

}

/** @function Print out the values of all the elements found in
 * that MetaData structure. It is using PRINT_DEBUG so it has to
 * should be defined
 * It returns the number of printed items
 */

int metadata_print(metadata *cfgptr) {

	metadata_element *root, *handle;
	int howManySettings;
	int i = 0;
	int type;
	int value;
	int64_t val64;
	char *stringValue;
	char *name;

	root = config_root_setting(cfgptr);
	howManySettings = config_setting_length(root);

	for (i = 0; i < howManySettings; i++) {

		handle = config_setting_get_elem(root, i);
		name = config_setting_name(handle);

		type = config_setting_type(handle);
		//PRINT_DEBUG("%s \\", name);
		switch (type) {
		case CONFIG_TYPE_INT:
			value = config_setting_get_int(handle);
			//PRINT_DEBUG("%d", value);
			PRINT_DEBUG("meta=%p, '%s'=%d", cfgptr, name, value);
			break;
		case CONFIG_TYPE_INT64:
			val64 = config_setting_get_int64(handle);
			//PRINT_DEBUG("%lld", val64);
			PRINT_DEBUG("meta=%p, '%s'=%lld", cfgptr, name, val64);
			break;
		case CONFIG_TYPE_STRING:
			stringValue = (char *) config_setting_get_string(handle);
			//PRINT_DEBUG("%s", stringValue);
			PRINT_DEBUG("meta=%p, '%s'='%s'", cfgptr, name, stringValue);
			break;
		default:
			PRINT_ERROR(" wrong type found");
			break;
		}
	}

	return (i);
}

int metadata_copy(metadata *cfgptr, metadata *cfgptr_copy) {
	PRINT_DEBUG("Entered: meta=%p, meta_copy=%p", cfgptr, cfgptr_copy);

	metadata_element *root = config_root_setting(cfgptr);
	metadata_element *root_copy = config_root_setting(cfgptr_copy);

	int num_settings = config_setting_length(root);
	int status;
	int total = 0;

	metadata_element *handle;
	metadata_element *handle_copy;
	char *target;

	int type;
	int value_int32;
	int64_t value_int64;
	char *value_string;

	int i;
	for (i = 0; i < num_settings; i++) {
		handle = config_setting_get_elem(root, i);
		target = config_setting_name(handle);

		type = config_setting_type(handle);
		switch (type) {
		case CONFIG_TYPE_INT:
			value_int32 = config_setting_get_int(handle);

			handle_copy = config_setting_get_member(root_copy, target);
			if (handle_copy == NULL)
				handle_copy = config_setting_add(root_copy, target, CONFIG_TYPE_INT);
			status = config_setting_set_int(handle_copy, value_int32);
			break;
		case CONFIG_TYPE_INT64:
			value_int64 = config_setting_get_int64(handle);

			handle_copy = config_setting_get_member(root_copy, target);
			if (handle_copy == NULL)
				handle_copy = config_setting_add(root_copy, target, CONFIG_TYPE_INT64);
			status = config_setting_set_int64(handle_copy, value_int64);
			break;
		case CONFIG_TYPE_STRING:
			value_string = (char *) config_setting_get_string(handle);

			handle_copy = config_setting_get_member(root_copy, target);
			if (handle_copy == NULL)
				handle_copy = config_setting_add(root_copy, target, CONFIG_TYPE_STRING);
			status = config_setting_set_string(handle_copy, value_string);
			break;
		default:
			PRINT_ERROR(" wrong type found, type=%d", type);
			status = META_FALSE;
			break;
		}
		PRINT_DEBUG("meta=%p, '%s', %d", cfgptr_copy, target, status);
		total += (status == CONFIG_TRUE);
	}

	return total == num_settings;
}

metadata *metadata_clone(metadata *cfgptr) {
	PRINT_DEBUG("Entered: meta=%p", cfgptr);

	metadata *cfgptr_clone = (metadata *) malloc(sizeof(metadata));
	if (cfgptr_clone == NULL) {
		PRINT_ERROR("failed to create matadata: meta=%p", cfgptr);
		exit(-1);
	}
	metadata_create(cfgptr_clone);

	metadata_copy(cfgptr, cfgptr_clone);

	return cfgptr_clone;
}

/*---------------------------------------------------------------
 * Functions code that might be reused later
 * */

/*
 void *metadata_read(metadata *cfgptr,char *target)
 {

 config_setting_t *root, *ethernet, *network, *transport,*socket,*handle;
 int howManySettings;
 int i=0;
 char *toBeParsed;
 int type;
 int value;
 char *stringValue;
 char *name;

 root=config_root_setting(cfgptr);
 howManySettings= config_setting_length(root);

 for (i=0; i< howManySettings; i++)
 {

 handle = config_setting_get_elem(root,i);
 name = config_setting_name(handle);
 if (strcmp(name,target)==0)
 {
 stringValue = config_setting_get_string(handle);
 PRINT_DEBUG("%s",stringValue);

 }
 type= config_setting_type(handle);
 PRINT_DEBUG("%s \\",name);
 switch (type)
 {
 case CONFIG_TYPE_INT:
 value = config_setting_get_int(handle);
 PRINT_DEBUG("%d",value);
 return(&value);
 case CONFIG_TYPE_STRING:
 stringValue = config_setting_get_string(handle);
 PRINT_DEBUG("%s",stringValue);
 return (stringValue);
 case CONFIG_TYPE_GROUP:
 PRINT_DEBUG("%s",handle->value);
 printf("Meta Data Type is group !! ");
 //exit();
 break;

 case CONFIG_TYPE_NONE:
 stringValue = config_setting_get_string(handle);
 PRINT_DEBUG("%s",stringValue);
 printf("Meta Data Type is NONE !! ");
 //exit();
 break;

 default:
 PRINT_DEBUG(" Default");
 printf("No Matching for Meta Data Type!! ");
 //exit();
 break;
 }


 }




 }

 */

