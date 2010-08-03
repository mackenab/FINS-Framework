/**
 * @file metadata.c
 *
 *  @date Aug 2, 2010
 *  @version 1
 *  @author Abdallah Abdallah
 */



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
int metadata_copy(metadata *dest,metadata *src);
int metadata_size(metadata *cfgptr);





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


	   ethernet = metadata_add(cfgptr,"ethernet",META_TYPE_INT);
	   network = metadata_add(cfgptr, "network", META_TYPE_STRING);

	  metadata_write(cfgptr,"ethernet",&l,META_TYPE_INT);
		metadata_set_element(network,lolo);

	     metadata_write(cfgptr,"transport",lolo, META_TYPE_STRING);

	     metadata_print(cfgptr);

	  config_destroy(cfgptr);

}

*/
void metadata_create(metadata *metadata)
{

config_init(metadata);

}


void metadata_destroy(metadata *metadata)
{

config_destroy(metadata);


}
/*
void *metadata_read(metadata *cfgptr,char *target)
{

	config_setting_t *root,*handle;
	int howManySettings;
	int i=0;

	int type;
	int value;
	const char *stringValue;
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
		PRINT_DEBUG("\n%s \\",name);
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
				PRINT_DEBUG(" Default\n");
				printf("No Matching for Meta Data Type!! ");
				//exit();
				break;
			}


	}




}
*/
int metadata_read2(metadata *cfgptr,const char *target, void *value)
{


config_setting_t *root,*handle;
int status;
char *stringAddress;
stringAddress= (char *)value;

root=config_root_setting(cfgptr);
handle = config_setting_get_member(root,target);
if (handle == NULL)
	{
	PRINT_DEBUG("%s is not found in the metadata", target);
	status = CONFIG_FALSE;

	}
else
	{
	switch (config_setting_type(handle))
			{
			case CONFIG_TYPE_INT:
				status = config_setting_lookup_int(root,target,(int *)value);
				break;
			case CONFIG_TYPE_STRING:
				status = config_setting_lookup_string(root,target,(char **)value);
				break;
			default:
					PRINT_DEBUG(" wrong type to be read\n");
					printf("wrong type to be read from meta data!! ");
					status = CONFIG_FALSE;
					break;

			}
	}


return (status);


}

/** @function set a value of metadata element that might exist or not exist
 * if it does not exist, it creates the element and set its value
 * if it already exists , it sets its value only
 */
int metadata_write(metadata *cfgptr,char *target, void *value, int type)
{


int status;
metadata_element *root, *handle;
root = config_root_setting(cfgptr);

switch (type)
			{
			case CONFIG_TYPE_INT:
				handle =config_setting_get_member(root, target);
				if (handle == NULL )
				handle = config_setting_add(root,target,CONFIG_TYPE_INT);
				status = config_setting_set_int(handle,*(int *)value);
				PRINT_DEBUG("%d",status);
				break;

			case CONFIG_TYPE_STRING:
				handle =config_setting_get_member(root, target);
				if (handle == NULL )
				handle = config_setting_add(root,target,CONFIG_TYPE_STRING);
				status = config_setting_set_string(handle,(char *)value);
				PRINT_DEBUG("%d",status);
				break;
			default:
				PRINT_DEBUG(" wrong type to be written\n");
				printf("wrong type to be written to meta data!! ");
				status = CONFIG_FALSE;
				break;
			}



return (status);





}


int metadata_set_element(metadata_element *element, void *value)
{

int status;
switch (config_setting_type(element) )
{
	case META_TYPE_INT:
				status = config_setting_set_int(element, *((int *)value));
				break;
	case META_TYPE_STRING:
				status = config_setting_set_string(element,(char *)value);
				break;
	default :
				PRINT_DEBUG(" wrong type to be written\n");
				printf("wrong type to be written to meta data!! ");
				status = CONFIG_FALSE;
				break;


}
return (status);
}

metadata_element *metadata_add(metadata *cfgptr,char *elementName, int type)
{
metadata_element *root;
root= config_root_setting(cfgptr);
return (config_setting_add(root,elementName, type));

}


int metadata_element_delete(metadata *cfgptr,char *elementName)
{
metadata_element *root;
root= config_root_setting(cfgptr);
return (config_setting_remove(root, elementName));

}



void metadata_print(metadata *cfgptr)
{

	metadata_element *root,*handle;
	int howManySettings;
	int i=0;
	int type;
	int value;
	const char *stringValue;
	char *name;


	root=config_root_setting(cfgptr);
	howManySettings= config_setting_length(root);


	for (i=0; i< howManySettings; i++)
	{

		handle = config_setting_get_elem(root,i);
		name = config_setting_name(handle);

		type= config_setting_type(handle);
		PRINT_DEBUG("\n%s \\",name);
			switch (type)
			{
			case CONFIG_TYPE_INT:
				value = config_setting_get_int(handle);
				PRINT_DEBUG("%d",value);
				break;
			case CONFIG_TYPE_STRING:
				stringValue = config_setting_get_string(handle);
				PRINT_DEBUG("%s",stringValue);
				break;

		default :
				PRINT_DEBUG(" wrong type to be written\n");
				printf("wrong type to be written to meta data!! ");
				break;
			}


	}


return;
}
/** @function <metadata_copy> returns the number of copied element */
int metadata_copy(metadata *dest,metadata *src)
{

	metadata_element *rootDest,*rootSrc;
	metadata_element *handleDest,*handleSrc;
	int howManySettings;
	int count=0;
	int type;
	int value;
	const char *stringValue;
	char *name;
	int i;

	rootSrc=config_root_setting(src);
	rootDest=config_root_setting(dest);

	howManySettings= config_setting_length(rootSrc);

	for (i=0; i< howManySettings; i++)
	{
		count ++;
		handleSrc = config_setting_get_elem(rootSrc,i);
		name = config_setting_name(handleSrc);

		type= config_setting_type(handleSrc);

			switch (type)
			{
			case CONFIG_TYPE_INT:
				value = config_setting_get_int(handleSrc);
			//	PRINT_DEBUG("%d",value);
				handleDest = config_setting_add(rootDest,name,CONFIG_TYPE_INT);
				config_setting_set_int(handleDest, value);
				break;

			case CONFIG_TYPE_STRING:
				stringValue = config_setting_get_string(handleSrc);
			//	PRINT_DEBUG("%s",stringValue);
				handleDest = config_setting_add(rootDest,name,CONFIG_TYPE_STRING);
				config_setting_set_string(handleDest, stringValue);
				break;

		default :
				PRINT_DEBUG(" wrong type to be copied\n");
				printf("wrong type to be copied to meta data!! ");
				count=0;
				return(count);
			}


	}


return(count);
}



int metadata_size(metadata *cfgptr)
{


metadata_element *root;
root= config_root_setting(cfgptr);



return (1);
}
