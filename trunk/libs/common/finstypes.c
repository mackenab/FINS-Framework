/*
 * finstypes.c
 *
 *  Created on: Jul 21, 2011
 *      Author: dell-kevin
 */

#include "finstypes.h"

uint32_t global_control_serial_num = 0;
sem_t global_control_serial_sem;

void *secure_malloc_full(const char *file, const char *func, int line, uint32_t len) {
	void *buf = malloc(len);
	if (buf == NULL) {
#ifdef ERROR
#ifdef BUILD_FOR_ANDROID
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):malloc: len=%u\n", file, func, line, len);
#else
		//printf("\033[01;31mERROR(%s, %s, %d):malloc: len=%u\n\033[01;37m", file, func, line, len);fflush(stdout);
		gettimeofday(&global_print_tv, NULL);
		printf("\033[01;31m%u.%06u:ERROR(%s, %s, %d):malloc: len=%u\n\033[01;37m", (uint32_t) global_print_tv.tv_sec, (uint32_t) global_print_tv.tv_usec, file,
				func, line, len);
		fflush(stdout);
#endif
#endif
		exit(-1);
	}
	memset(buf, 0, len); //needed to prevent problems from uncleared data
	return buf;
}

void secure_sem_wait_full(const char *file, const char *func, int line, sem_t *sem) {
	while (1) {
		if (sem_wait(sem)) {
			if (errno != EINTR) {
#ifdef ERROR
#ifdef BUILD_FOR_ANDROID
				__android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):sem_wait prob: sem=%p\n", file, func, line, sem);
#else
				//printf("\033[01;31mERROR(%s, %s, %d):sem_wait prob: sem=%p\n\033[01;37m", file, func, line, sem);fflush(stdout);
				gettimeofday(&global_print_tv, NULL);
				printf("\033[01;31m%u.%06u:ERROR(%s, %s, %d):sem_wait prob: sem=%p\n\033[01;37m", (uint32_t) global_print_tv.tv_sec,
						(uint32_t) global_print_tv.tv_usec, file, func, line, sem);
				fflush(stdout);
#endif
#endif
				exit(-1);
			}
		} else {
			break;
		}
	}
}

void secure_metadata_readFromElement_full(const char *file, const char *func, int line, metadata *meta, const char *target, void *value) {
	if (metadata_readFromElement(meta, target, value) == META_FALSE) {
#ifdef ERROR
#ifdef BUILD_FOR_ANDROID
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):meta read: meta=%p, target='%s', value=%p\n", file, func, line, meta, target, value);
#else
		//printf("\033[01;31mERROR(%s, %s, %d):meta read: meta=%p, target='%s', value=%p\n\033[01;37m", file, func, line, meta, target, value);fflush(stdout);
		gettimeofday(&global_print_tv, NULL);
		printf("\033[01;31m%u.%06u:ERROR(%s, %s, %d):meta read: meta=%p, target='%s', value=%p\n\033[01;37m", (uint32_t) global_print_tv.tv_sec,
				(uint32_t) global_print_tv.tv_usec, file, func, line, meta, target, value);
		fflush(stdout);
#endif
#endif
		exit(-1);
	}
}

void secure_metadata_writeToElement_full(const char *file, const char *func, int line, metadata *meta, char *target, void *value, int type) {
	if (metadata_writeToElement(meta, target, value, type) == META_FALSE) {
#ifdef ERROR
#ifdef BUILD_FOR_ANDROID
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):meta write: meta=%p, target='%s', value=%p, type=%d\n", file, func, line, meta, target, value, type);
#else
		//printf("\033[01;31mERROR(%s, %s, %d):meta write: meta=%p, target='%s', value=%p, type=%d\n\033[01;37m", file, func, line, meta, target, value, type);fflush(stdout);
		gettimeofday(&global_print_tv, NULL);
		printf("\033[01;31m%u.%06u:ERROR(%s, %s, %d):meta write: meta=%p, target='%s', value=%p, type=%d\n\033[01;37m", (uint32_t) global_print_tv.tv_sec,
				(uint32_t) global_print_tv.tv_usec, file, func, line, meta, target, value, type);
		fflush(stdout);
#endif
#endif
		exit(-1);
	}
}

void secure_pthread_create_full(const char *file, const char *func, int line, pthread_t *thread, pthread_attr_t *attr, void *(*routine)(void *), void *arg) {
	if (pthread_create(thread, attr, routine, arg)) {
#ifdef ERROR
#ifdef BUILD_FOR_ANDROID
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):pthread_create: thread=%p, attr=%p, routine=%p, arg=%p\n", file, func, line, thread, attr, routine, arg);
#else
		//printf("\033[01;31mERROR(%s, %s, %d):pthread_create: thread=%p, attr=%p, routine=%p, arg=%p\n\033[01;37m", file, func, line, thread, attr, routine, arg);fflush(stdout);
		gettimeofday(&global_print_tv, NULL);
		printf("\033[01;31m%u.%06u:ERROR(%s, %s, %d):pthread_create: thread=%p, attr=%p, routine=%p, arg=%p\n\033[01;37m", (uint32_t) global_print_tv.tv_sec,
				(uint32_t) global_print_tv.tv_usec, file, func, line, thread, attr, routine, arg);
		fflush(stdout);
#endif
#endif
		exit(-1);
	}
}

void uint32_increase(uint32_t *data, uint32_t value, uint32_t max) { //assumes *data,value < max
	if (*data + value < *data || max < *data + value) {
		*data = max;
	} else {
		*data += value;
	}
}

void uint32_decrease(uint32_t *data, uint32_t value) {
	if (*data > value) {
		*data -= value;
	} else {
		*data = 0;
	}
}

//A test that always returns true
int true_test(uint8_t *data) {
	return LIST_TRUE;
}

//A test that always returns false
int false_test(uint8_t *data) {
	return LIST_FALSE;
}

void nop_func(uint8_t *data) {
}

//Return a malloc'd linked_list with 0 elements, & a maximum of <max>
struct linked_list *list_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct linked_list *list = (struct linked_list *) secure_malloc(sizeof(struct linked_list));
	list->max = max;
	list->len = 0;
	list->front = NULL;
	list->end = NULL;

	//list_check(list);
	PRINT_DEBUG("Exited: max=%u, list=%p", max, list);
	return list;
}

//Prepend the pointer to the front of the list
void list_prepend_full(struct linked_list *list, uint8_t *data) {
	PRINT_DEBUG("Entered: list=%p, data=%p", list, data);

	struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
	node->data = data;
	node->next = list->front;
	node->prev = NULL;

	if (list_is_empty(list)) {
		list->end = node;
	} else {
		list->front->prev = node;
	}
	list->front = node;
	list->len++;

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
}

//Append the pointer to the end of the list
void list_append_full(struct linked_list *list, uint8_t *data) {
	PRINT_DEBUG("Entered: list=%p, data=%p", list, data);

	struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
	node->data = data;
	node->next = NULL;

	if (list_is_empty(list)) {
		node->prev = NULL;
		list->front = node;
	} else {
		node->prev = list->end;
		list->end->next = node;
	}
	list->end = node;
	list->len++;

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
}

//Insert the pointer after the pointer given by <prev>
void list_insert_full(struct linked_list *list, uint8_t *data, uint8_t *prev) {
	PRINT_DEBUG("Entered: list=%p, data=%p", list, data);

	if (list_is_empty(list)) {
		//list_check(list);
		PRINT_ERROR("No prev node: list=%p, len=%u, prev=%p", list, list->len, prev);
		return;
	}

	if (list->end->data == data) {
		struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
		node->data = data;
		node->next = NULL;
		node->prev = list->end;

		list->end->next = node;
		list->end = node;
		list->len++;

		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
		return;
	}

	struct list_node *temp = list->front;
	while (temp) {
		if (temp->data == prev) {
			struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
			node->data = data;
			node->next = temp->next;
			node->prev = temp;

			temp->next->prev = node;
			temp->next = node;
			list->len++;

			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
			return;
		} else {
			temp = temp->next;
		}
	}

	//list_check(list);
	PRINT_ERROR("No prev node: list=%p, len=%u, prev=%p", list, list->len, prev);
}

//Iterate through the list to check that the total length matches the number of elements
int list_check(struct linked_list *list) { //TODO remove all references
	PRINT_DEBUG("Entered: list=%p, len=%u", list, list->len);

	int count = 0;

	PRINT_DEBUG("bounds: front=%p, end=%p", list->front, list->end);

	struct list_node *temp = list->front;
	struct list_node *prev = NULL;
	while (temp && count <= list->max) {
		count++;

		if (prev != temp->prev) {
			PRINT_WARN("todo error");
			return LIST_FALSE;
		}

		prev = temp;
		temp = temp->next;
	}

	if (count == list->len) {
		PRINT_DEBUG("Exited: list=%p, count=%u, check=%u", list, count, 1);
		return LIST_TRUE;
	} else {
		PRINT_ERROR("todo error: list=%p, max=%u, len=%u, count=%u, check=%u", list, list->max, list->len, count, count == list->len);
		temp = list->front;
		while (temp && count <= list->max) {
			PRINT_DEBUG("count=%d, node=%p", count, temp);
			count++;
			temp = temp->next;
		}
		PRINT_DEBUG("Exited: list=%p, count=%u, check=%u", list, count, 0);
		return LIST_FALSE;
	}
}

//Return the pointer at the <index> location in the list
uint8_t *list_look(struct linked_list *list, uint32_t index) {
	PRINT_DEBUG("Entered: list=%p, index=%u", list, index);

	uint32_t i = 0;
	struct list_node *comp = list->front;
	while (comp) {
		if (i == index) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, index=%u, data=%p", list, index, comp->data);
			return comp->data;
		} else {
			comp = comp->next;
			i++;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, index=%u, data=%p", list, index, NULL);
	return NULL;
}

//Return true if the list contains the pointer data
int list_contains_full(struct linked_list *list, uint8_t *data) {
	PRINT_DEBUG("Entered: list=%p, data=%p", list, data);

	if (list_is_empty(list)) {
		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, data=%p, 0", list, data);
		return LIST_FALSE;
	}

	struct list_node *node = list->front;
	while (node) {
		if (node->data == data) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, data=%p, 1", list, data);
			return LIST_TRUE;
		} else {
			node = node->next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p, 0", list, data);
	return LIST_FALSE;
}

//Remove the first element of the list & return it
uint8_t *list_remove_front(struct linked_list *list) {
	PRINT_DEBUG("Entered: list=%p", list);

	if (list_is_empty(list)) {
		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, data=%p", list, list->len, NULL);
		return NULL;
	} else {
		struct list_node *node = list->front;
		if (list->end == node) {
			list->front = NULL;
			list->end = NULL;
		} else {
			list->front = node->next;
			list->front->prev = NULL;
		}

		list->len--;
		uint8_t *data = node->data;
		PRINT_DEBUG("Freeing: node=%p", node);
		free(node);

		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, data=%p", list, list->len, data);
		return data;
	}
}

//Remove first instance of the specific pointer <data> from the list
void list_remove_full(struct linked_list *list, uint8_t *data) {
	PRINT_DEBUG("Entered: list=%p, data=%p", list, data);

	if (list_is_empty(list)) {
		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
		return;
	}

	struct list_node *node = list->front;
	while (node) {
		if (node->data == data) {
			if (list->front == node) {
				if (list->end == node) { //only 1 element
					list->front = NULL;
					list->end = NULL;
				} else {
					list->front = list->front->next;
					list->front->prev = NULL;
				}
			} else if (list->end == node) {
				list->end = node->prev;
				list->end->next = NULL;
			} else {
				node->next->prev = node->prev;
				node->prev->next = node->next;
			}
			list->len--;
			PRINT_DEBUG("Freeing: node=%p", node);
			free(node);

			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
			return;
		} else {
			node = node->next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, len=%u", list, list->len);
	return;
}

//Iterate through <list> and remove elements for which <equal> returns true, add those elements to a new list that is returned.
//<equal> should return:
//1 if equal
//0 if not
struct linked_list *list_remove_all_full(struct linked_list *list, int (*equal)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p", list, equal);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data)) {
			//remove from list
			if (list->front == comp) {
				if (list->end == comp) { //only 1 element
					list->front = NULL;
					list->end = NULL;
				} else {
					list->front = list->front->next;
					list->front->prev = NULL;
				}
			} else if (list->end == comp) {
				list->end = comp->prev;
				list->end->next = NULL;
			} else {
				comp->next->prev = comp->prev;
				comp->prev->next = comp->next;
			}
			list->len--;

			//append to list_ret
			comp->next = NULL;
			if (list_is_empty(list_ret)) {
				comp->prev = NULL;
				list_ret->front = comp;
			} else {
				comp->prev = list_ret->end;
				list_ret->end->next = comp;
			}
			list_ret->end = comp;
			list_ret->len++;
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, len=%u, ret=%p, len=%u", list, list->len, list_ret, list_ret->len);
	return list_ret;
}

//See list_remove_all()
struct linked_list *list_remove_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p", list, equal, param);

	struct linked_list *list_ret = list_create(list->max);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param)) {
			//remove from list
			if (list->front == comp) {
				if (list->end == comp) { //only 1 element
					list->front = NULL;
					list->end = NULL;
				} else {
					list->front = list->front->next;
					list->front->prev = NULL;
				}
			} else if (list->end == comp) {
				list->end = comp->prev;
				list->end->next = NULL;
			} else {
				comp->next->prev = comp->prev;
				comp->prev->next = comp->next;
			}
			list->len--;

			//append to list_ret
			comp->next = NULL;
			if (list_is_empty(list_ret)) {
				comp->prev = NULL;
				list_ret->front = comp;
			} else {
				comp->prev = list_ret->end;
				list_ret->end->next = comp;
			}
			list_ret->end = comp;
			list_ret->len++;
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, len=%u, ret=%p, len=%u", list, list->len, list_ret, list_ret->len);
	return list_ret;
}

//See list_remove_all()
struct linked_list *list_remove_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1,
		uint8_t *param2) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p", list, equal, param1, param2);

	struct linked_list *list_ret = list_create(list->max);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2)) {
			//remove from list
			if (list->front == comp) {
				if (list->end == comp) { //only 1 element
					list->front = NULL;
					list->end = NULL;
				} else {
					list->front = list->front->next;
					list->front->prev = NULL;
				}
			} else if (list->end == comp) {
				list->end = comp->prev;
				list->end->next = NULL;
			} else {
				comp->next->prev = comp->prev;
				comp->prev->next = comp->next;
			}
			list->len--;

			//append to list_ret
			comp->next = NULL;
			if (list_is_empty(list_ret)) {
				comp->prev = NULL;
				list_ret->front = comp;
			} else {
				comp->prev = list_ret->end;
				list_ret->end->next = comp;
			}
			list_ret->end = comp;
			list_ret->len++;
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, len=%u, ret=%p, len=%u", list, list->len, list_ret, list_ret->len);
	return list_ret;
}

//Return true if the list has no elements
int list_is_empty(struct linked_list *list) {
	return list->len == 0;
	//return list->len == NULL; //Use so can add 0 len nodes, signals/flags?
}

//Return true if the list has reached the limit of elements given by list->max
int list_is_full(struct linked_list *list) {
	return list->len == list->max;
}

//Return true if the list has space for another element
int list_has_space(struct linked_list *list) {
	return list->len < list->max;
}

//Return the number of elements the list can add before reaching max
uint32_t list_space(struct linked_list *list) {
	return list->max - list->len;
}

//Clone the list and return the new list
//<clone> should return a pointer to a copied version of an element, returning the same pointer is permissible but must be handled
struct linked_list *list_clone_full(struct linked_list *list, uint8_t *(*clone)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, clone=%p", list, clone);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		list_append(list_ret, clone(comp->data));
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, len=%u, ret=%p, len=%u", list, list->len, list_ret, list_ret->len);
	return list_ret;
}

//Remove & append as many elements of <list2> to <list1> up to its max, return true if all of <list2> appended to <list1>
int list_join(struct linked_list *list1, struct linked_list *list2) {
	PRINT_DEBUG("Entered: list1=%p, list2=%p", list1, list2);
	if (list_is_empty(list2)) {
		//list_check(list1);
		//list_check(list2);
		PRINT_DEBUG("Exited: list1=%p, list2=%p, %u", list1, list2, LIST_TRUE);
		return LIST_TRUE;
	} else {
		uint32_t space = list_space(list1);
		if (list2->len <= space) { //use space, prevents rollover
			if (list_is_empty(list1)) {
				list1->front = list2->front;
				list1->end = list2->end;
			} else {
				list1->end->next = list2->front;
				list2->front->prev = list1->end;
				list1->end = list2->end;
			}
			list2->front = NULL;
			list2->end = NULL;
			list1->len += list2->len;
			list2->len = 0;

			//list_check(list1);
			//list_check(list2);
			PRINT_DEBUG("Exited: list1=%p, list2=%p, %u", list1, list2, LIST_TRUE);
			return LIST_TRUE;
		} else if (space > 0) {
			uint32_t i = 0;
			struct list_node *comp = list2->front;
			while (comp) {
				if (i == space) {
					break;
				} else {
					comp = comp->next;
					i++;
				}
			}

			if (list_is_empty(list1)) {
				list1->front = list2->front;
			} else {
				list1->end->next = list2->front;
				list2->front->prev = list1->end;
			}
			list1->end = comp->prev;
			comp->prev->next = NULL;

			comp->prev = NULL;
			list2->front = comp;
			list2->len -= space;

			//list_check(list1);
			//list_check(list2);
			PRINT_DEBUG("Exited: list1=%p, list2=%p, %u", list1, list2, LIST_FALSE);
			return LIST_FALSE;
		} else {
			//list_check(list1);
			//list_check(list2);
			PRINT_DEBUG("Exited: list1=%p, list2=%p, %u", list1, list2, LIST_FALSE);
			return LIST_FALSE;
		}
	}
}

//Remove all elements of <list> after <index> & return rest as separate list
struct linked_list *list_split(struct linked_list *list, uint32_t index) {
	PRINT_DEBUG("Entered: list=%p, index=%u", list, index);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	if (index + 1 < list->len) {
		uint32_t i = 0;
		struct list_node *comp = list->front;
		while (comp) {
			if (i == index) {
				break;
			} else {
				comp = comp->next;
				i++;
			}
		}
		list_ret->front = comp->next;
		list_ret->end = list->end;
		list_ret->len = list->len - (index + 1);
		list_ret->front->prev = NULL;

		list->end = comp;
		comp->next = NULL;
		list->len = index + 1;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, len=%u, ret=%p, len=%u", list, list->len, list_ret, list_ret->len);
	return list_ret;
}

//Add the pointer <data> to the list, using the comparer, returns true if inserts, false if problem
//<comparer> should return:
//-1 = less than, goes before
//0 = problem don't insert
//1 = greater than, goes after, if is equal but want put in use this
int list_add_full(struct linked_list *list, uint8_t *data, int (*comparer)(uint8_t *data1, uint8_t *data2)) {
	PRINT_DEBUG("Entered: list=%p, len=%u, data=%p, comparer=%p", list, list->len, data, comparer);

	if (list_is_empty(list)) {
		struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
		node->data = data;
		node->next = NULL;
		node->prev = NULL;

		list->front = node;
		list->end = node;
		list->len++;

		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_TRUE);
		return LIST_TRUE;
	}

	int ret = comparer(data, list->front->data);
	if (ret == -1) { //before front
		struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
		node->data = data;
		node->next = list->front;
		node->prev = NULL;

		list->front->prev = node;
		list->front = node;
		list->len++;

		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_TRUE);
		return LIST_TRUE;
	} else if (ret == 0) {
		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_FALSE);
		return LIST_FALSE;
	}

	ret = comparer(data, list->end->data);
	if (ret == 1) { //after end
		struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
		node->data = data;
		node->next = NULL;
		node->prev = list->end;

		list->end->next = node;
		list->end = node;
		list->len++;

		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_TRUE);
		return LIST_TRUE;
	} else if (ret == 0) {
		//list_check(list);
		PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_FALSE);
		return LIST_FALSE;
	}

	//iterate through list
	struct list_node *temp = list->front;
	while (temp->next) {
		ret = comparer(data, temp->next->data);
		if (ret == -1) {
			struct list_node *node = (struct list_node *) secure_malloc(sizeof(struct list_node));
			node->data = data;
			node->next = temp->next;
			node->prev = temp;

			temp->next->prev = node;
			temp->next = node;
			list->len++;

			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_TRUE);
			return LIST_TRUE;
		} else if (ret == 0) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, len=%u, %u", list, list->len, LIST_FALSE);
			return LIST_FALSE;
		} else {
			temp = temp->next;
		}
	}

	//list_check(list);
	//unable to insert, but didn't trip any overlaps - big error/not possible?
	PRINT_ERROR("unreachable insert location: list=%p, data=%p", list, data);
	exit(-1);
}

//Finds the first element that satisfies <equal>
//<equal> should return:
//1 if equal
//0 if not
uint8_t *list_find_full(struct linked_list *list, int (*equal)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p", list, equal);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data)) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, data=%p", list, comp->data);
			return comp->data;
		} else {
			comp = next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, NULL);
	return NULL;
}

//See list_find()
uint8_t *list_find1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p", list, equal, param);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param)) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, data=%p", list, comp->data);
			return comp->data;
		} else {
			comp = next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, NULL);
	return NULL;
}

//See list_find()
uint8_t *list_find2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p", list, equal, param1, param2);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2)) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, data=%p", list, comp->data);
			return comp->data;
		} else {
			comp = next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, NULL);
	return NULL;
}

//See list_find()
uint8_t *list_find4_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2, uint8_t *param3, uint8_t *param4),
		uint8_t *param1, uint8_t *param2, uint8_t *param3, uint8_t *param4) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p, param3=%p, param4=%p", list, equal, param1, param2, param3, param4);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2, param3, param4)) {
			//list_check(list);
			PRINT_DEBUG("Exited: list=%p, data=%p", list, comp->data);
			return comp->data;
		} else {
			comp = next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, NULL);
	return NULL;
}

//Creates a new list and returns the pointers for which <equal> returns true
//<equal> should return:
//1 if equal
//0 if not
struct linked_list *list_find_all_full(struct linked_list *list, int (*equal)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p", list, equal);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data)) {
			list_append(list_ret, comp->data);
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//See list_find_all()
struct linked_list *list_find_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p", list, equal, param);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param)) {
			list_append(list_ret, comp->data);
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//See list_find_all()
struct linked_list *list_find_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1,
		uint8_t *param2) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p", list, equal, param1, param2);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2)) {
			list_append(list_ret, comp->data);
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//Finds & returns the last element that satisfies <equal>
//<equal> should return:
//1 if equal
//0 if not
uint8_t *list_find_last_full(struct linked_list *list, int (*equal)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p", list, equal);

	struct list_node *comp = list->front;
	struct list_node *next;
	struct list_node *ret = NULL;
	while (comp) {
		next = comp->next;
		if (equal(comp->data)) {
			ret = comp;
		}
		comp = next;
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, ret->data);
	return ret->data;
}

//See list_find_last()
uint8_t *list_find_last1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p", list, equal, param);

	struct list_node *comp = list->front;
	struct list_node *next;
	struct list_node *ret = NULL;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param)) {
			ret = comp;
		}
		comp = next;
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, ret->data);
	return ret->data;
}

//See list_find_last()
uint8_t *list_find_last2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p", list, equal, param1, param2);

	struct list_node *comp = list->front;
	struct list_node *next;
	struct list_node *ret = NULL;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2)) {
			ret = comp;
		}
		comp = next;
	}

	//list_check(list);
	PRINT_DEBUG("Exited: list=%p, data=%p", list, ret->data);
	return ret->data;
}

//Iterates through list and calls <apply> on each element
//<apply> should do something on the element, removing an element in <apply> is permissible
void list_for_each_full(struct linked_list *list, void (*apply)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, apply=%p", list, apply);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		apply(comp->data);
		comp = next;
	}

	//list_check(list);
}

//See list_for_each()
void list_for_each1_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param), uint8_t *param) {
	PRINT_DEBUG("Entered: list=%p, apply=%p, param=%p", list, apply, param);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		apply(comp->data, param);
		comp = next;
	}

	//list_check(list);
}

//See list_for_each()
void list_for_each2_full(struct linked_list *list, void (*apply)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2) {
	PRINT_DEBUG("Entered: list=%p, apply=%p, param1=%p, param2=%p", list, apply, param1, param2);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		apply(comp->data, param1, param2);
		comp = next;
	}

	//list_check(list);
}

//Return a new list containing copies of each element that <equal> returns true for
//<equal> should return:
//1 if equal
//0 if not
//<clone> should return a pointer to a copied version of an element, returning the same pointer is permissible but must be handled
struct linked_list *list_filter_full(struct linked_list *list, int (*equal)(uint8_t *data), uint8_t *(*clone)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, clone=%p", list, equal, clone);

	struct linked_list *list_ret = list_create(list->max); //should it be list->len?

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data)) {
			list_append(list_ret, clone(comp->data));
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//See list_filter()
struct linked_list *list_filter1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param, uint8_t *(*clone)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p, clone=%p", list, equal, param, clone);

	struct linked_list *list_ret = list_create(list->max);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param)) {
			list_append(list_ret, clone(comp->data));
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//See list_filter()
struct linked_list *list_filter2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2,
		uint8_t *(*clone)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p, clone=%p", list, equal, param1, param2, clone);

	struct linked_list *list_ret = list_create(list->max);

	struct list_node *comp = list->front;
	struct list_node *next;
	while (comp) {
		next = comp->next;
		if (equal(comp->data, param1, param2)) {
			list_append(list_ret, clone(comp->data));
		}
		comp = next;
	}

	//list_check(list);
	//list_check(list_ret);
	PRINT_DEBUG("Exited: list=%p, ret=%p, len=%u", list, list_ret, list_ret->len);
	return list_ret;
}

//Iterate and free the elements of <list>, afterwards free the list
//<release> should free the data structure in the element as well as any subcomponents
void list_free_full(struct linked_list *list, void (*release)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, release=%p", list, release);

	//list_check(list);

	struct list_node *next;

	struct list_node *node = list->front;
	while (node) {
		next = node->next;
		if (node->data) {
			PRINT_DEBUG("Freeing: data=%p", node->data);
			release(node->data);
		}
		PRINT_DEBUG("Freeing: node=%p", node);
		free(node);

		node = next;
	}
	free(list);
}

//Iterate and free the elements of <list> that equal returns true for
//<equal> should return:
//1 if equal
//0 if not
//<release> should free the data structure in the element as well as any subcomponents
void list_free_all_full(struct linked_list *list, int (*equal)(uint8_t *data), void (*release)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, release=%p", list, equal, release);

	//list_check(list);

	struct list_node *next;

	struct list_node *node = list->front;
	while (node) {
		next = node->next;
		if (equal(node->data)) {
			PRINT_DEBUG("Freeing: data=%p", node->data);
			release(node->data);
			PRINT_DEBUG("Freeing: node=%p", node);
			free(node);
		}
		node = next;
	}
}

//See list_free_all()
void list_free_all1_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param), uint8_t *param, void (*release)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param=%p, release=%p", list, equal, param, release);

	//list_check(list);

	struct list_node *next;

	struct list_node *node = list->front;
	while (node) {
		next = node->next;
		if (equal(node->data, param)) {
			PRINT_DEBUG("Freeing: data=%p", node->data);
			release(node->data);
			PRINT_DEBUG("Freeing: node=%p", node);
			free(node);
		}
		node = next;
	}
}

//See list_free_all()
void list_free_all2_full(struct linked_list *list, int (*equal)(uint8_t *data, uint8_t *param1, uint8_t *param2), uint8_t *param1, uint8_t *param2,
		void (*release)(uint8_t *data)) {
	PRINT_DEBUG("Entered: list=%p, equal=%p, param1=%p, param2=%p, release=%p", list, equal, param1, param2, release);

	//list_check(list);

	struct list_node *next;

	struct list_node *node = list->front;
	while (node) {
		next = node->next;
		if (equal(node->data, param1, param2)) {
			PRINT_DEBUG("Freeing: data=%p", node->data);
			release(node->data);
			PRINT_DEBUG("Freeing: node=%p", node);
			free(node);
		}
		node = next;
	}
}

uint32_t gen_control_serial_num(void) {
	uint32_t num;

	//TODO replace this with a random number generator
	secure_sem_wait(&global_control_serial_sem);
	num = ++global_control_serial_num;
	sem_post(&global_control_serial_sem);

	return num;
}

struct finsFrame * buildFinsFrame(void) { //TODO replace with createFinsFrame() or just remove

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));

	PRINT_DEBUG("2.1");
	int linkvalue = 80211;
	char linkname[] = "linklayer";
	uint8_t fakeDatav[] = "loloa77a7";
	uint8_t *fakeData = fakeDatav;

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));

	PRINT_DEBUG("2.2");
	metadata_create(meta);
	PRINT_DEBUG("2.3");
	metadata_addElement(meta, linkname, META_TYPE_INT32);
	PRINT_DEBUG("2.4");
	metadata_writeToElement(meta, linkname, &linkvalue, META_TYPE_INT32);
	PRINT_DEBUG("2.5");
	ff->dataOrCtrl = FF_DATA;
	ff->destinationID = (uint32_t) 200;

	ff->dataFrame.directionFlag = DIR_UP;
	ff->metaData = meta;
	ff->dataFrame.pdu = fakeData;
	ff->dataFrame.pduLength = 10;

	return ff;
}

/**@brief prints the contents of a fins frame whether data or control type
 * @param fins_in the pointer to the fins frame
 * */
void print_finsFrame(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	/*
	 struct destinationList *dest = &(ff->destinationID);
	 while (dest != NULL) {
	 PRINT_DEBUG("Destination id %d", dest->id);
	 dest = dest->next;
	 }
	 */

	if (ff->dataOrCtrl == FF_DATA) {
		PRINT_IMPORTANT("frame: ff=%p, FF_DATA, dst=%u, meta=%p, dir=%u, pduLen=%u, pdu=%p",
				ff, ff->destinationID, ff->metaData, ff->dataFrame.directionFlag, ff->dataFrame.pduLength, ff->dataFrame.pdu);
		metadata_print(ff->metaData);

#ifdef DEBUG
		print_hex(ff->dataFrame.pduLength, ff->dataFrame.pdu);
#endif

		//######################
#ifdef DEBUG
		char *temp = (char *) secure_malloc(ff->dataFrame.pduLength + 1);
		memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
		temp[ff->dataFrame.pduLength] = '\0';
		PRINT_DEBUG("pdu='%s'", temp);
		free(temp);
#endif
		//######################
	} else if (ff->dataOrCtrl == FF_CONTROL) {
		PRINT_IMPORTANT("frame: ff=%p, FF_CONTROL, dst=%u, meta=%p, sender=%u, serial_num=%u, opcode=%u, param_id=%u, data_len=%u, data=%p",
				ff, ff->destinationID, ff->metaData, ff->ctrlFrame.sender_id, ff->ctrlFrame.serial_num, ff->ctrlFrame.opcode, ff->ctrlFrame.param_id, ff->ctrlFrame.data_len, ff->ctrlFrame.data);
		metadata_print(ff->metaData);

#ifdef DEBUG
		print_hex(ff->ctrlFrame.data_len, ff->ctrlFrame.data);
#endif
	} else {
		PRINT_WARN("todo error");
	}
}

/**@brief copies the contents of one fins frame into another
 * @param dst is the pointer to the fins frame being written to
 * @param src is the pointer to the source fins frame
 * */
void copy_fins_to_fins(struct finsFrame *dst, struct finsFrame *src) {

	if (src->dataOrCtrl == FF_DATA) {

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->dataFrame, &src->dataFrame, sizeof(src->dataFrame));

		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pdu = src->dataFrame.pdu;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->metaData = src->metaData;

	} else if (src->dataOrCtrl == FF_CONTROL) {

		PRINT_DEBUG("control fins frame");

		dst->destinationID = src->destinationID;
		dst->dataOrCtrl = src->dataOrCtrl;
		//memcpy(&dst->ctrlFrame, &src->ctrlFrame, sizeof(src->ctrlFrame));
		dst->ctrlFrame.opcode = src->ctrlFrame.opcode;
		dst->ctrlFrame.param_id = src->ctrlFrame.param_id;
		dst->ctrlFrame.data = src->ctrlFrame.data;
		//dst->ctrlFrame.replyRecord = (void *) src->ctrlFrame.data;
		dst->ctrlFrame.sender_id = src->ctrlFrame.sender_id;
		dst->ctrlFrame.serial_num = src->ctrlFrame.serial_num;
	} else {
		PRINT_WARN("todo error");
	}
}

struct finsFrame *cloneFinsFrame(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *meta_clone = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_clone);

	if (ff->metaData != NULL) {
		if (metadata_copy(ff->metaData, meta_clone) == META_FALSE) {
			PRINT_WARN("todo error");
		}
	} else {
		PRINT_WARN("todo error");
	}

	struct finsFrame *ff_clone = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	memcpy(ff_clone, ff, sizeof(struct finsFrame));
	ff_clone->metaData = meta_clone;

	if (ff_clone->dataOrCtrl == FF_CONTROL) {
		if (ff_clone->ctrlFrame.data_len) {
			ff_clone->ctrlFrame.data = (uint8_t *) secure_malloc(ff_clone->ctrlFrame.data_len);
			memcpy(ff_clone->ctrlFrame.data, ff->ctrlFrame.data, ff_clone->ctrlFrame.data_len);
		} else {
			PRINT_DEBUG("here");
			ff_clone->ctrlFrame.data = NULL;
		}
		PRINT_DEBUG("Exited: orig: ff=%p, meta=%p, data=%p; clone: ff=%p, meta=%p, data=%p",
				ff, ff->metaData, ff->ctrlFrame.data, ff_clone, ff_clone->metaData, ff_clone->ctrlFrame.data);
	} else if (ff_clone->dataOrCtrl == FF_DATA) {
		if (ff_clone->dataFrame.pduLength) {
			ff_clone->dataFrame.pdu = (uint8_t *) secure_malloc(ff_clone->dataFrame.pduLength);
			memcpy(ff_clone->dataFrame.pdu, ff->dataFrame.pdu, ff_clone->dataFrame.pduLength);
		} else {
			PRINT_DEBUG("here");
			ff_clone->dataFrame.pdu = NULL;
		}
		PRINT_DEBUG("Exited: orig: ff=%p, meta=%p, pdu=%p; clone: ff=%p, meta=%p, pdu=%p",
				ff, ff->metaData, ff->dataFrame.pdu, ff_clone, ff_clone->metaData, ff_clone->dataFrame.pdu);
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	return ff_clone;
}

int freeFinsFrame(struct finsFrame *ff) {
	if (ff == NULL) {
		return (0);
	}

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);
	if (ff->dataOrCtrl == FF_CONTROL) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->ctrlFrame.data) {
			PRINT_DEBUG("Freeing: data=%p", ff->ctrlFrame.data);
			free(ff->ctrlFrame.data);
		}
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->metaData != NULL) {
			metadata_destroy(ff->metaData);
		}
		if (ff->dataFrame.pdu) {
			PRINT_DEBUG("Freeing: pdu=%p", ff->dataFrame.pdu);
			free(ff->dataFrame.pdu);
		}
	} else {
		//dataOrCtrl uninitialized
		PRINT_ERROR("todo error");
		exit(-1);
	}

	free(ff);
	return (1);
}

int serializeCtrlFrame(struct finsFrame *ff, uint8_t **buffer)
/* serializes a fins control frame for transmission to an external process
 * - pass it the frame (finsFrame) and it will fill in the pointer to the frame, uchar*
 * -- and return the length of the array (return int);
 * - this is used to send a control frame to an external app
 * - we can't send pointers outside of a process
 * - called by the sender
 */
{
	// MST: I think we only need to worry about a subset of these, mainly the read/read reply/set
	// types. For the others, why don't you serialize part of the info and send that or
	// just not do anything -- use your best judgement.
	// We probably won't know how all of the information is stored unless we go nuts
	// and start including a whole bunch of stuff -- this is where it would be great
	// to have objects that could serialize themselves. Oh well.

	//switch (finsFrame->opcode)
	// CTRL_READ_PARAM: ...
	// CTRL_READ_PARAM_REPLY: ...
	// CTRL_ALERT: ...
	// CTRL_ERROR: ...
	// CTRL_SET_PARAM:...
	// CTRL_EXEC: ...
	// CTRL_EXEC_REPLY: ...
	// default: ...

	//load buffer

	//	if(sizeof(buffer) < sizeof(itoa(ff->dataOrCtrl) + ff->destinationID + ff->ctrlFrame.name + itoa(ff->ctrlFrame.opcode) + itoa(ff->ctrlFrame.sender_id) + itoa(ff->ctrlFrame.serial_num) + sizeof((char)ff->ctrlFrame.data)))

	PRINT_DEBUG("In serializeCtrlFrame!");

	//PRINT_DEBUG("temp_buffer: '%s' size of temp_buffer: %d",temp_buffer,sizeof(temp_buffer));

	//initialize buffer

	int buf_size = /*strlen((char *) ff->ctrlFrame.data_old) + strlen((char *) ff->ctrlFrame.name) + */3 * sizeof(uint8_t) + 2 * sizeof(int)
			+ sizeof(unsigned short int) + sizeof(unsigned int);

	//PRINT_DEBUG("SIZE OF BUF_SIZE = %d", buf_size);

	*buffer = (uint8_t *) secure_malloc(buf_size);

	uint8_t *temporary = *buffer;

	//FF_DATA OR FF_CONTROL
	memcpy((uint8_t *) *buffer, &(ff->dataOrCtrl), sizeof(uint8_t));
	//PRINT_DEBUG("buffer1:'%s'", *buffer);

	//increment pointer
	*buffer += sizeof(uint8_t);

	//DESTINATION ID
	memcpy((uint8_t *) *buffer, &(ff->destinationID), sizeof(uint8_t));
	//PRINT_DEBUG("buffer2:'%s'",*buffer);

	//increment pointer
	*buffer += sizeof(uint8_t);

	//send size of name first
	int temp = 0; //strlen((char *) ff->ctrlFrame.name);
	memcpy((uint8_t *) *buffer, &temp, sizeof(int));

	//increment pointer
	*buffer += sizeof(int);

	//NAME
	//strcat((uint8_t *)*buffer, ff->ctrlFrame.name);
	//memcpy((uint8_t *) *buffer, ff->ctrlFrame.name, temp);
	//PRINT_DEBUG("buffer3:'%s'", *buffer);

	//increment pointer
	*buffer += temp;

	//OPCODE
	//	strncat((uint8_t *)*buffer, (uint8_t *) (&(htonl(ff->ctrlFrame.opcode))), sizeof(int));
	memcpy((uint8_t *) *buffer, &(ff->ctrlFrame.opcode), sizeof(unsigned short int));
	//PRINT_DEBUG("buffer4 = '%s'", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned short int);

	//SENDERID
	//strncat((uint8_t *)*buffer, &(ff->ctrlFrame.sender_id),sizeof(uint8_t *));
	memcpy((uint8_t *) *buffer, &(ff->ctrlFrame.sender_id), sizeof(uint8_t));
	//PRINT_DEBUG("buffer5:'%s'", *buffer);

	//increment pointer
	*buffer += sizeof(uint8_t);

	//SERIALNUM
	memcpy((uint8_t *) *buffer, &(ff->ctrlFrame.serial_num), sizeof(unsigned int));
	//PRINT_DEBUG("buffer6: '%s'", *buffer);

	*buffer += sizeof(unsigned int);

	//fill in known/common parts
	switch (ff->ctrlFrame.opcode) {
	case CTRL_READ_PARAM:
		break;

	case CTRL_READ_PARAM_REPLY:
		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//send size of data first
		//temp = strlen((char *) (ff->ctrlFrame.data_old));
		//memcpy((uint8_t *) *buffer, &temp, sizeof(int));

		//increment buffer
		*buffer += sizeof(int);

		//send data itself
		//memcpy(*buffer, (char *) (ff->ctrlFrame.data_old), temp);
		//PRINT_DEBUG("CSP: buffer7 = '%s', temp = %d, data = '%s'", *buffer,temp,((char *)(ff->ctrlFrame.data)));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;

	}

	//decrement pointer
	*buffer = temporary;
	PRINT_DEBUG("Final value of buffer:'%s'", *buffer);

	return strlen((char *) (*buffer));
}

struct finsFrame* unserializeCtrlFrame(uint8_t * buffer, int length)
/* does the opposite of serializeCtrlFrame; used to reconstruct a controlFrame
 * - pass it the byte array and the length and it will give you a pointer to the
 * -- struct.
 * - called by the receiver
 */
{
	/* again, we'll probably only have to deal with a subset of the types here.
	 * I'm OK with just doing what we know we'll pass back and forth and we
	 * can worry about the rest later. -- MST
	 */
	PRINT_DEBUG("In unserializeCtrlFrame!");

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	//	PRINT_DEBUG("The value of buffer = '%s'", buffer,length);

	//FF_DATA OR FF_CONTROL
	memcpy(&(ff->dataOrCtrl), (uint8_t *) buffer, sizeof(uint8_t));
	//PRINT_DEBUG("buffer1 = '%s', dataOrCtrl = %d", buffer,ff->dataOrCtrl);
	buffer += sizeof(uint8_t);

	//DESTINATION ID
	memcpy(&(ff->destinationID), (uint8_t *) buffer, sizeof(uint8_t));
	//PRINT_DEBUG("buffer2 = '%s', destination = %d", buffer,ff->destinationID);
	buffer += sizeof(uint8_t);

	//NAME
	//retrieve size of name first
	int temp = 0;
	memcpy(&temp, (uint8_t *) buffer, sizeof(int));
	buffer += sizeof(int);

	//PRINT_DEBUG("temp = %d", temp);

	//retrieve the name
	//ff->ctrlFrame.name = fins_malloc(temp);
	//memcpy(ff->ctrlFrame.name, (uint8_t *) buffer, temp);
	//PRINT_DEBUG("buffer3 = '%s', name = '%s'", buffer,ff->ctrlFrame.name);
	buffer += temp;

	//OPCODE
	memcpy(&(ff->ctrlFrame.opcode), (uint8_t *) buffer, sizeof(unsigned short int));
	//PRINT_DEBUG("buffer4 = '%s', opcode = %d", buffer,ff->ctrlFrame.opcode);
	buffer += sizeof(unsigned short int);

	//SENDERID
	memcpy(&(ff->ctrlFrame.sender_id), (uint8_t *) buffer, sizeof(uint8_t));
	//PRINT_DEBUG("buffer5 = '%s', senderID = %d", buffer,ff->ctrlFrame.sender_id);
	buffer += sizeof(uint8_t);

	//SERIALNUM
	memcpy(&(ff->ctrlFrame.serial_num), (uint8_t *) buffer, sizeof(unsigned int));
	//PRINT_DEBUG("buffer6 = '%s', serial_num = %d", buffer,ff->ctrlFrame.serial_num);
	buffer += sizeof(unsigned int);

	//FF_DATA
	//fill in known/common parts
	switch (ff->ctrlFrame.opcode) {
	case CTRL_READ_PARAM:

		break;

	case CTRL_READ_PARAM_REPLY:

		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//retrieve size of data first
		temp = 0;
		memcpy(&temp, (uint8_t *) buffer, sizeof(int));

		//PRINT_DEBUG("CSP: buffer6.25 = '%s'", buffer);

		//increment buffer
		buffer += sizeof(int);
		//PRINT_DEBUG("CSP: buffer6.5 = '%s'", buffer);

		//retrieve data itself
		//ff->ctrlFrame.data_old = fins_malloc(temp);
		//memcpy((char *) (ff->ctrlFrame.data_old), buffer, temp);
		//PRINT_DEBUG("CSP: buffer7 = '%s', temp = %d, data = '%s'", buffer, temp,(char *)(ff->ctrlFrame.data));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;
	}

	return ff;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
#ifndef BUILD_FOR_ANDROID
	/* ascii (if printable)*/
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
#endif
	return;
}

void print_hex_block(const u_char *payload, int len) {
	PRINT_DEBUG("passed len = %d", len);
	int len_rem = len;
	int line_width = 16; /* number of bytes per line */
	int line_len;
	int offset = 0; /* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		PRINT_DEBUG("calling hex_ascii_line");
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void print_hex(uint32_t msg_len, uint8_t *msg_pt) {
	uint8_t *temp = (uint8_t *) malloc(3 * msg_len + 1);
	uint8_t *pt = temp;
	int i;
	for (i = 0; i < msg_len; i++) {
		if (i == 0) {
			sprintf((char *) pt, "%02x", msg_pt[i]);
			pt += 2;
		} else if (i % 4 == 0) {
			sprintf((char *) pt, ":%02x", msg_pt[i]);
			pt += 3;
		} else {
			sprintf((char *) pt, " %02x", msg_pt[i]);
			pt += 3;
		}
	}
	temp[3 * msg_len] = '\0';
	PRINT_IMPORTANT("msg_len=%u, msg='%s'", msg_len, temp);
	free(temp);
}

struct addr_record *addr_clone(struct addr_record *addr) {
	PRINT_DEBUG("Entered: addr=%p, if_index=%u", addr, addr->if_index);

	struct addr_record *addr_clone = (struct addr_record *) secure_malloc(sizeof(struct addr_record));
	memcpy(addr_clone, addr, sizeof(struct addr_record));

	PRINT_DEBUG("Exited: addr=%p, ret=%p", addr, addr_clone);
	return addr_clone;
}

int addr_is_v4(struct addr_record *addr) {
	return addr->family == AF_INET;
}

int addr_ipv4_test(struct addr_record *addr, uint32_t *ip) {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr->ip;
	return addr4->sin_family == AF_INET && addr4->sin_addr.s_addr == *ip;
}

int addr_bdcv4_test(struct addr_record *addr, uint32_t *ip) {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr->bdc;
	return addr4->sin_family == AF_INET && addr4->sin_addr.s_addr == *ip;
}

int addr_is_v6(struct addr_record *addr) {
	return addr->family == AF_INET6;
}

int addr_ipv6_test(struct addr_record *addr, uint32_t *ip) {
	return 0;
}

int addr_bdcv6_test(struct addr_record *addr, uint32_t *ip) {
	return 0;
}

void addr4_set_ip(struct sockaddr_storage *addr, uint32_t ip) {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
	addr4->sin_family = AF_INET;
	addr4->sin_addr.s_addr = ip;
}

uint32_t addr4_get_ip(struct sockaddr_storage *addr) {
	return ((uint32_t) ((struct sockaddr_in *) addr)->sin_addr.s_addr);
}

void addr4_set_port(struct sockaddr_storage *addr, uint16_t port) {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
	addr4->sin_family = AF_INET;
	addr4->sin_port = port;
}

uint16_t addr4_get_port(struct sockaddr_storage *addr) {
	return ((uint16_t) ((struct sockaddr_in *) addr)->sin_port);
}

void addr6_set_ip(struct sockaddr_storage *addr, uint32_t ip) {
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
	memset(addr6, 0, sizeof(struct sockaddr_in6));
	addr6->sin6_family = AF_INET6;
	//addr6->sin6_addr.s_addr = val;
}

uint8_t *addr6_get_ip(struct sockaddr_storage *addr) {
	return NULL;
}

struct if_record *ifr_clone(struct if_record *ifr) {
	PRINT_DEBUG("Entered: ifr=%p, name='%s'", ifr, ifr->name);

	struct if_record *ifr_clone = (struct if_record *) secure_malloc(sizeof(struct if_record));
	memcpy(ifr_clone, ifr, sizeof(struct if_record));

	if (ifr->addr_list) {
		PRINT_DEBUG("Cloning addr_list=%p", ifr_clone->addr_list);
		ifr_clone->addr_list = list_clone(ifr->addr_list, addr_clone);
	}

	PRINT_DEBUG("Exited: ifr=%p, ret=%p", ifr, ifr_clone);
	return ifr_clone;
}

int ifr_running_test(struct if_record *ifr) {
	return ifr->flags & IFF_RUNNING;
}

int ifr_index_test(struct if_record *ifr, int32_t *index) {
	return ifr->index == *index;
}

int ifr_name_test(struct if_record *ifr, uint8_t *name) {
	return strcmp((char *) ifr->name, (char *) name) == 0;
}

void ifr_total_test(struct if_record *ifr, uint32_t *total) {
	*total = *total + ifr->addr_list->len;
}

int ifr_ipv4_test(struct if_record *ifr, uint32_t *ip) {
	if (ifr->addr_list != NULL) {
		struct addr_record *addr = (struct addr_record *) list_find1(ifr->addr_list, addr_ipv4_test, ip);
		return addr != NULL;
	}
	return 0;
}

int ifr_ipv6_test(struct if_record *ifr, uint32_t *ip) {
	return 0;
}

void ifr_free(struct if_record *ifr) {
	PRINT_DEBUG("Entered: ifr=%p", ifr);

	if (ifr->addr_list) {
		list_free(ifr->addr_list, free);
	}

	free(ifr);
}

int route_is_addr4(struct route_record *route) {
	return route->family == AF_INET;
}

int route_is_addr6(struct route_record *route) {
	return route->family == AF_INET6;
}

struct route_record *route_clone(struct route_record *route) {
	PRINT_DEBUG("Entered: route=%p", route);

	struct route_record *route_clone = (struct route_record *) secure_malloc(sizeof(struct route_record));
	memcpy(route_clone, route, sizeof(struct route_record));

	PRINT_DEBUG("Exited: route=%p, ret=%p", route, route_clone);
	return route_clone;
}
