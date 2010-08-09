/*
 * IP4_reass.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "IP4.h"

/* Variable pointing to the first element of a double
 * linked list holding partially received packets.
 * Must be global so the todo:TTL garbage collector
 * can clean it.
 */
static struct ip4_reass_list *packet_list = NULL;

/*
 * Function that takes the header struct and the
 * raw IP data of a fragmented IP packet.
 * In case that this fragment is the last one missing to
 * reassemble an IP packet it returns a pointer to it.
 * In case it isn't it returns NULL
 */
struct ip4_packet* IP4_reass(struct ip4_header *pheader,
		struct ip4_packet *ppacket)
{
	struct ip4_reass_list *packet_entry;

	if (packet_list == NULL)
	{
		packet_entry = packet_list = IP4_new_packet_entry(pheader, NULL, NULL);
	} else
	{
		packet_entry = packet_list;
		while (1)
		{
			if ((packet_entry->header.id == pheader->id)
					& (packet_entry->header.source == pheader->source)
					& (packet_entry->header.protocol == pheader->protocol)
					& (packet_entry->header.destination == pheader->destination))
			{
				break;
			}
			if (packet_entry->next_packet == NULL)
			{
				struct ip4_reass_list* new_packet_entry = IP4_new_packet_entry(
						pheader, packet_entry, NULL);
				packet_entry->next_packet = new_packet_entry;
				packet_entry = new_packet_entry;
				break;
			}
			packet_entry = packet_entry->next_packet;
		}
	}

	struct ip4_fragment* fragment = IP4_construct_fragment(pheader, ppacket);
	PRINT_DEBUG("Packet pointer: %lu",(unsigned long)ppacket);
	PRINT_DEBUG("Fragment.first: %d",fragment->first);
	PRINT_DEBUG("Fragment.last: %d",fragment->last);
	PRINT_DEBUG("Fragment.more_fragments: %d", fragment->more_fragments);
	PRINT_DEBUG("Fragment.data: %lu", (unsigned long)fragment->data);

	IP4_add_fragment(packet_entry, fragment);

	return (NULL);
}

uint8_t IP4_add_fragment(struct ip4_reass_list *list,
		struct ip4_fragment *fragment)
{
	int i;
	uint8_t use_fragment = 0;
	struct ip4_reass_hole *current_hole = NULL, *next_hole_abs_pointer,
			*prev_hole_abs_pointer, *new_hole;

	for (i = 0; 1; i++)
	{
		/* Step 1
		 * Select the next hole descriptor from the hole descriptor
		 * list. If there are no more entries, go to step eight.
		 */
		if (current_hole == NULL)
		{
			current_hole
					= (struct ip4_reass_hole*) ((unsigned long) list->buffer
							+ list->first_hole_rel_pointer);
		} else if (current_hole->next_hole_rel_pointer != 0)
		{
			current_hole = IP4_next_hole(current_hole);
		} else
		{
			break;
		}
		prev_hole_abs_pointer = IP4_previous_hole(current_hole);
		next_hole_abs_pointer = IP4_next_hole(current_hole);

		/* Step 2 & 3
		 * 2. If fragment.first is greater than hole.last, go to step one.
		 * 3. If fragment.last is less than hole.first, go to step one.
		 */
		if ((fragment->first > current_hole->last) || (fragment->last
				< current_hole->first))
		{
			use_fragment = 0;
			continue;
		}
		use_fragment = 1;

		/* Step 4
		 * Delete the current entry from the hole descriptor list.
		 * -(Since  neither  step  two  nor step three was true, the
		 * newly arrived fragment does interact with this  hole  in
		 * some  way.    Therefore,  the current descriptor will no
		 * longer be valid.  We will destroy it, and  in  the  next
		 * two  steps  we  will  determine  whether  or  not  it is
		 * necessary to create any new hole descriptors.)
		 */
		IP4_remove_hole(current_hole, list);

		/* Step 5
		 * If fragment.first is greater than hole.first, then  create  a
		 * new  hole  descriptor "new_hole" with new_hole.first equal to
		 * hole.first, and new_hole.last equal to  fragment.first  minus
		 * one.
		 */
		if (fragment->first > current_hole->first)
		{
			new_hole = current_hole;
			if (IP4_previous_hole(current_hole) == NULL)
			{
				new_hole->prev_hole_rel_pointer = 0;
				list ->first_hole_rel_pointer = (unsigned long) new_hole
						- (unsigned long) list->buffer;
			} else
			{
				new_hole->prev_hole_rel_pointer = (unsigned long) new_hole
						- (unsigned long) IP4_previous_hole(current_hole);
				IP4_previous_hole(current_hole)->next_hole_rel_pointer
						= new_hole->prev_hole_rel_pointer;
			}

			if (IP4_next_hole(current_hole) == NULL)
			{
				new_hole->next_hole_rel_pointer = 0;
			} else
			{
				new_hole->next_hole_rel_pointer
						= (unsigned long) IP4_next_hole(current_hole)
								- (unsigned long) new_hole;
				IP4_next_hole(current_hole)->prev_hole_rel_pointer
						= new_hole->next_hole_rel_pointer;
			}

			new_hole->first = current_hole->first;
			new_hole->last = fragment->first - 1;
			list->hole_count++;
			current_hole=new_hole;
		}

		/* Step 6
		 * If fragment.last is less  than  hole.last  and  fragment.more_
		 * fragments is true, then create a new hole descriptor
		 * "new_hole", with new_hole.first equal to fragment.last plus
		 * one and new_hole.last equal to hole.last.
		 */
		if ((fragment->last < current_hole->last) && (fragment->more_fragments
				== 1))
		{
			new_hole = (struct ip4_reass_hole*) ((unsigned long) list->buffer
					+ (unsigned long) fragment->last + 1);

			if (IP4_previous_hole(current_hole) == NULL)
			{
				list->first_hole_rel_pointer = (unsigned long) new_hole
						- (unsigned long) IP4_previous_hole(current_hole);
				new_hole->prev_hole_rel_pointer = 0;
			} else
			{
				new_hole->prev_hole_rel_pointer = (unsigned long) new_hole
						- (unsigned long) IP4_previous_hole(current_hole);
				IP4_previous_hole(current_hole)->next_hole_rel_pointer
						= new_hole->prev_hole_rel_pointer;
			}

			if (IP4_next_hole(current_hole) == NULL)
			{
				new_hole->next_hole_rel_pointer = 0;
			} else
			{
				new_hole->next_hole_rel_pointer
						= (unsigned long) IP4_next_hole(current_hole)
								- (unsigned long) new_hole;
				IP4_next_hole(current_hole)->prev_hole_rel_pointer
						= new_hole->next_hole_rel_pointer;
			}

			new_hole->first = fragment->last + 1;
			new_hole->last = current_hole->last;
			list->hole_count++;
			current_hole=new_hole;
		}

		/* Step 7
		 * Go to step one.
		 */
	}

	if (use_fragment == 1)
	{
		if (fragment->last < list->length)
		{
			memcpy((void *) ((unsigned long) list->buffer
					+ (unsigned long) fragment->first),
					(void *) fragment->data, fragment->data_length);
		} else
		{
			/* todo: Packet reassembly buffer extension*/
			PRINT_DEBUG("Packet buffer needs to be expanded to for packets larger than the defined initial buffer size.");
		}
	}

	/*
	 * Step 8
	 * If the hole descriptor list is now empty, the datagram is now
	 * complete.  Pass it on to the higher level protocol  processor
	 * for further handling.  Otherwise, return.
	 */
	if (list->hole_count == 0)
	{
		return (1);
	} else
	{
		return (0);
	}
}

struct ip4_reass_list* IP4_new_packet_entry(struct ip4_header* pheader,
		struct ip4_reass_list* previous, struct ip4_reass_list* next)
{
	struct ip4_reass_list* packet_list_entry = (struct ip4_reass_list*) malloc(
			sizeof(struct ip4_reass_list*));
	packet_list_entry->next_packet = next;
	packet_list_entry->previous_packet = previous;
	packet_list_entry = (struct ip4_reass_list*) malloc(
			sizeof(struct ip4_reass_list));
	packet_list_entry->header = *pheader;
	packet_list_entry->length = IP4_BUFFLEN;
	packet_list_entry->buffer = (void *) malloc(IP4_BUFFLEN);
	packet_list_entry->ttl = IP4_REASS_TTL;
	packet_list_entry->first_hole_rel_pointer = 0;
	packet_list_entry->hole_count = 1;

	((struct ip4_reass_hole*) packet_list_entry->buffer)->first = 0;
	((struct ip4_reass_hole*) packet_list_entry->buffer)->last = IP4_MAXLEN;
	((struct ip4_reass_hole*) packet_list_entry->buffer)->next_hole_rel_pointer
			= 0;
	((struct ip4_reass_hole*) packet_list_entry->buffer)->prev_hole_rel_pointer
			= 0;
	return (packet_list_entry);
}

struct ip4_fragment* IP4_construct_fragment(struct ip4_header* pheader,
		struct ip4_packet* ppacket)
{
	struct ip4_fragment* fragment = (struct ip4_fragment*) malloc(
			sizeof(struct ip4_fragment));
	fragment->first = (pheader->fragmentation_offset) * 8;
	fragment->last = fragment->first + (pheader->packet_length
			- pheader->header_length);
	fragment->data_length = pheader->packet_length - pheader->header_length;
	if (pheader->flags & IP4_MF)
		fragment->more_fragments = 1;
	else
		fragment->more_fragments = 0;
	fragment->data = (void*) ppacket + pheader->header_length;
	return (fragment);
}

struct ip4_reass_hole* IP4_previous_hole(struct ip4_reass_hole* current_hole)
{
	if (current_hole->prev_hole_rel_pointer == 0)
	{
		return (NULL);
	}
	return ((struct ip4_reass_hole*) ((unsigned long) current_hole
			+ current_hole->prev_hole_rel_pointer));
}

struct ip4_reass_hole* IP4_next_hole(struct ip4_reass_hole* current_hole)
{
	if (current_hole->next_hole_rel_pointer == 0)
	{
		return (NULL);
	}
	return ((struct ip4_reass_hole*) ((unsigned long) current_hole
			+ current_hole->next_hole_rel_pointer));
}

void IP4_remove_hole(struct ip4_reass_hole* current_hole,
		struct ip4_reass_list *list)
{
	struct ip4_reass_hole* next_hole = IP4_next_hole(current_hole);
	struct ip4_reass_hole* previous_hole = IP4_previous_hole(current_hole);
	if (previous_hole == NULL && next_hole == NULL)
	{
		list->first_hole_rel_pointer = 0;
		list->hole_count = 0;
		return;
	}
	if (next_hole == NULL)
	{
		previous_hole->next_hole_rel_pointer = 0;
		list->hole_count--;
		return;
	}
	if (previous_hole == NULL)
	{
		next_hole->prev_hole_rel_pointer = 0;
		list->first_hole_rel_pointer += current_hole->next_hole_rel_pointer;
		list->hole_count--;
		return;
	}
	previous_hole->next_hole_rel_pointer += current_hole->next_hole_rel_pointer;
	next_hole->prev_hole_rel_pointer += current_hole->prev_hole_rel_pointer;
	list->hole_count--;
	return;
}
