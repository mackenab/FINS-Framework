#include "IP4.h"

struct ip4_fragment IP4_fragment_data(void *data, uint16_t length,
		uint16_t offset, uint16_t fragment_size)
{
	struct ip4_fragment fragment;
	if ((offset + fragment_size) >= length)
	{
		fragment.first = offset;
		fragment.last = length;
		fragment.data_length = length - offset;
		fragment.more_fragments = 0;
		fragment.data = data + offset;
		return (fragment);
	}

	/* Take care of a special case when the fragment is less than 8 bytes larger that then
	 * the fragment size
	 */
	if ((offset + fragment_size + 8) > length)
	{
		fragment.first = offset;
		fragment.last = length - (length - offset) % 8;
		fragment.data_length = fragment.last - fragment.first;

#ifdef DEBUG
		if (fragment.data_length % 8 != 0)
		{
			PRINT_DEBUG("Problem with fragment data length. Not a multiple of 8");
		}
#endif

		fragment.more_fragments = 1;
		return (fragment);
	}

	fragment.first = offset;
	fragment.last = offset + fragment_size;
	fragment.data_length = fragment_size;
#ifdef DEBUG
	if (fragment.data_length % 8 != 0)
	{
		PRINT_DEBUG("Problem with fragment data length. Not a multiple of 8");
	}
#endif
	fragment.more_fragments = 1;
	return (fragment);
}
