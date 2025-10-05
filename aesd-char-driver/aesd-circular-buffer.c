/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
                                                                          size_t char_offset, size_t *entry_offset_byte_rtn)
{
    /**
     *  Implemented per description, mutex or other synch. mechanism to be used for thread safe
     */

    struct aesd_buffer_entry *entry_rtn = NULL; // entry pointer to iterate over and return at the end
    size_t curr_position = 0;                   // stores the current position of offset from the oldest entry while iterating over entries

    uint8_t index = buffer->out_offs;

    // to avoid segfaults
    if (buffer == NULL)
        return NULL;

    while (index != buffer->in_offs || entry_rtn == NULL)
    {
        // current position in the array of entries
        entry_rtn = buffer->entry + index;

        // checks to avoid segfaults, the buffer should be already initialized
        if (entry_rtn->buffptr == NULL) 
            return entry_rtn;

        if (entry_offset_byte_rtn == NULL)
            return entry_rtn;

        /**
         * increment curr_position of offset by the size of the current entry
         * set outputs as soon as found
         */

        if (char_offset >= curr_position + entry_rtn->size)
            curr_position += entry_rtn->size;
        else
        {
            // return offset into char buffer at entry
            *entry_offset_byte_rtn = char_offset - curr_position;

            // return entry containing it
            return entry_rtn;
        }
        index++;
        index %= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    return NULL;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
 * new start location.
 * Any necessary locking must be handled by the caller
 * Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
 */
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
     *  implemented per description
     */
    // Add the entry to the array of strings
    memcpy(buffer->entry + buffer->in_offs, add_entry, sizeof(*buffer->entry));

    // Handle wright - read pointers periodically with AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED

    // check and set flag if buffer is full
    if ((buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED == buffer->out_offs)
    {
        buffer->full = true;
    }

    // move read marker - out_offs if buffer is full and in_offs is about to move past out_offs
    if (buffer->full && buffer->out_offs == buffer->in_offs)
    {
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // move write marker - in_offs to next entry
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
}

/**
 * Initializes the circular buffer described by @param buffer to an empty struct
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}
