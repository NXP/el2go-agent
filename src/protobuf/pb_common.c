/*
 * Copyright (c) 2011 Petteri Aimonen <jpa at nanopb.mail.kapsi.fi>
 * 
 * This software is provided 'as-is', without any express or 
 * implied warranty. In no event will the authors be held liable 
 * for any damages arising from the use of this software.
 * 
 * Permission is granted to anyone to use this software for any 
 * purpose, including commercial applications, and to alter it and 
 * redistribute it freely, subject to the following restrictions:
 * 
 * 1. The origin of this software must not be misrepresented; you 
 *    must not claim that you wrote the original software. If you use 
 *    this software in a product, an acknowledgment in the product 
 *    documentation would be appreciated but is not required.
 * 
 * 2. Altered source versions must be plainly marked as such, and 
 *    must not be misrepresented as being the original software.
 * 
 * 3. This notice may not be removed or altered from any source 
 *    distribution.
 */

/*
 * Modifications copyright (C) 2021,2024 NXP
 */

/* pb_common.c: Common support functions for pb_encode.c and pb_decode.c.
 *
 * 2014 Petteri Aimonen <jpa@kapsi.fi>
 */

#include "pb_common.h"

bool pb_field_iter_begin(pb_field_iter_t *iter, const pb_field_t *fields, void *dest_struct)
{
    iter->start = fields;
    iter->pos = fields;
    iter->required_field_index = 0;
    iter->dest_struct = dest_struct;
    iter->pData = (char*)dest_struct + iter->pos->data_offset;
    iter->pSize = (char*)iter->pData + iter->pos->size_offset;
    
    return (iter->pos->tag != 0);
}

bool pb_field_iter_next(pb_field_iter_t *iter)
{
    const pb_field_t *prev_field = iter->pos;

    if (prev_field->tag == 0)
    {
        /* Handle empty message types, where the first field is already the terminator.
         * In other cases, the iter->pos never points to the terminator. */
        return false;
    }
    
    iter->pos++;
    
    if (iter->pos->tag == 0)
    {
        /* Wrapped back to beginning, reinitialize */
        (void)pb_field_iter_begin(iter, iter->start, iter->dest_struct);
        return false;
    }
    else
    {
        /* Increment the pointers based on previous field size */
        size_t prev_size = prev_field->data_size;
    
        if (PB_HTYPE(prev_field->type) == PB_HTYPE_ONEOF &&
            PB_HTYPE(iter->pos->type) == PB_HTYPE_ONEOF &&
            iter->pos->data_offset == PB_SIZE_MAX)
        {
            /* Don't advance pointers inside unions */
            return true;
        }
        else if (PB_ATYPE(prev_field->type) == PB_ATYPE_STATIC &&
                 PB_HTYPE(prev_field->type) == PB_HTYPE_REPEATED)
        {
            /* In static arrays, the data_size tells the size of a single entry and
             * array_size is the number of entries */
            prev_size *= prev_field->array_size;
        }
        else if (PB_ATYPE(prev_field->type) == PB_ATYPE_POINTER)
        {
            /* Pointer fields always have a constant size in the main structure.
             * The data_size only applies to the dynamically allocated area. */
            prev_size = sizeof(void*);
        }

        if (PB_HTYPE(prev_field->type) == PB_HTYPE_REQUIRED)
        {
            /* Count the required fields, in order to check their presence in the
             * decoder. */
            iter->required_field_index++;
        }
    
        iter->pData = (char*)iter->pData + prev_size + iter->pos->data_offset;
        iter->pSize = (char*)iter->pData + iter->pos->size_offset;
        return true;
    }
}

bool pb_field_iter_find(pb_field_iter_t *iter, uint32_t tag)
{
    const pb_field_t *start = iter->pos;
    
    do {
        if (iter->pos->tag == tag &&
            PB_LTYPE(iter->pos->type) != PB_LTYPE_EXTENSION)
        {
            /* Found the wanted field */
            return true;
        }
        
        (void)pb_field_iter_next(iter);
    } while (iter->pos != start);
    
    /* Searched all the way back to start, and found nothing. */
    return false;
}


