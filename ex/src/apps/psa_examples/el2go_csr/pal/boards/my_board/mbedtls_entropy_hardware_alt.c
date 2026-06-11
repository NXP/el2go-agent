/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include <stddef.h>
#include <stdint.h>

int mbedtls_hardware_poll(void *data, unsigned char *output,
                          size_t len, size_t *olen)
{
    uint32_t seed = 0xDEADBEEF;

    if (!data || !output || !olen) {
        return -1; 
    }
    
    for (size_t i = 0; i < len; i++) {
        seed = seed * 0xBAD + 0xC0DE;
        output[i] = (unsigned char)(seed >> 24);
    }

    *olen = len;
    return 0;
}