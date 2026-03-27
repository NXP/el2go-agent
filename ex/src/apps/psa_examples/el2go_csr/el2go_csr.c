/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr.h"

int main(void)
{
#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif

    printc(LOG_INFO, "\r\nHello from EL2GO CSR example.\r\n");

    while (true)
    {
        /* Infinite loop */
    }
}
