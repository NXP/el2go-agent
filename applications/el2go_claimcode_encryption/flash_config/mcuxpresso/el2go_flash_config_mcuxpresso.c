/*
 * Copyright 2026 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fsl_device_registers.h>
#include <fsl_romapi_iap.h>

#include "osal.h"
#include "el2go_flash_config.h"

/*
 * Determine whether the current execution address falls within the XIP
 * FlexSPI window (0x08000000-0x0fffffff or 0x18000000-0x1fffffff).
 */
#define SYSTEM_IS_XIP_FLEXSPI()                           \
    ((((uint32_t)SystemCoreClockUpdate >= 0x08000000U) && \
      ((uint32_t)SystemCoreClockUpdate < 0x10000000U)) || \
     (((uint32_t)SystemCoreClockUpdate >= 0x18000000U) && \
      ((uint32_t)SystemCoreClockUpdate < 0x20000000U)))

#define FLEXSPI_INSTANCE (0U)

/*
 * MCUXpresso SDK RAM-execution override.
 *
 * When running from RAM after a soft reset the ROM boot clock configuration
 * may differ from the application clock, so the FlexSPI clock must be
 * reconfigured before reading the FCB. The correct flash config is stored
 * in the application-level variable flexspi_config_agent.
 */
void el2go_flash_get_config(flexspi_nor_config_t *config, uint32_t fcb_address)
{
    if (!SYSTEM_IS_XIP_FLEXSPI()) {
        uint32_t flexspi_clock_source = 0x0;
        status_t status = flexspi_nor_set_clock_source(flexspi_clock_source);
        if (kStatus_Success != status) {
            osal_printf_always("flexspi_nor_set_clock_source returned with code [%d]\r\n", status);
        }

        uint32_t flexspi_freqOption = 0x1;
        uint32_t flexspi_sampleClkMode = 0x0;
        flexspi_clock_config(FLEXSPI_INSTANCE, flexspi_freqOption, flexspi_sampleClkMode);

        *config = flexspi_config_agent;
    } else {
        *config = *((flexspi_nor_config_t *)fcb_address);
    }
}
