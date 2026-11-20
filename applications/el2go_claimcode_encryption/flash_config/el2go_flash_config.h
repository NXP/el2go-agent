/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EL2GO_FLASH_CONFIG_H__
#define __EL2GO_FLASH_CONFIG_H__

#include <stdint.h>
#include <fsl_romapi_iap.h>

/**
 * @brief Retrieve the active FlexSPI NOR configuration.
 *
 * A __weak default implementation reads the FCB directly from flash.
 * MCUXpresso SDK RAM-execution builds override this to reconfigure the
 * FlexSPI clock before reading the FCB.
 *
 * @param[out] config      Output buffer to receive the FlexSPI NOR configuration.
 * @param[in]  fcb_address Address in flash where the FCB is located.
 */
void el2go_flash_get_config(flexspi_nor_config_t *config, uint32_t fcb_address);

#endif /* __EL2GO_FLASH_CONFIG_H__ */
