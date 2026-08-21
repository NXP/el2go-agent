/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_CSR_PLATFORM_H__
#define __EL2GO_CSR_PLATFORM_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _platform_status {
    kStatus_PLATFORM_INIT_SUCCESS = 0xADDEF992U,
    kStatus_PLATFORM_INIT_FAILED = 0xBB321844U,
} platform_status_t;

/*! @brief Platform initialization function
 *
 * This function is called at the start of the application to initialize
 * the platform hardware and software components required for the application,
 * depending on the target platform.
 *
 * @param None
 * @retval kStatus_PLATFORM_INIT_SUCCESS Upon successful initialization.
 */
platform_status_t platform_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_CSR_PLATFORM_H__ */