/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_CSR_OSAL__H_
#define _EL2GO_CSR_OSAL__H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _os_status
{
    kStatus_OS_INIT_SUCCESS     = 0x87393DEFU,
    kStatus_OS_NOT_SUPPORTED    = 0x1CBE3190U,
    kStatus_OS_INIT_FAILED      = 0x34526BCDU,

} os_status_t; 


/*! @brief OS initialization function
 * 
 * This function is called at the start of the application to initialize 
 * the operation system servies required for the application, 
 * or or no-op on bare metal systems.
 * 
 * @param None
 * @retval kStatus_OS_INIT_SUCCESS Upon successful initialization.
 */
os_status_t os_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_OSAL__H_ */