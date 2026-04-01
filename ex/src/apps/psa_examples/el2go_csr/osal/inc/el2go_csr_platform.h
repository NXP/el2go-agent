/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_CSR_PLATFORM__H_
#define _EL2GO_CSR_PLATFORM__H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_csr_osal_types.h"

/*! @brief Platform initialization function
 * 
 * This function is called at the start of the application to initialize 
 * the platform hardware and software components required for the application, 
 * depending on the target platform.
 * 
 * @param None
 * @retval None
 */
void platform_init(void);


#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_PLATFORM__H_ */