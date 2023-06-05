/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _PSA_INIT_UTILS_H_
#define _PSA_INIT_UTILS_H_

#include <psa/crypto.h>
#include "nxp_iot_agent_status.h"

 /** @brief This function is used to import the command.
  *  *
  * \p cmd is the buffer containing the command string
  *
  */
iot_agent_status_t psa_init_utils_import_cmd(const char* cmd);

#endif //_PSA_INIT_UTILS_H_