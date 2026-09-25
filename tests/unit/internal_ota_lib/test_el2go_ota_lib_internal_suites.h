/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __OTA_LIB_INTERNAL_SUITES_H__
#define __OTA_LIB_INTERNAL_SUITES_H__

/**
 * @brief Per-module internal OTA-lib test suites.
 */
void register_ota_lib_grpc_tests(void);
void register_ota_lib_request_builder_tests(void);
void register_ota_lib_response_handler_tests(void);
void register_ota_lib_status_reporting_tests(void);
void register_ota_lib_download_engine_tests(void);
void register_ota_lib_kvs_tests(void);
void register_ota_lib_tls_tests(void);
void register_ota_lib_cred_psa_tests(void);
void register_ota_lib_core_tests(void);

#endif /* __OTA_LIB_INTERNAL_SUITES_H__ */