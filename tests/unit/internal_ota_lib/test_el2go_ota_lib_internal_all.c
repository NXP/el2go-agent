/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_el2go_ota_lib_internal_suites.h"

/**
 * @brief Register all internal OTA-lib submodule suites in one call.
 */
void register_ota_lib_internal_all_tests(void)
{
    register_ota_lib_grpc_tests();
    register_ota_lib_request_builder_tests();
    register_ota_lib_response_handler_tests();
    register_ota_lib_status_reporting_tests();
    register_ota_lib_download_engine_tests();
    register_ota_lib_kvs_tests();
    register_ota_lib_tls_tests();
    register_ota_lib_cred_psa_tests();
    register_ota_lib_core_tests();
}