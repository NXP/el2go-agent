/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_suites.h"
#include "ztest_bridge.h"
#include "wrap_net_crypto.h"
#include "test_el2go_ota_lib_internal_suites.h"

void register_ota_lib_internal_tests(void);

/* Reset wrap_net_crypto.c mock state before every ZTEST so mock 
 * state cannot leak into another test. */
static void el2go_ota_unit_before(void *fixture)
{
    ARG_UNUSED(fixture);
    wrap_net_crypto_reset_all();
}

ZTEST_SUITE(el2go_ota_unit, NULL, NULL, el2go_ota_unit_before, NULL, NULL);

ZTEST(el2go_ota_unit, test_ota_lib_public)
{
    zassert_ok(el2go_run_suite(register_ota_lib_tests),
               "OTA lib public unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_internal)
{
    zassert_ok(el2go_run_suite(register_ota_lib_internal_tests),
               "OTA lib internal unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_grpc)
{
    zassert_ok(el2go_run_suite(register_ota_lib_grpc_tests),
               "OTA lib gRPC transport unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_request_builder)
{
    zassert_ok(el2go_run_suite(register_ota_lib_request_builder_tests),
               "OTA lib request_builder unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_response_handler)
{
    zassert_ok(el2go_run_suite(register_ota_lib_response_handler_tests),
               "OTA lib response_handler unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_status_reporting)
{
    zassert_ok(el2go_run_suite(register_ota_lib_status_reporting_tests),
               "OTA lib status_reporting unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_download_engine)
{
    zassert_ok(el2go_run_suite(register_ota_lib_download_engine_tests),
               "OTA lib download_engine unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_kvs)
{
    zassert_ok(el2go_run_suite(register_ota_lib_kvs_tests),
               "OTA lib kvs unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_tls)
{
    zassert_ok(el2go_run_suite(register_ota_lib_tls_tests),
               "OTA lib tls unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_cred_psa)
{
    zassert_ok(el2go_run_suite(register_ota_lib_cred_psa_tests),
               "OTA lib cred_psa unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_core)
{
    zassert_ok(el2go_run_suite(register_ota_lib_core_tests),
               "OTA lib core (el2go_ota_lib.c) unit suite reported failures");
}
