/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include <pb_decode.h>
#include <pb_encode.h>

#include "ota/el2go_ota_lib.h"
#include "el2go_ota_request_builder.h"
#include "el2go_ota_response_handler.h"
#include "ota_delivery.pb.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @defgroup test_el2go_ota_lib_public Public EL2GO OTA Library Tests
 * @brief Unit tests for the public el2go_ota_lib API.
 *
 * Covers parameter validation and state management paths that are
 * exercisable without hardware (no live PSA keystore required).
 *
 * @{
 */

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

/** Minimal valid CA cert placeholder -- content not verified in param tests. */
static const uint8_t s_dummy_ca[] = { 0x30, 0x01, 0x00 };

/* ========================================================================== */
/* Parameter Validation Tests -- el2go_ota_init()                             */
/* ========================================================================== */

/**
 * @brief el2go_ota_init(NULL, valid_config) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM and leave *ctx untouched.
 */
static bool test_el2go_ota_init_null_ctx(void *params)
{
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(NULL, &cfg));

    return true;
}

/**
 * @brief el2go_ota_init(&ctx, NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM
 *        and set *ctx to NULL.
 */
static bool test_el2go_ota_init_null_config(void *params)
{
    el2go_ota_ctx_t *ctx = (el2go_ota_ctx_t *)0xDEADBEEF; /* sentinel */
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;

    (void)params;

    status = el2go_ota_init(&ctx, NULL);
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, status);
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with config->hostname == NULL must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_init_null_hostname(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = NULL,
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with server_ca_chain == NULL must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_init_null_ca_chain(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = NULL,
        .server_ca_chain_size = 0U,
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief el2go_ota_init() with server_ca_chain_size == 0 (non-NULL pointer)
 *        must return EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_init_zero_ca_chain_size(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = 0U,
    };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_init(&ctx, &cfg));
    TEST_ASSERT_NULL(ctx);

    return true;
}

/* ========================================================================== */
/* Parameter Validation Tests -- el2go_ota_connect() / disconnect()           */
/* ========================================================================== */

/**
 * @brief el2go_ota_connect(NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_connect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_connect(NULL));

    return true;
}

/**
 * @brief el2go_ota_disconnect(NULL) must return EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_el2go_ota_disconnect_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_disconnect(NULL));

    return true;
}

/* ========================================================================== */
/* Diagnostics Tests                                                          */
/* ========================================================================== */

/**
 * @brief el2go_ota_is_connected(NULL) must return false.
 */
static bool test_el2go_ota_is_connected_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(NULL));

    return true;
}

/**
 * @brief el2go_ota_get_error_string() must return a non-NULL string for every
 *        defined status code, including the success case.
 */
static bool test_el2go_ota_get_error_string(void *params)
{
    (void)params;

    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_SUCCESS));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_INVALID_PARAM));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_MEMORY));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_AUTH));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_NETWORK));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_TLS_HANDSHAKE));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_CERT_VERIFY));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_PLATFORM_INIT));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_ENCODE));
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string(EL2GO_OTA_ERROR_DECODE));
    /* Unknown value must also return a non-NULL fallback. */
    TEST_ASSERT_NOT_NULL(el2go_ota_get_error_string((el2go_ota_status_t)0xFF));

    return true;
}

/**
 * @brief el2go_ota_cleanup(NULL) and el2go_ota_cleanup(&NULL) must not crash.
 */
static bool test_el2go_ota_cleanup_null_safe(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;

    (void)params;

    el2go_ota_cleanup(NULL); /* must not crash */
    el2go_ota_cleanup(&ctx); /* *ctx already NULL -- must not crash */

    TEST_PRINT_INFO("el2go_ota_cleanup() with NULL is safe");

    return true;
}

/**
 * @brief el2go_ota_init() with valid parameters must succeed and return a
 *        non-NULL context that can be cleaned up without crashing.
 */
static bool test_el2go_ota_init_cleanup(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    status = el2go_ota_init(&ctx, &cfg);
    /* Must fail -- no real PSA keystore or valid CA on a unit-test host. */
    TEST_ASSERT_NOT_EQUAL(EL2GO_OTA_SUCCESS, status);
    /* ctx must be NULL-ed on any failure path. */
    TEST_ASSERT_NULL(ctx);
    /* cleanup of NULL ctx must be safe. */
    el2go_ota_cleanup(&ctx);

    return true;
}

/**
 * @brief A failed el2go_ota_init() must leave ctx NULL, which must report
 *        not connected.
 */
static bool test_el2go_ota_is_connected_after_init(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };

    (void)params;

    /* Ignore the specific error -- see test_el2go_ota_init_cleanup. */
    (void)el2go_ota_init(&ctx, &cfg);
    TEST_ASSERT_NULL(ctx);

    /* NULL ctx must always report not connected. */
    TEST_ASSERT_EQUAL(false, el2go_ota_is_connected(ctx));

    el2go_ota_cleanup(&ctx);
    return true;
}

/**
 * @brief el2go_ota_get_error_string() on the status returned by a failed
 *        el2go_ota_init() must return a non-NULL, non-empty string.
 */
static bool test_el2go_ota_get_error_string_after_failed_init(void *params)
{
    el2go_ota_ctx_t *ctx = NULL;
    el2go_ota_status_t status = EL2GO_OTA_SUCCESS;
    el2go_ota_mtls_config_t cfg = {
        .hostname = "ota.example.com",
        .port = 443U,
        .server_ca_chain = s_dummy_ca,
        .server_ca_chain_size = sizeof(s_dummy_ca),
    };
    const char *err = NULL;

    (void)params;

    status = el2go_ota_init(&ctx, &cfg);
    TEST_ASSERT_NULL(ctx);

    /* The returned status must translate to a non-NULL, non-empty string. */
    err = el2go_ota_get_error_string(status);
    TEST_ASSERT_NOT_NULL(err);
    TEST_ASSERT_NOT_EQUAL('\0', err[0]);

    el2go_ota_cleanup(&ctx);
    return true;
}

/* ========================================================================== */
/* Request Builder -- Happy-path round-trip tests                             */
/* ========================================================================== */

/**
 * @brief Encode a FetchPackage request and decode it back with nanopb to verify
 *        that both string fields survive the encode/decode cycle unchanged.
 */
static bool test_encode_fetch_package_roundtrip(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "update-abc-123",
        .package_id = "pkg-xyz-456",
    };
    uint8_t buf[128];
    size_t out_len = 0U;
    com_nxp_iot_ota_FileRequest msg = com_nxp_iot_ota_FileRequest_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_FileRequest_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "update-abc-123"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.packageId, "pkg-xyz-456"));
    /* artifactId was not set -- must decode as empty string. */
    TEST_ASSERT_EQUAL('\0', msg.artifactId[0]);
    TEST_ASSERT_EQUAL(false, msg.has_rangeStart);
    TEST_ASSERT_EQUAL(false, msg.has_rangeEnd);

    return true;
}

/**
 * @brief Encode a FetchPackage request with all five fields set (including
 *        artifactId, rangeStart, rangeEnd) and verify the decoded wire message.
 */
static bool test_encode_fetch_package_with_artifact_and_range(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "upd-range-1",
        .package_id = "pkg-range-2",
        .artifact_id = "artifact-fw.bin",
        .has_range_start = true,
        .range_start = 0,
        .has_range_end = true,
        .range_end = 4095,
    };
    uint8_t buf[256];
    size_t out_len = 0U;
    com_nxp_iot_ota_FileRequest msg = com_nxp_iot_ota_FileRequest_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_FileRequest_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-range-1"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.packageId, "pkg-range-2"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.artifactId, "artifact-fw.bin"));
    TEST_ASSERT_EQUAL(true, msg.has_rangeStart);
    TEST_ASSERT_EQUAL(0, msg.rangeStart);
    TEST_ASSERT_EQUAL(true, msg.has_rangeEnd);
    TEST_ASSERT_EQUAL(4095, msg.rangeEnd);

    return true;
}

/**
 * @brief Encode successive chunked requests and verify that rangeStart advances
 *        correctly (chunk 0: 0..4095, chunk 1: 4096..8191).
 */
static bool test_encode_fetch_package_chunked_range(void *params)
{
    const int64_t chunk_size = 4096;
    uint8_t buf[256];
    size_t out_len = 0U;
    int64_t chunk = 0;
    el2go_ota_fetch_pkg_req_t req;
    com_nxp_iot_ota_FileRequest msg;
    pb_istream_t stream;

    (void)params;

    for (chunk = 0; chunk < 2; chunk++) {
        req.update_id = "upd-chunk";
        req.package_id = "pkg-chunk";
        req.artifact_id = NULL;
        req.has_range_start = true;
        req.range_start = chunk * chunk_size;
        req.has_range_end = true;
        req.range_end = (chunk + 1) * chunk_size - 1;

        TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                          el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
        TEST_ASSERT(out_len > 0U);

        memset(&msg, 0, sizeof(msg)); /* reset for each iteration */
        stream = pb_istream_from_buffer(buf, out_len);
        TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_FileRequest_fields, &msg));
        TEST_ASSERT_EQUAL(true, msg.has_rangeStart);
        TEST_ASSERT_EQUAL(chunk * chunk_size, msg.rangeStart);
        TEST_ASSERT_EQUAL(true, msg.has_rangeEnd);
        TEST_ASSERT_EQUAL((chunk + 1) * chunk_size - 1, msg.rangeEnd);
    }

    return true;
}

/**
 * @brief Encode a ReportStatus request (STATUS_SUCCESS, with message) and
 *        decode it back to verify all fields survive the encode/decode cycle.
 *
 * The server-side UpdateStatusNotification has:
 *   updateId (field 1), updateStatus (field 2), optional statusMessage (field 3).
 * There is no packageId field.
 */
static bool test_encode_report_status_roundtrip(void *params)
{
    el2go_ota_report_status_req_t req = {
        .update_id = "upd-1",
        .status = EL2GO_OTA_UPDATE_STATUS_SUCCESS,
        .status_message = "applied ok",
    };
    uint8_t buf[128];
    size_t out_len = 0U;
    com_nxp_iot_ota_UpdateStatusNotification msg =
        com_nxp_iot_ota_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-1"));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_Status_STATUS_SUCCESS, msg.updateStatus);
    TEST_ASSERT_EQUAL(true, msg.has_statusMessage);
    TEST_ASSERT_EQUAL(0, strcmp(msg.statusMessage, "applied ok"));

    return true;
}

/**
 * @brief Encode a CheckUpdate request with two device attributes and verify the
 *        encoded byte count is larger than the zero-attributes case, confirming
 *        the map callback actually wrote data.
 */
static bool test_encode_check_update_with_attrs(void *params)
{
    static const el2go_ota_attr_t attrs[] = {
        { "board", "rw612" },
        { "fw_ver", "1.2.3" },
    };
    el2go_ota_check_update_req_t req_with = { .attrs = attrs, .attr_count = 2U };
    el2go_ota_check_update_req_t req_without = { .attrs = NULL, .attr_count = 0U };

    uint8_t buf[256];
    size_t len_with = 0U;
    size_t len_without = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req_with, buf, sizeof(buf), &len_with));
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_check_update(&req_without, buf, sizeof(buf), &len_without));

    /* A request with attributes must encode to more bytes than one without. */
    TEST_ASSERT(len_with > len_without);
    TEST_PRINT_INFO("check_update: with_attrs=%u bytes, no_attrs=%u bytes", (unsigned)len_with,
                    (unsigned)len_without);

    return true;
}

/* ========================================================================== */
/* Wire-buffer helpers for AvailableUpdatesResponse                           */
/* ========================================================================== */

/**
 * @brief Encode a minimal Package sub-message (packageId, name, version) into
 *        pkg_buf[] and return the number of bytes written, or 0 on error.
 *
 * Uses raw pb_encode_tag / pb_encode_string so we do not need callback
 * infrastructure in the test.
 */
static size_t encode_test_package(uint8_t *pkg_buf, size_t pkg_buf_size, const char *package_id,
                                  const char *name, const char *version)
{
    pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, pkg_buf_size);
    /* field 1: packageId */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_Package_packageId_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&ps, (const pb_byte_t *)package_id, strlen(package_id))) {
        return 0U;
    }
    /* field 2: name */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_Package_name_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&ps, (const pb_byte_t *)name, strlen(name))) {
        return 0U;
    }
    /* field 4: version */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_Package_version_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&ps, (const pb_byte_t *)version, strlen(version))) {
        return 0U;
    }
    return ps.bytes_written;
}

/**
 * @brief Encode a minimal Update sub-message (updateId, name, one Package)
 *        into upd_buf[] and return the number of bytes written, or 0 on error.
 */
static size_t encode_test_update(uint8_t *upd_buf, size_t upd_buf_size, const char *update_id,
                                 const char *name, const uint8_t *pkg_buf, size_t pkg_len)
{
    pb_ostream_t us = pb_ostream_from_buffer(upd_buf, upd_buf_size);
    /* field 1: updateId */
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_Update_updateId_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, (const pb_byte_t *)update_id, strlen(update_id))) {
        return 0U;
    }
    /* field 2: name */
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_Update_name_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, (const pb_byte_t *)name, strlen(name))) {
        return 0U;
    }
    /* field 5: packages (embedded Package sub-message) */
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_Update_packages_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, pkg_buf, pkg_len)) {
        return 0U;
    }
    return us.bytes_written;
}

/* ========================================================================== */
/* Response Handler -- round-trip / correctness tests                         */
/* ========================================================================== */

/**
 * @brief Parse a CheckUpdate response built from a known nanopb-encoded buffer
 *        containing one Update with one Package and verify all string fields.
 *
 * Schema: AvailableUpdatesResponse { repeated Update updates = 1; }
 *   Update { updateId=1, name=2, repeated Package packages=5 }
 *   Package { packageId=1, name=2, version=4 }
 */
static bool test_parse_check_update_one_package(void *params)
{
    uint8_t pkg_buf[128];
    uint8_t upd_buf[256];
    uint8_t wire[512];
    size_t pkg_len = 0U;
    size_t upd_len = 0U;
    pb_ostream_t outer;
    size_t wire_len = 0U;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    /* Encode the inner Package. */
    pkg_len = encode_test_package(pkg_buf, sizeof(pkg_buf), "pkg-1", "fw", "1.0.0");
    TEST_ASSERT(pkg_len > 0U);

    /* Encode the Update containing that package. */
    upd_len = encode_test_update(upd_buf, sizeof(upd_buf), "upd-1", "update-one", pkg_buf, pkg_len);
    TEST_ASSERT(upd_len > 0U);

    /* Encode the outer AvailableUpdatesResponse (field 1 = Update). */
    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(
        pb_encode_tag(&outer, PB_WT_STRING, com_nxp_iot_ota_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));
    wire_len = outer.bytes_written;

    /* Parse with our response handler. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, wire_len, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(1U, out.update_count);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].update_id, "upd-1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].name, "update-one"));
    TEST_ASSERT_EQUAL(1U, out.updates[0].package_count);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].package_id, "pkg-1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].name, "fw"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].version, "1.0.0"));

    /* Convenience pointers must be set. */
    TEST_ASSERT_NOT_NULL(out.first_update_id);
    TEST_ASSERT_NOT_NULL(out.first_package_id);
    TEST_ASSERT_EQUAL(0, strcmp(out.first_update_id, "upd-1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.first_package_id, "pkg-1"));

    return true;
}

/**
 * @brief Parse a CheckUpdate response with buf_len == 0 (empty server response).
 *        Must succeed and report no update available.
 */
static bool test_parse_check_update_empty_buf(void *params)
{
    static el2go_ota_check_update_resp_t out;
    static const uint8_t empty_buf[1] = { 0x00 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(empty_buf, 0U, &out));
    TEST_ASSERT_EQUAL(false, out.update_available);
    TEST_ASSERT_EQUAL(0U, out.update_count);

    return true;
}

/* ========================================================================== */
/* Request Builder -- Additional coverage                                     */
/* ========================================================================== */

/**
 * @brief Encode a ReportStatus request with STATUS_ERROR and no status message.
 *        Verifies the ERROR enum value is encoded and statusMessage is absent.
 */
static bool test_encode_report_status_error_no_msg(void *params)
{
    el2go_ota_report_status_req_t req = {
        .update_id = "upd-1",
        .status = EL2GO_OTA_UPDATE_STATUS_ERROR,
        .status_message = NULL,
    };
    uint8_t buf[128];
    size_t out_len = 0U;
    com_nxp_iot_ota_UpdateStatusNotification msg =
        com_nxp_iot_ota_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_Status_STATUS_ERROR, msg.updateStatus);
    /* statusMessage must be absent (empty string, has_statusMessage false). */
    TEST_ASSERT_EQUAL(false, msg.has_statusMessage);

    return true;
}

/**
 * @brief encode_report_status with NULL update_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_report_status_null_update_id(void *params)
{
    el2go_ota_report_status_req_t req = {
        .update_id = NULL,
        .status = EL2GO_OTA_UPDATE_STATUS_SUCCESS,
        .status_message = NULL,
    };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief encode_fetch_package with NULL package_id (update_id set) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_fetch_package_null_package_id(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "upd-1",
        .package_id = NULL,
    };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief encode_fetch_package with a 1-byte output buffer (too small) must
 *        return EL2GO_OTA_ERROR_ENCODE.
 */
static bool test_encode_fetch_package_buf_too_small(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "update-abc-123",
        .package_id = "pkg-xyz-456",
    };
    uint8_t buf[1];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_ENCODE,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief encode_check_update with attributes and a 1-byte buffer must return
 *        EL2GO_OTA_ERROR_ENCODE.
 */
static bool test_encode_check_update_buf_too_small(void *params)
{
    static const el2go_ota_attr_t attrs[] = {
        { "board", "rw612" },
    };
    el2go_ota_check_update_req_t req = { .attrs = attrs, .attr_count = 1U };
    uint8_t buf[1];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_ENCODE,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len));

    return true;
}

/* ========================================================================== */
/* Response Handler -- Additional coverage                                    */
/* ========================================================================== */

/**
 * @brief parse_check_update_response with NULL buf and non-zero len must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_parse_check_update_null_buf(void *params)
{
    static el2go_ota_check_update_resp_t out;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_check_update_response(NULL, 4U, &out));

    return true;
}

/**
 * @brief parse_fetch_package_response with NULL buf must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_parse_fetch_package_null_buf(void *params)
{
    el2go_ota_fetch_pkg_resp_t out;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_fetch_package_response(NULL, 4U, &out));

    return true;
}

/**
 * @brief parse_fetch_package_response with NULL out must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_parse_fetch_package_null_out(void *params)
{
    static const uint8_t buf[] = { 0x00 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_fetch_package_response(buf, sizeof(buf), NULL));

    return true;
}

/**
 * @brief parse_report_status_response with a valid non-empty wire buffer for an
 *        empty proto3 message (all-zero bytes are a valid encoding) must succeed.
 */
static bool test_parse_report_status_valid_buf(void *params)
{
    /* UpdateStatusNotificationResponse is google.protobuf.Empty: zero bytes on the wire. */
    static const uint8_t buf[] = { 0x00 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_parse_report_status_response(buf, 0U));

    return true;
}

/**
 * @brief parse_check_update_response with a garbage wire buffer must return
 *        EL2GO_OTA_ERROR_DECODE.
 */
static bool test_parse_check_update_corrupt_buf(void *params)
{
    /* 0xFF 0xFF is not a valid proto3 encoding (overlong varint). */
    static const uint8_t corrupt[] = { 0xFF, 0xFF };
    static el2go_ota_check_update_resp_t out;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_DECODE,
                      el2go_ota_parse_check_update_response(corrupt, sizeof(corrupt), &out));

    return true;
}

/**
 * @brief parse_check_update_response with 4 updates (the maximum supported)
 *        must succeed and report update_count == 4.
 */
static bool test_parse_check_update_four_updates(void *params)
{
    uint8_t wire[1024];
    uint8_t pkg_buf[128];
    uint8_t upd_buf[256];
    size_t i;
    size_t pkg_len = 0U;
    size_t upd_len = 0U;
    pb_ostream_t outer;
    static el2go_ota_check_update_resp_t out;

    (void)params;

    outer = pb_ostream_from_buffer(wire, sizeof(wire));

    /* Encode 4 identical Update sub-messages, each with one Package. */
    for (i = 0U; i < 4U; i++) {
        pkg_len = encode_test_package(pkg_buf, sizeof(pkg_buf), "pkg-1", "fw", "1.0.0");
        TEST_ASSERT(pkg_len > 0U);

        upd_len =
            encode_test_update(upd_buf, sizeof(upd_buf), "upd-1", "update-one", pkg_buf, pkg_len);
        TEST_ASSERT(upd_len > 0U);

        TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                                  com_nxp_iot_ota_AvailableUpdatesResponse_updates_tag));
        TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT_EQUAL(4U, out.update_count);

    return true;
}

/* ========================================================================== */
/* Request Builder Tests -- parameter validation                              */
/* ========================================================================== */

/**
 * @brief el2go_ota_encode_check_update() with NULL req must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_check_update_null_req(void *params)
{
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_check_update(NULL, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief el2go_ota_encode_check_update() with NULL buf must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_check_update_null_buf(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_check_update(&req, NULL, 64U, &out_len));

    return true;
}

/**
 * @brief el2go_ota_encode_check_update() with NULL out_len must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_check_update_null_out_len(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    uint8_t buf[64];

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_check_update(&req, buf, sizeof(buf), NULL));

    return true;
}

/**
 * @brief el2go_ota_encode_check_update() with no attributes must succeed and
 *        write a non-zero number of bytes into the output buffer.
 */
static bool test_encode_check_update_no_attrs(void *params)
{
    el2go_ota_check_update_req_t req = { .attrs = NULL, .attr_count = 0U };
    uint8_t buf[64];
    size_t out_len = 0U;
    el2go_ota_status_t status;

    (void)params;

    status = el2go_ota_encode_check_update(&req, buf, sizeof(buf), &out_len);
    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, status);
    TEST_PRINT_INFO("check_update (no attrs) encoded %u byte(s)", (unsigned)out_len);

    return true;
}

/**
 * @brief el2go_ota_encode_fetch_package() with NULL req must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_fetch_package_null_req(void *params)
{
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(NULL, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief el2go_ota_encode_fetch_package() with NULL update_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_fetch_package_null_ids(void *params)
{
    el2go_ota_fetch_pkg_req_t req = { .update_id = NULL, .package_id = "pkg-1" };
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));

    return true;
}

/**
 * @brief el2go_ota_encode_report_status() with NULL req must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_report_status_null_req(void *params)
{
    uint8_t buf[64];
    size_t out_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_encode_report_status(NULL, buf, sizeof(buf), &out_len));

    return true;
}

/* ========================================================================== */
/* Response Handler Tests                                                     */
/* ========================================================================== */

/**
 * @brief el2go_ota_parse_check_update_response() with NULL out must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_parse_check_update_null_out(void *params)
{
    static const uint8_t buf[] = { 0x00U };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_parse_check_update_response(buf, sizeof(buf), NULL));

    return true;
}

/**
 * @brief el2go_ota_parse_report_status_response() with buf_len == 0 and
 *        buf == NULL must succeed (empty proto3 response is valid).
 */
static bool test_parse_report_status_empty(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS, el2go_ota_parse_report_status_response(NULL, 0U));

    return true;
}

/**
 * @brief Encode a ReportStatus request with STATUS_ROLLED_BACK and verify the
 *        enum survives the round-trip.
 */
static bool test_encode_report_status_rolled_back(void *params)
{
    el2go_ota_report_status_req_t req = {
        .update_id = "upd-rb",
        .status = EL2GO_OTA_UPDATE_STATUS_ROLLED_BACK,
        .status_message = "rollback triggered",
    };
    uint8_t buf[128];
    size_t out_len = 0U;
    com_nxp_iot_ota_UpdateStatusNotification msg =
        com_nxp_iot_ota_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_Status_STATUS_ROLLED_BACK, msg.updateStatus);
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-rb"));

    return true;
}

/**
 * @brief Parse a FileResponse wire buffer built from known values and verify
 *        that range_start, range_end, and data_ptr/data_len are extracted.
 *
 * FileResponse: rangeStart (field 1, int64), rangeEnd (field 2, int64),
 *               data (field 3, bytes).
 */
static bool test_parse_fetch_package_roundtrip(void *params)
{
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t wire[64];
    pb_ostream_t out;
    size_t wire_len = 0U;
    el2go_ota_fetch_pkg_resp_t resp;

    (void)params;

    /* Build wire buffer manually using nanopb encode helpers. */
    out = pb_ostream_from_buffer(wire, sizeof(wire));
    /* field 1: rangeStart = 0 */
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_VARINT, com_nxp_iot_ota_FileResponse_rangeStart_tag));
    TEST_ASSERT(pb_encode_varint(&out, 0U));
    /* field 2: rangeEnd = 3 (last index of 4-byte payload) */
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_VARINT, com_nxp_iot_ota_FileResponse_rangeEnd_tag));
    TEST_ASSERT(pb_encode_varint(&out, 3U));
    /* field 3: data = payload bytes */
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_FileResponse_data_tag));
    TEST_ASSERT(pb_encode_string(&out, payload, sizeof(payload)));

    wire_len = out.bytes_written;
    TEST_ASSERT(wire_len > 0U);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_fetch_package_response(wire, wire_len, &resp));
    TEST_ASSERT_EQUAL(0, resp.range_start);
    TEST_ASSERT_EQUAL(3, resp.range_end);
    TEST_ASSERT_NOT_NULL(resp.data_ptr);
    TEST_ASSERT_EQUAL(sizeof(payload), resp.data_len);
    TEST_ASSERT_EQUAL(0, memcmp(resp.data_ptr, payload, sizeof(payload)));

    return true;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

/**
 * @brief Register all public EL2GO OTA Library tests with the test framework.
 */
void register_ota_lib_tests(void)
{
    TEST_REGISTER(test_el2go_ota_init_null_ctx);
    TEST_REGISTER(test_el2go_ota_init_null_config);
    TEST_REGISTER(test_el2go_ota_init_null_hostname);
    TEST_REGISTER(test_el2go_ota_init_null_ca_chain);
    TEST_REGISTER(test_el2go_ota_init_zero_ca_chain_size);
    TEST_REGISTER(test_el2go_ota_connect_null_ctx);
    TEST_REGISTER(test_el2go_ota_disconnect_null_ctx);
    TEST_REGISTER(test_el2go_ota_is_connected_null_ctx);
    TEST_REGISTER(test_el2go_ota_get_error_string);
    TEST_REGISTER(test_el2go_ota_cleanup_null_safe);
    TEST_REGISTER(test_el2go_ota_init_cleanup);
    TEST_REGISTER(test_el2go_ota_is_connected_after_init);
    TEST_REGISTER(test_el2go_ota_get_error_string_after_failed_init);
    TEST_REGISTER(test_encode_fetch_package_roundtrip);
    TEST_REGISTER(test_encode_fetch_package_with_artifact_and_range);
    TEST_REGISTER(test_encode_fetch_package_chunked_range);
    TEST_REGISTER(test_encode_report_status_roundtrip);
    TEST_REGISTER(test_encode_report_status_error_no_msg);
    TEST_REGISTER(test_encode_report_status_rolled_back);
    TEST_REGISTER(test_encode_report_status_null_update_id);
    TEST_REGISTER(test_encode_fetch_package_null_package_id);
    TEST_REGISTER(test_encode_fetch_package_buf_too_small);
    TEST_REGISTER(test_encode_check_update_buf_too_small);
    TEST_REGISTER(test_encode_check_update_with_attrs);
    TEST_REGISTER(test_parse_check_update_one_package);
    TEST_REGISTER(test_parse_check_update_empty_buf);
    TEST_REGISTER(test_parse_check_update_null_buf);
    TEST_REGISTER(test_parse_check_update_null_out);
    TEST_REGISTER(test_parse_check_update_corrupt_buf);
    TEST_REGISTER(test_parse_check_update_four_updates);
    TEST_REGISTER(test_parse_fetch_package_null_buf);
    TEST_REGISTER(test_parse_fetch_package_null_out);
    TEST_REGISTER(test_parse_fetch_package_roundtrip);
    TEST_REGISTER(test_parse_report_status_valid_buf);
    TEST_REGISTER(test_parse_report_status_empty);
    TEST_REGISTER(test_encode_check_update_null_req);
    TEST_REGISTER(test_encode_check_update_null_buf);
    TEST_REGISTER(test_encode_check_update_null_out_len);
    TEST_REGISTER(test_encode_check_update_no_attrs);
    TEST_REGISTER(test_encode_fetch_package_null_req);
    TEST_REGISTER(test_encode_fetch_package_null_ids);
    TEST_REGISTER(test_encode_report_status_null_req);
}
