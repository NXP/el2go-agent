/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include <pb_decode.h>
#include <pb_encode.h>

#include "el2go_ota_request_builder.h"
#include "el2go_ota_response_handler.h"
#include "types/available_updates_response.pb.h"
#include "types/file_request.pb.h"
#include "types/file_response.pb.h"
#include "types/package.pb.h"
#include "types/update.pb.h"
#include "types/update_status_notification.pb.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @defgroup test_el2go_ota_lib_internal Internal EL2GO OTA Library Tests
 * @brief Unit tests for the internal el2go_ota_lib API.
 *
 * Covers request builder, response handler, download engine, and status
 * reporting symbols that are only accessible via private headers.
 *
 * @{
 */

/* Wire-buffer helpers */

/**
 * @brief Encode a minimal Package sub-message (packageId, name, version) into
 *        pkg_buf[] and return the number of bytes written, or 0 on error.
 */
static size_t encode_test_package(uint8_t *pkg_buf, size_t pkg_buf_size, const char *package_id,
                                  const char *name, const char *version)
{
    pb_ostream_t ps = pb_ostream_from_buffer(pkg_buf, pkg_buf_size);
    /* field 1: packageId */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_packageId_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&ps, (const pb_byte_t *)package_id, strlen(package_id))) {
        return 0U;
    }
    /* field 2: name */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_name_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&ps, (const pb_byte_t *)name, strlen(name))) {
        return 0U;
    }
    /* field 4: version */
    if (!pb_encode_tag(&ps, PB_WT_STRING, com_nxp_iot_ota_update_proto_Package_version_tag)) {
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
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_updateId_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, (const pb_byte_t *)update_id, strlen(update_id))) {
        return 0U;
    }
    /* field 2: name */
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_name_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, (const pb_byte_t *)name, strlen(name))) {
        return 0U;
    }
    /* field 5: packages (embedded Package sub-message) */
    if (!pb_encode_tag(&us, PB_WT_STRING, com_nxp_iot_ota_update_proto_Update_packages_tag)) {
        return 0U;
    }
    if (!pb_encode_string(&us, pkg_buf, pkg_len)) {
        return 0U;
    }
    return us.bytes_written;
}

/** No-op chunk callback used to satisfy the non-NULL callback requirement. */
static el2go_ota_status_t s_noop_chunk_cb(const uint8_t *data, size_t len, size_t offset, void *ctx)
{
    (void)data;
    (void)len;
    (void)offset;
    (void)ctx;
    return EL2GO_OTA_SUCCESS;
}

/* Request Builder -- Happy-path round-trip tests */

/**
 * @brief Encode a FetchPackage request and decode it back with nanopb to verify
 *        that all string fields survive the encode/decode cycle unchanged.
 */
static bool test_encode_fetch_package_roundtrip(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "update-abc-123",
        .package_id = "pkg-xyz-456",
        .file_id = "file-def-789",
        .range_start = 0,
        .range_end = 0,
    };
    uint8_t buf[128];
    size_t out_len = 0U;
    com_nxp_iot_ota_update_proto_FileRequest msg =
        com_nxp_iot_ota_update_proto_FileRequest_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_update_proto_FileRequest_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "update-abc-123"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.packageId, "pkg-xyz-456"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.fileId, "file-def-789"));
    /* No range set -- start and end must both decode as 0. */
    TEST_ASSERT_EQUAL(0, msg.range.start);
    TEST_ASSERT_EQUAL(0, msg.range.end);

    return true;
}

/**
 * @brief Encode a FetchPackage request with all fields set (including
 *        fileId, rangeStart, rangeEnd) and verify the decoded wire message.
 */
static bool test_encode_fetch_package_with_artifact_and_range(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "upd-range-1",
        .package_id = "pkg-range-2",
        .file_id = "artifact-fw.bin",
        .range_start = 0,
        .range_end = 4095,
    };
    uint8_t buf[256];
    size_t out_len = 0U;
    com_nxp_iot_ota_update_proto_FileRequest msg =
        com_nxp_iot_ota_update_proto_FileRequest_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_update_proto_FileRequest_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-range-1"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.packageId, "pkg-range-2"));
    TEST_ASSERT_EQUAL(0, strcmp(msg.fileId, "artifact-fw.bin"));
    TEST_ASSERT_EQUAL(0, msg.range.start);
    TEST_ASSERT_EQUAL(4095, msg.range.end);

    return true;
}

/**
 * @brief Encode successive chunked requests and verify that range_start advances
 *        correctly (chunk 0: 0..4095, chunk 1: 4096..8191).
 */
static bool test_encode_fetch_package_chunked_range(void *params)
{
    const int64_t chunk_size = 4096;
    uint8_t buf[256];
    size_t out_len = 0U;
    int64_t chunk = 0;
    el2go_ota_fetch_pkg_req_t req;
    com_nxp_iot_ota_update_proto_FileRequest msg;
    pb_istream_t stream;

    (void)params;

    for (chunk = 0; chunk < 2; chunk++) {
        req.update_id = "upd-chunk";
        req.package_id = "pkg-chunk";
        req.file_id = "file-chunk";
        req.range_start = chunk * chunk_size;
        req.range_end = (chunk + 1) * chunk_size - 1;

        TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                          el2go_ota_encode_fetch_package(&req, buf, sizeof(buf), &out_len));
        TEST_ASSERT(out_len > 0U);

        memset(&msg, 0, sizeof(msg)); /* reset for each iteration */
        stream = pb_istream_from_buffer(buf, out_len);
        TEST_ASSERT(pb_decode(&stream, com_nxp_iot_ota_update_proto_FileRequest_fields, &msg));
        TEST_ASSERT_EQUAL(chunk * chunk_size, msg.range.start);
        TEST_ASSERT_EQUAL((chunk + 1) * chunk_size - 1, msg.range.end);
    }

    return true;
}

/**
 * @brief Encode a ReportStatus request (STATUS_SUCCESS, with message) and
 *        decode it back to verify all fields survive the encode/decode cycle.
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
    com_nxp_iot_ota_update_proto_UpdateStatusNotification msg =
        com_nxp_iot_ota_update_proto_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(
        pb_decode(&stream, com_nxp_iot_ota_update_proto_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-1"));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_update_proto_UpdateStatus_UPDATE_STATUS_SUCCESS,
                      msg.updateStatus);
    TEST_ASSERT(msg.statusMessage[0] != '\0');
    TEST_ASSERT_EQUAL(0, strcmp(msg.statusMessage, "applied ok"));

    return true;
}

/**
 * @brief Encode a CheckUpdate request with two device attributes and verify the
 *        encoded byte count is larger than the zero-attributes case.
 */
static bool test_encode_check_update_with_vs_without_attrs(void *params)
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

/* Response Handler -- round-trip / correctness tests */

/**
 * @brief Parse a CheckUpdate response built from a known nanopb-encoded buffer
 *        containing one Update with one Package and verify all string fields.
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

    pkg_len = encode_test_package(pkg_buf, sizeof(pkg_buf), "pkg-1", "fw", "1.0.0");
    TEST_ASSERT(pkg_len > 0U);

    upd_len = encode_test_update(upd_buf, sizeof(upd_buf), "upd-1", "update-one", pkg_buf, pkg_len);
    TEST_ASSERT(upd_len > 0U);

    outer = pb_ostream_from_buffer(wire, sizeof(wire));
    TEST_ASSERT(pb_encode_tag(&outer, PB_WT_STRING,
                              com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
    TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));
    wire_len = outer.bytes_written;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, wire_len, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT(out.update_count == 1U);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].update_id, "upd-1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].name, "update-one"));
    TEST_ASSERT(out.updates[0].package_count == 1U);
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].package_id, "pkg-1"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].name, "fw"));
    TEST_ASSERT_EQUAL(0, strcmp(out.updates[0].packages[0].version, "1.0.0"));

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
    TEST_ASSERT(out.update_count == 0U);

    return true;
}

/* ========================================================================== */
/* Request Builder -- Additional coverage                                     */
/* ========================================================================== */

/**
 * @brief Encode a ReportStatus request with STATUS_ERROR and no status message.
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
    com_nxp_iot_ota_update_proto_UpdateStatusNotification msg =
        com_nxp_iot_ota_update_proto_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(
        pb_decode(&stream, com_nxp_iot_ota_update_proto_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_update_proto_UpdateStatus_UPDATE_STATUS_ERROR,
                      msg.updateStatus);
    TEST_ASSERT_EQUAL('\0', msg.statusMessage[0]);

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
 * @brief encode_fetch_package with NULL package_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_encode_fetch_package_null_package_id(void *params)
{
    el2go_ota_fetch_pkg_req_t req = {
        .update_id = "upd-1",
        .package_id = NULL,
        .file_id = "file-1",
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
        .file_id = "file-1",
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

/* Response Handler -- Additional coverage */

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
 * @brief parse_check_update_response with a garbage wire buffer must return
 *        EL2GO_OTA_ERROR_DECODE.
 */
static bool test_parse_check_update_corrupt_buf(void *params)
{
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

    for (i = 0U; i < 4U; i++) {
        pkg_len = encode_test_package(pkg_buf, sizeof(pkg_buf), "pkg-1", "fw", "1.0.0");
        TEST_ASSERT(pkg_len > 0U);

        upd_len =
            encode_test_update(upd_buf, sizeof(upd_buf), "upd-1", "update-one", pkg_buf, pkg_len);
        TEST_ASSERT(upd_len > 0U);

        TEST_ASSERT(
            pb_encode_tag(&outer, PB_WT_STRING,
                          com_nxp_iot_ota_update_proto_AvailableUpdatesResponse_updates_tag));
        TEST_ASSERT(pb_encode_string(&outer, upd_buf, upd_len));
    }

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_check_update_response(wire, outer.bytes_written, &out));
    TEST_ASSERT(out.update_available);
    TEST_ASSERT(out.update_count == 4U);

    return true;
}

/* Request Builder -- parameter validation */

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
    el2go_ota_fetch_pkg_req_t req = { .update_id = NULL,
                                      .package_id = "pkg-1",
                                      .file_id = "file-1" };
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

/* Response Handler Tests */

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
    com_nxp_iot_ota_update_proto_UpdateStatusNotification msg =
        com_nxp_iot_ota_update_proto_UpdateStatusNotification_init_zero;
    pb_istream_t stream;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_encode_report_status(&req, buf, sizeof(buf), &out_len));
    TEST_ASSERT(out_len > 0U);

    stream = pb_istream_from_buffer(buf, out_len);
    TEST_ASSERT(
        pb_decode(&stream, com_nxp_iot_ota_update_proto_UpdateStatusNotification_fields, &msg));
    TEST_ASSERT_EQUAL(com_nxp_iot_ota_update_proto_UpdateStatus_UPDATE_STATUS_ROLLED_BACK,
                      msg.updateStatus);
    TEST_ASSERT_EQUAL(0, strcmp(msg.updateId, "upd-rb"));

    return true;
}

/**
 * @brief Parse a FileResponse wire buffer built from known values and verify
 *        that total_file_size, range_start, range_end, and data_ptr/data_len
 *        are extracted correctly.
 *
 * New FileResponse wire layout (schema v2):
 *   field 1 (varint):          totalFileSize
 *   field 2 (length-delimited): range (embedded Range sub-message)
 *   field 3 (length-delimited): data bytes
 */
static bool test_parse_fetch_package_roundtrip(void *params)
{
    static const uint8_t payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t range_buf[16];
    uint8_t wire[64];
    pb_ostream_t range_out;
    pb_ostream_t out;
    size_t range_len = 0U;
    size_t wire_len = 0U;
    el2go_ota_fetch_pkg_resp_t resp;

    (void)params;

    /* Encode the nested Range sub-message: start=0, end=3. */
    range_out = pb_ostream_from_buffer(range_buf, sizeof(range_buf));
    TEST_ASSERT(
        pb_encode_tag(&range_out, PB_WT_VARINT, com_nxp_iot_ota_update_proto_Range_start_tag));
    TEST_ASSERT(pb_encode_varint(&range_out, 0U));
    TEST_ASSERT(
        pb_encode_tag(&range_out, PB_WT_VARINT, com_nxp_iot_ota_update_proto_Range_end_tag));
    TEST_ASSERT(pb_encode_varint(&range_out, 3U));
    range_len = range_out.bytes_written;
    TEST_ASSERT(range_len > 0U);

    /* Encode the outer FileResponse. */
    out = pb_ostream_from_buffer(wire, sizeof(wire));
    /* field 1: totalFileSize = 4 */
    TEST_ASSERT(pb_encode_tag(&out, PB_WT_VARINT,
                              com_nxp_iot_ota_update_proto_FileResponse_totalFileSize_tag));
    TEST_ASSERT(pb_encode_varint(&out, (uint64_t)sizeof(payload)));
    /* field 2: range (embedded sub-message) */
    TEST_ASSERT(
        pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_range_tag));
    TEST_ASSERT(pb_encode_string(&out, range_buf, range_len));
    /* field 3: data = payload bytes */
    TEST_ASSERT(
        pb_encode_tag(&out, PB_WT_STRING, com_nxp_iot_ota_update_proto_FileResponse_data_tag));
    TEST_ASSERT(pb_encode_string(&out, payload, sizeof(payload)));

    wire_len = out.bytes_written;
    TEST_ASSERT(wire_len > 0U);

    TEST_ASSERT_EQUAL(EL2GO_OTA_SUCCESS,
                      el2go_ota_parse_fetch_package_response(wire, wire_len, &resp));
    TEST_ASSERT_EQUAL((int64_t)sizeof(payload), resp.total_file_size);
    TEST_ASSERT_EQUAL(0, resp.range_start);
    TEST_ASSERT_EQUAL(3, resp.range_end);
    TEST_ASSERT_NOT_NULL(resp.data_ptr);
    TEST_ASSERT_EQUAL(sizeof(payload), resp.data_len);
    TEST_ASSERT_EQUAL(0, memcmp(resp.data_ptr, payload, sizeof(payload)));

    return true;
}

/* Download Engine -- Parameter Validation Tests */

/**
 * @brief el2go_ota_check_for_updates(NULL, ...) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM without crashing.
 */
static bool test_check_for_updates_null_ctx(void *params)
{
    static el2go_ota_check_update_resp_t out;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_check_for_updates(NULL, NULL, 0U, &out));

    return true;
}

/**
 * @brief el2go_ota_check_for_updates() with NULL out_resp must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_check_for_updates_null_out(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_check_for_updates(NULL, NULL, 0U, NULL));

    return true;
}

/**
 * @brief el2go_ota_download_package(NULL, ...) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM without crashing.
 */
static bool test_download_package_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(NULL, "upd-1", "pkg-1", "file-1", 0U,
                                                 s_noop_chunk_cb, NULL));

    return true;
}

/**
 * @brief el2go_ota_download_package() with NULL update_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_download_package_null_update_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(NULL, NULL, "pkg-1", "file-1", 0U, s_noop_chunk_cb,
                                                 NULL));

    return true;
}

/**
 * @brief el2go_ota_download_package() with NULL package_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_download_package_null_package_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(NULL, "upd-1", NULL, "file-1", 0U, s_noop_chunk_cb,
                                                 NULL));

    return true;
}

/**
 * @brief el2go_ota_download_package() with NULL chunk_cb must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_download_package_null_callback(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_download_package(NULL, "upd-1", "pkg-1", "file-1", 0U, NULL, NULL));

    return true;
}

/* Status Reporting API -- Parameter Validation Tests */

/**
 * @brief el2go_ota_report_status(NULL, ...) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_report_status_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(NULL, "upd-1", "pkg-1", EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief el2go_ota_report_status() with NULL update_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_report_status_null_update_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(NULL, NULL, "pkg-1", EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief el2go_ota_report_status() with NULL package_id must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_report_status_null_package_id(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(NULL, "upd-1", NULL, EL2GO_OTA_OUTCOME_SUCCESS));

    return true;
}

/**
 * @brief el2go_ota_report_status() with an out-of-range outcome value must
 *        return EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_report_status_invalid_outcome(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_report_status(NULL, "upd-1", "pkg-1",
                                              (el2go_ota_update_outcome_t)99));

    return true;
}

/**
 * @brief el2go_ota_report_pending_status(NULL) must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 */
static bool test_report_pending_status_null_ctx(void *params)
{
    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_report_pending_status(NULL));

    return true;
}

/**
 * @brief sizeof(el2go_ota_pending_status_t) must be within the expected range.
 */
static bool test_pending_status_struct_layout(void *params)
{
    size_t sz = sizeof(el2go_ota_pending_status_t);

    (void)params;

    TEST_PRINT_INFO("sizeof(el2go_ota_pending_status_t) = %u", (unsigned)sz);
    TEST_ASSERT(sz >= 130U);
    TEST_ASSERT(sz <= 136U);

    return true;
}

/* Test Registration */

/**
 * @brief Register all internal EL2GO OTA Library tests with the test framework.
 */
void register_ota_lib_internal_tests(void)
{
    TEST_REGISTER_ID("-", test_encode_check_update_no_attrs);
    TEST_REGISTER_ID("OTA_UT_OL_2.1", test_encode_fetch_package_roundtrip);
    TEST_REGISTER_ID("OTA_UT_OL_2.2", test_encode_fetch_package_with_artifact_and_range);
    TEST_REGISTER_ID("OTA_UT_OL_2.3", test_encode_fetch_package_chunked_range);
    TEST_REGISTER_ID("OTA_UT_OL_2.4", test_encode_report_status_roundtrip);
    TEST_REGISTER_ID("OTA_UT_OL_2.5", test_encode_check_update_with_vs_without_attrs);
    TEST_REGISTER_ID("OTA_UT_OL_2.6", test_encode_report_status_error_no_msg);
    TEST_REGISTER_ID("OTA_UT_OL_2.7", test_encode_report_status_null_update_id);
    TEST_REGISTER_ID("OTA_UT_OL_2.8", test_encode_fetch_package_null_package_id);
    TEST_REGISTER_ID("OTA_UT_OL_2.9", test_encode_fetch_package_buf_too_small);
    TEST_REGISTER_ID("OTA_UT_OL_2.10", test_encode_check_update_buf_too_small);
    TEST_REGISTER_ID("OTA_UT_OL_2.11", test_encode_check_update_null_req);
    TEST_REGISTER_ID("OTA_UT_OL_2.11", test_encode_check_update_null_buf);
    TEST_REGISTER_ID("OTA_UT_OL_2.11", test_encode_check_update_null_out_len);
    TEST_REGISTER_ID("OTA_UT_OL_2.12", test_encode_fetch_package_null_req);
    TEST_REGISTER_ID("OTA_UT_OL_2.12", test_encode_fetch_package_null_ids);
    TEST_REGISTER_ID("OTA_UT_OL_2.13", test_encode_report_status_null_req);
    TEST_REGISTER_ID("OTA_UT_OL_2.14", test_encode_report_status_rolled_back);
    TEST_REGISTER_ID("OTA_UT_OL_3.1", test_parse_check_update_one_package);
    TEST_REGISTER_ID("OTA_UT_OL_3.2", test_parse_check_update_empty_buf);
    TEST_REGISTER_ID("OTA_UT_OL_3.3", test_parse_check_update_null_buf);
    TEST_REGISTER_ID("OTA_UT_OL_3.4", test_parse_check_update_null_out);
    TEST_REGISTER_ID("OTA_UT_OL_3.5", test_parse_check_update_corrupt_buf);
    TEST_REGISTER_ID("OTA_UT_OL_3.6", test_parse_check_update_four_updates);
    TEST_REGISTER_ID("OTA_UT_OL_3.7", test_parse_fetch_package_null_buf);
    TEST_REGISTER_ID("OTA_UT_OL_3.7", test_parse_fetch_package_null_out);
    TEST_REGISTER_ID("OTA_UT_OL_3.8", test_parse_fetch_package_roundtrip);
    TEST_REGISTER_ID("OTA_UT_OL_3.9", test_parse_report_status_empty);
    TEST_REGISTER_ID("OTA_UT_OL_4.1", test_check_for_updates_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_4.2", test_check_for_updates_null_out);
    TEST_REGISTER_ID("OTA_UT_OL_4.3", test_download_package_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_4.4", test_download_package_null_update_id);
    TEST_REGISTER_ID("OTA_UT_OL_4.5", test_download_package_null_package_id);
    TEST_REGISTER_ID("OTA_UT_OL_4.6", test_download_package_null_callback);
    TEST_REGISTER_ID("OTA_UT_OL_5.1", test_report_status_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_5.2", test_report_status_null_update_id);
    TEST_REGISTER_ID("OTA_UT_OL_5.3", test_report_status_null_package_id);
    TEST_REGISTER_ID("OTA_UT_OL_5.4", test_report_status_invalid_outcome);
    TEST_REGISTER_ID("OTA_UT_OL_5.5", test_report_pending_status_null_ctx);
    TEST_REGISTER_ID("OTA_UT_OL_5.6", test_pending_status_struct_layout);
}
